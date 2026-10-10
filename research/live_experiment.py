"""Live HTTP/2 CU overlay + real Open5GS NRF discovery experimental stage.

Exactly scoped: Open5GS implements real NRF and NF registration; six lab-owned
HTTP/2 NF sidecars implement opt-in CU, and an independent lab-owned HTTP/2 SCP
proxy observes all simulated work. CU is NOT patched into native Open5GS NFs.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import hmac
import json
import math
from pathlib import Path
import random
import statistics
import time

from .h2_wire import H2Server, encode, h2_request
from .experiment import paired_ci

N = 6
ZONES = 2
PER_ZONE = 3
TICK_SECONDS = 5  # Experimental logical time, not wall-clock pacing
TOTAL_TICKS = 96
TRAIN_TICKS = 16
PROBES_PER_TICK = 2
SEEDS = tuple(range(701, 707))


def mac(key, msg):
    return hmac.new(key, encode(msg), hashlib.sha256).hexdigest()


def events(seed):
    jitter = seed % 3
    return [
        dict(nf=0, start=23 + jitter, end=41 + jitter, kind="slow_forgery"),
        dict(nf=4, start=50 + jitter, end=69 + jitter, kind="stealth_forgery"),
        dict(nf=2, start=74, end=92, kind="slow_forgery"),
    ]


class NFSidecar:
    def __init__(self, nf, seed):
        self.nf = nf
        self.key = hashlib.sha256(f"LAB-ONLY-{seed}-{nf}".encode()).digest()
        self.count = 0
        self.compromised = False
        self.slow = False
        self.burst = False
        self.last_cycle = -1
        self.server = H2Server(self.handle)

    async def handle(self, headers, body):
        path = headers.get(":path", "")
        if path == "/service" and headers.get(":method") == "POST":
            # Service-like requests, NOT a native Open5GS NF API.
            await asyncio.sleep((0.019 if self.slow or self.burst else 0.0015))
            self.count += 1
            return 200, {"accepted": True, "nf": self.nf}
        if path == "/cu" and headers.get(":method") == "POST":
            data = json.loads(body)
            unsigned = {k: data[k] for k in ("nf", "cycle", "nonce", "created")}
            if data["nf"] != self.nf or not hmac.compare_digest(
                    data["mac"], mac(self.key, unsigned)):
                return 401, {"error": "challenge authentication failed"}
            if data["cycle"] <= self.last_cycle:
                return 409, {"error": "replay"}
            self.last_cycle = data["cycle"]
            # Attacker has valid CU signing key but lies about traffic count.
            reported = max(0, self.count - (max(4, self.count // 5) if self.compromised else 0))
            payload = {**unsigned, "reported": reported}
            return 200, {**payload, "mac": mac(self.key, payload)}
        return 404, {"error": "unknown path"}


class SCPObserver:
    """Independent trusted HTTP/2 proxy, counts actually forwarded requests."""
    def __init__(self, peers):
        self.peers = peers
        self.counts = [0] * N
        self.lat_ms = [0.0] * N
        self.server = H2Server(self.handle)

    async def handle(self, headers, body):
        path = headers.get(":path", "")
        if path == "/stats" and headers.get(":method") == "GET":
            return 200, {"counts": self.counts, "latency_ms": self.lat_ms}
        if path.startswith("/forward/") and headers.get(":method") == "POST":
            try:
                nf = int(path.rsplit("/", 1)[1])
            except ValueError:
                return 400, {"error": "bad NF"}
            if not 0 <= nf < N:
                return 404, {"error": "not found"}
            started = time.perf_counter()
            code, data, _, _ = await h2_request(
                f"http://127.0.0.1:{self.peers[nf].server.port}", "/service", "POST", {"op": "lab-work"})
            elapsed = (time.perf_counter() - started) * 1000
            if code == 200:
                self.counts[nf] += 1
                self.lat_ms[nf] = .45 * elapsed + .55 * self.lat_ms[nf] if self.lat_ms[nf] else elapsed
            return code, data
        return 404, {"error": "unknown path"}


async def nrf_discovery(url, retries=30, interval=2):
    """Require actual Open5GS NRF to expose NF discovery over HTTP/2."""
    path = "/nnrf-disc/v1/nf-instances?target-nf-type=AUSF&requester-nf-type=AMF"
    last = "no answer"
    for attempt in range(retries):
        try:
            status, data, wire, headers = await h2_request(url, path, timeout=5)
            profiles = data.get("nfInstances", []) if isinstance(data, dict) else []
            if status == 200 and any(p.get("nfType") == "AUSF" for p in profiles):
                return dict(uri=url, http="h2c", status=status, nf_count=len(profiles),
                            nf_types=sorted(set(p.get("nfType", "UNKNOWN") for p in profiles)),
                            discovery_response_wire_bytes=wire, server=headers.get("server", ""))
            last = f"status={status} profiles={len(profiles)} body={str(data)[:160]}"
        except (OSError, ConnectionError, asyncio.TimeoutError, ValueError) as exc:
            last = f"{type(exc).__name__}: {str(exc)[:160]}"
        if attempt + 1 < retries:
            await asyncio.sleep(interval)
    raise RuntimeError("Real Open5GS NRF discovery unavailable: " + last)


async def policy_trial(seed, policy):
    if policy not in ("fixed", "local_adaptive", "zone_adaptive"):
        raise ValueError(policy)
    peers = [NFSidecar(i, seed) for i in range(N)]
    proxy = SCPObserver(peers)
    for peer in peers:
        await peer.server.start()
    await proxy.server.start()
    purl = f"http://127.0.0.1:{proxy.server.port}"
    nfurls = [f"http://127.0.0.1:{p.server.port}" for p in peers]
    attack_scenarios = events(seed)
    rng = random.Random(seed)
    delays = {i: None for i in range(len(attack_scenarios))}
    previous = [-1_000] * N
    cycles = [0] * N
    wire = 0
    tested = 0
    false_alarms = 0
    training = [[] for _ in range(N)]
    baseline = [0.0] * N
    scales = [1.0] * N
    risk_ema = [0.0] * N
    risk_trajectories = []
    benign_bursts = [(1, 33, 43), (5, 64, 72)]
    try:
        for tick in range(TOTAL_TICKS):
            for nf, peer in enumerate(peers):
                peer.compromised = any(x["nf"] == nf and x["start"] <= tick < x["end"] for x in attack_scenarios)
                peer.slow = peer.compromised and any(x["nf"] == nf and x["kind"] == "slow_forgery"
                                                    and x["start"] <= tick < x["end"] for x in attack_scenarios)
                peer.burst = any(a == nf and start <= tick < end for a, start, end in benign_bursts)
                # Identical workload, reset and replayed per policy on fresh sidecars.
                nreq = 1 + ((nf * 5 + tick + seed) % 3)
                for _ in range(nreq):
                    status, _, _, _ = await h2_request(purl, f"/forward/{nf}", "POST", {"tick": tick})
                    if status != 200:
                        raise RuntimeError("SCP traffic not delivered")
            status, stat, _, _ = await h2_request(purl, "/stats")
            assert status == 200
            latencies = stat["latency_ms"]
            if tick < TRAIN_TICKS:
                for nf, lat in enumerate(latencies):
                    training[nf].append(lat)
                if tick == TRAIN_TICKS - 1:
                    baseline = [statistics.median(xs) for xs in training]
                    scales = [max(.7, 1.4826 * statistics.median(abs(v - baseline[n]) for v in xs))
                              for n, xs in enumerate(training)]
                continue
            zone_medians = [statistics.median(latencies[z*PER_ZONE:(z+1)*PER_ZONE])
                            for z in range(ZONES)]
            local_scores, zone_scores = [], []
            for nf, lat in enumerate(latencies):
                local = max(0.0, min(12.0, (lat - baseline[nf]) / scales[nf]))
                relative = max(0.0, min(12.0, (lat - zone_medians[nf // PER_ZONE]) / scales[nf]))
                risk_ema[nf] = .4 * local + .6 * risk_ema[nf]
                local_scores.append(risk_ema[nf])
                zone_scores.append(risk_ema[nf] + .5 * relative)
            risk_trajectories.append(zone_scores)
            if policy == "fixed":
                selected = [(2 * (tick - TRAIN_TICKS) + j) % N for j in range(PROBES_PER_TICK)]
            else:
                scores = local_scores if policy == "local_adaptive" else zone_scores
                # No starvation, and identical number of probes in every policy.
                selected = sorted(range(N), key=lambda nf: (
                    -(scores[nf] + .2 * min(10, tick - previous[nf])), nf))[:PROBES_PER_TICK]
            for nf in selected:
                cycles[nf] += 1
                challenge = dict(nf=nf, cycle=cycles[nf], created=tick*TICK_SECONDS,
                                 nonce=f"{rng.getrandbits(128):032x}")
                signed = {**challenge, "mac": mac(peers[nf].key, challenge)}
                code, cu, octets, _ = await h2_request(nfurls[nf], "/cu", "POST", signed)
                tested += 1
                wire += octets
                if code != 200:
                    raise RuntimeError(f"CU challenge failed HTTP {code}")
                payload = {k: cu[k] for k in ("nf", "cycle", "created", "nonce", "reported")}
                if any(cu[k] != challenge[k] for k in challenge) or not hmac.compare_digest(
                        mac(peers[nf].key, payload), cu["mac"]):
                    raise RuntimeError("Signed CU integrity/replay check failed")
                previous[nf] = tick
                inconsistent = abs(cu["reported"] - stat["counts"][nf]) > 3
                active = [(i, x) for i, x in enumerate(attack_scenarios)
                          if x["nf"] == nf and x["start"] <= tick < x["end"]]
                if inconsistent and not active:
                    false_alarms += 1
                if inconsistent:
                    for idx, scenario in active:
                        if delays[idx] is None:
                            delays[idx] = (tick - scenario["start"]) * TICK_SECONDS
        n_attacks = len(attack_scenarios)
        censored = [(d if d is not None else (TOTAL_TICKS - x["start"]) * TICK_SECONDS)
                    for d, x in zip(delays.values(), attack_scenarios)]
        return dict(seed=seed, policy=policy, attacks=n_attacks,
                    event_recall=sum(v is not None for v in delays.values())/n_attacks,
                    mean_censored_delay_s=statistics.mean(censored),
                    observed_delays_s=list(delays.values()), cu_probes=tested,
                    cu_h2_wire_bytes=wire, false_alarms=false_alarms,
                    checks_per_tick=PROBES_PER_TICK, ticks=TOTAL_TICKS-TRAIN_TICKS)
    finally:
        await proxy.server.close()
        for peer in peers:
            await peer.server.close()


async def run_lab(seeds, nrf_url):
    core = await nrf_discovery(nrf_url, retries=1)
    results = []
    for seed in seeds:
        for policy in ("fixed", "local_adaptive", "zone_adaptive"):
            results.append(await policy_trial(seed, policy))
            print(f"seed {seed}: {policy} completed", flush=True)
    return core, results


def summarize(core, results):
    summary = {"open5gs_discovery": core, "experiment_kind": "LIVE-h2c-sidecars-NOT-native-CU-in-Open5GS"}
    for policy in ("fixed", "local_adaptive", "zone_adaptive"):
        rows = [r for r in results if r["policy"] == policy]
        summary[policy] = {k: statistics.mean(r[k] for r in rows) for k in
                            ("event_recall", "mean_censored_delay_s", "cu_probes", "cu_h2_wire_bytes", "false_alarms")}
    fixed = {r["seed"]: r for r in results if r["policy"] == "fixed"}
    zonal = {r["seed"]: r for r in results if r["policy"] == "zone_adaptive"}
    common = sorted(fixed.keys() & zonal.keys())
    diff = [fixed[s]["mean_censored_delay_s"] - zonal[s]["mean_censored_delay_s"] for s in common]
    summary["paired_effect"] = {"seeds": len(common), "fixed_minus_zone_delay_s": statistics.mean(diff),
                               "bootstrap_ci95_s": paired_ci(diff, n_boot=2000)}
    return summary


def report(summary, results):
    core = summary["open5gs_discovery"]
    lines = ["# Live HTTP/2 overlay with real Open5GS NRF discovery", "",
             f"NRF `GET nnrf-disc`: HTTP/2 h2c response {core['status']}, NF types {', '.join(core['nf_types'])}; Open5GS containers run in Docker.",
             "", "**Scope:** NRF and AUSF/NSSF registration are live Open5GS. CU is handled by explicit lab HTTP/2 sidecars, not by unmodified 3GPP NFs. SCP-like observer is a separate instrumented HTTP/2 laboratory proxy.",
             "Attacks are controlled report forgeries performed by sidecars with access to their valid MAC key; benign load bursts are included. Time is a **logical 5 s tick**, not 5 s real-time wall clock.",
             "", "| Policy | Event recall | Censored delay (logical s) | Probes/seed | HTTP/2 CU bytes/seed | False alarms/seed |",
             "|---|---:|---:|---:|---:|---:|"]
    for policy in ("fixed", "local_adaptive", "zone_adaptive"):
        s = summary[policy]
        lines.append(f"| {policy} | {s['event_recall']:.3f} | {s['mean_censored_delay_s']:.1f} | {s['cu_probes']:.0f} | {s['cu_h2_wire_bytes']:.0f} | {s['false_alarms']:.2f} |")
    v = summary["paired_effect"]
    lines += ["", f"Fixed minus zonal adaptive censored delay: {v['fixed_minus_zone_delay_s']:.2f} logical seconds, 95% paired bootstrap CI {v['bootstrap_ci95_s']}.",
              "The experiment demonstrates transport interoperability and limited controlled faults, **not** scientific priority, real Open5GS CU support, end-to-end mutual TLS/OAuth, operator performance, or secure production deployment.",
              "Independent observation assumes proxy not compromised. Every attack is detectable at inspection in this toy model; this favors all CU methods. No synthetic delays are mislabeled as measured 5G network latency.",
              "A nonpositive or zero-crossing confidence interval is not evidence of superiority."]
    return "\n".join(lines) + "\n"


async def async_main(args):
    seeds = SEEDS[:args.seeds]
    core, results = await run_lab(seeds, args.nrf_url)
    result = summarize(core, results)
    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    (root / "runs.json").write_text(json.dumps(results, indent=2))
    (root / "summary.json").write_text(json.dumps(result, indent=2))
    (root / "REPORT.md").write_text(report(result, results))
    print(report(result, results))
    if not all(x["cu_probes"] == results[0]["cu_probes"] for x in results):
        raise AssertionError("Unfair CU budget")
    if not all(x["false_alarms"] == 0 for x in results):
        raise AssertionError("Unexpected CU false alarms in deterministic lab")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--seeds", type=int, default=6)
    p.add_argument("--nrf-url", default="http://127.0.0.1:7777")
    p.add_argument("--output", default="live_results")
    args = p.parse_args()
    if args.seeds < 2 or args.seeds > len(SEEDS):
        p.error("seeds must be in 2..6")
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
