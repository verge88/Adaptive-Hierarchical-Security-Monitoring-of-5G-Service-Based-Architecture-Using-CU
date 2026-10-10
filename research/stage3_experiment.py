"""Stage 3: blinded attack schedules on real HTTP/2 CU research sidecars.

Runs with real Open5GS NRF/AUSF/NSSF in CI, but CU is NOT embedded in Open5GS.
Only the opt-in lab NF sidecars and SCP-like proxy process these CU messages.
"""
from __future__ import annotations
import argparse
import asyncio
import json
from pathlib import Path
import random
import statistics
import time

from .h2_wire import h2_request
from .live_experiment import N, PER_ZONE, NFSidecar, SCPObserver, mac, nrf_discovery

TRAIN = 12
TICKS = 96
TICK_S = 5
BUDGET = 2
POLICIES = ("fixed", "random", "local_adaptive", "zone_adaptive")
ATTACK_KINDS = ("slow", "stealth", "mimic", "collusion")
POSITIVE_KINDS = ("slow", "stealth", "mimic")


def challenge(nf, cycle, tick, rng, key):
    fields = dict(nf=nf, cycle=cycle, created=tick * TICK_S,
                  nonce=f"{rng.getrandbits(128):032x}")
    return {**fields, "mac": mac(key, fields)}


def scenario(seed):
    """Pre-generated, label-blind target assignment; algorithms only see traffic."""
    rng = random.Random(38000 + seed)
    targets = rng.sample(range(N), 4)
    starts = [20, 40, 59, 78]
    return [dict(nf=targets[i], kind=kind, start=starts[i] + rng.randint(-2, 2),
                 end=min(TICKS, starts[i] + 14 + rng.randint(-1, 2)))
            for i, kind in enumerate(ATTACK_KINDS)]


class ScenarioNF(NFSidecar):
    def __init__(self, nf, seed):
        super().__init__(nf, seed)
        self.strategy = "none"

    async def handle(self, headers, body):
        status, payload = await super().handle(headers, body)
        if headers.get(":path") != "/cu" or status != 200:
            return status, payload
        if self.strategy == "mimic":
            # Adaptive attacker intermittently reports truth. Otherwise a
            # 4-request discrepancy narrowly exceeds the predefined threshold.
            payload["reported"] = self.count if payload["cycle"] % 3 == 0 else max(0, self.count - 4)
            unsigned = {k: payload[k] for k in ("nf", "cycle", "created", "nonce", "reported")}
            payload["mac"] = mac(self.key, unsigned)
        return status, payload


class ColludingObserver(SCPObserver):
    async def handle(self, headers, body):
        status, payload = await super().handle(headers, body)
        if headers.get(":path") == "/stats" and status == 200:
            # This is an explicitly out-of-trust-boundary NEGATIVE CONTROL:
            # a colluding proxy conceals the forged cumulative count.
            payload = {**payload, "counts": list(payload["counts"])}
            for nf, peer in enumerate(self.peers):
                if peer.strategy == "collusion":
                    payload["counts"][nf] = max(0, peer.count - max(4, peer.count // 5))
        return status, payload


def choose(policy, tick, local, spatial, last, rng):
    """All choices depend ONLY on prior checks and passive, non-label features."""
    if policy == "fixed":
        return [(BUDGET * (tick - TRAIN) + j) % N for j in range(BUDGET)]
    if policy == "random":
        return rng.sample(range(N), BUDGET)
    if policy not in POLICIES:
        raise ValueError(policy)
    age = [min(20, max(0, tick - last[i])) for i in range(N)]
    if policy == "local_adaptive":
        score = [local[i] + .23 * age[i] for i in range(N)]
    else:
        # Remove zone-wide correlated nuisance from temporal risk, then give
        # nonzero weight to absolute latency and age for non-starvation.
        score = [.45 * local[i] + 1.45 * spatial[i] + .23 * age[i]
                 for i in range(N)]
    return sorted(range(N), key=lambda i: (-score[i], i))[:BUDGET]


async def trial(seed, policy):
    attacks = scenario(seed)
    peers = [ScenarioNF(i, seed) for i in range(N)]
    proxy = ColludingObserver(peers)
    for p in peers:
        await p.server.start()
    await proxy.server.start()
    purl = f"http://127.0.0.1:{proxy.server.port}"
    urls = [f"http://127.0.0.1:{p.server.port}" for p in peers]
    # Independent sampling RNG, same under all policies.
    rng = random.Random(51000 + seed)
    policy_rng = random.Random(91000 + seed)
    last = [-100] * N
    cycles = [0] * N
    base = [0.] * N
    scale = [1.] * N
    warmup = [[] for _ in range(N)]
    local = [0.] * N
    spatial = [0.] * N
    detected = [None] * len(attacks)
    event_probes = [0] * len(attacks)
    alerts = 0
    clean_checks = 0
    probes = 0
    wire_bytes = 0
    cu_rtts_ms = []
    started = time.perf_counter()
    try:
        for tick in range(TICKS):
            for nf, peer in enumerate(peers):
                current = next((a["kind"] for a in attacks
                                if a["nf"] == nf and a["start"] <= tick < a["end"]), "none")
                peer.strategy = current
                peer.compromised = current != "none"
                peer.slow = current == "slow"
                # Correlated benign latency bursts are common-mode nuisances.
                peer.burst = (tick in range(18, 31) and nf < PER_ZONE) or (
                    tick in range(47, 61) and nf >= PER_ZONE)
                count = 1 + int((nf * 7 + tick + seed) % 4 == 0)
                for _ in range(count):
                    status, _, _, _ = await h2_request(purl, f"/forward/{nf}", "POST", {"work": 1})
                    if status != 200:
                        raise RuntimeError("Laboratory SCP could not deliver workload")
            status, stats, _, _ = await h2_request(purl, "/stats")
            if status != 200:
                raise RuntimeError("Observer unavailable")
            lat = stats["latency_ms"]
            if tick < TRAIN:
                for i in range(N):
                    warmup[i].append(lat[i])
                if tick == TRAIN - 1:
                    for i, values in enumerate(warmup):
                        base[i] = statistics.median(values)
                        scale[i] = max(.7, 1.4826 * statistics.median(
                            abs(x - base[i]) for x in values))
                continue

            normalized = [max(0., min(12., (lat[i] - base[i]) / scale[i])) for i in range(N)]
            for i in range(N):
                local[i] = .45 * normalized[i] + .55 * local[i]
            medians = [statistics.median(normalized[z * PER_ZONE:(z + 1) * PER_ZONE])
                       for z in range(N // PER_ZONE)]
            for i in range(N):
                resid = max(0., normalized[i] - medians[i // PER_ZONE])
                spatial[i] = .45 * resid + .55 * spatial[i]

            selected = choose(policy, tick, local, spatial, last, policy_rng)
            assert len(set(selected)) == BUDGET
            for nf in selected:
                cycles[nf] += 1
                signed = challenge(nf, cycles[nf], tick, rng, peers[nf].key)
                t0 = time.perf_counter()
                status, cu, octets, _ = await h2_request(urls[nf], "/cu", "POST", signed)
                cu_rtts_ms.append((time.perf_counter() - t0) * 1000)
                if status != 200:
                    raise AssertionError(f"CU rejected: status {status}")
                fields = {k: cu[k] for k in ("nf", "cycle", "created", "nonce", "reported")}
                if (any(cu[k] != signed[k] for k in ("nf", "cycle", "created", "nonce"))
                        or not __import__("hmac").compare_digest(mac(peers[nf].key, fields), cu["mac"])):
                    raise AssertionError("Invalid authenticated CU")
                last[nf] = tick
                probes += 1
                wire_bytes += octets
                anomalous = abs(cu["reported"] - stats["counts"][nf]) > 3
                current_events = [(j, a) for j, a in enumerate(attacks)
                                  if a["nf"] == nf and a["start"] <= tick < a["end"]]
                if not current_events:
                    clean_checks += 1
                    if anomalous:
                        alerts += 1
                for j, a in current_events:
                    event_probes[j] += 1
                    if anomalous and detected[j] is None:
                        detected[j] = (tick - a["start"]) * TICK_S

        positive = [(j, a) for j, a in enumerate(attacks) if a["kind"] in POSITIVE_KINDS]
        censored = [(detected[j] if detected[j] is not None
                     else (TICKS - a["start"]) * TICK_S) for j, a in positive]
        return dict(seed=seed, policy=policy, attacks=len(positive), probes=probes,
                    cu_h2_wire_bytes=wire_bytes, cu_rtt_mean_ms=statistics.mean(cu_rtts_ms),
                    runtime_wall_seconds=time.perf_counter() - started,
                    event_recall=sum(detected[j] is not None for j, _ in positive) / len(positive),
                    mean_censored_delay_s=statistics.mean(censored),
                    false_alarms=alerts, clean_checks=clean_checks,
                    events=[{**a, "detected": detected[j] is not None,
                             "delay_logical_s": detected[j],
                             "censored_delay_logical_s": detected[j] if detected[j] is not None
                             else (TICKS - a["start"]) * TICK_S,
                             "cu_checks_while_active": event_probes[j]}
                            for j, a in enumerate(attacks)])
    finally:
        await proxy.server.close()
        for p in peers:
            await p.server.close()


async def calibrate_nrf(url, samples=8):
    from .live_experiment import nrf_discovery
    a = []
    for _ in range(samples):
        start = time.perf_counter()
        info = await nrf_discovery(url, retries=1)
        a.append((time.perf_counter() - start) * 1000)
    return dict(nrf=info, samples=samples, median_wall_rtt_ms=statistics.median(a),
                min_ms=min(a), max_ms=max(a))


async def run(args):
    core = await calibrate_nrf(args.nrf_url)
    rows = []
    for seed in range(args.start_seed, args.start_seed + args.count):
        for policy in POLICIES:
            result = await trial(seed, policy)
            rows.append(result)
            print(f"stage3 seed={seed} policy={policy} recall={result['event_recall']:.3f} "
                  f"delay={result['mean_censored_delay_s']:.1f} logical_s "
                  f"probes={result['probes']}", flush=True)
        checks = [r for r in rows if r["seed"] == seed]
        if len({x["probes"] for x in checks}) != 1:
            raise AssertionError("Unequal CU probe budget")
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "runs.json").write_text(json.dumps(rows, indent=2))
    (out / "nrf.json").write_text(json.dumps(core, indent=2))
    (out / "manifest.json").write_text(json.dumps(dict(
        stage="third", start_seed=args.start_seed, count=args.count,
        scenarios=list(ATTACK_KINDS), policy=list(POLICIES),
        logical_tick_seconds=TICK_S, total_ticks=TICKS, training_ticks=TRAIN,
        probes_per_tick=BUDGET, cu_is_native_open5gs=False), indent=2))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--start-seed", type=int, default=801)
    p.add_argument("--count", type=int, default=6)
    p.add_argument("--output", default="stage3_results")
    p.add_argument("--nrf-url", default="http://127.0.0.1:7777")
    a = p.parse_args()
    if a.count < 1 or a.count > 30:
        p.error("count must be 1..30")
    asyncio.run(run(a))


if __name__ == "__main__":
    main()
