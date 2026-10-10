"""Discrete-time simulated 5G SBA with signed control units (CU/KIE).

The NF/SCP/NRF names are architectural abstractions, NOT 3GPP implementations.
Independent SCP counters are only revealed during a CU check. Attack labels are
never available to the scheduler or the detector.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import random
import statistics
from typing import NamedTuple

N_ZONES = 3
NF_PER_ZONE = 8
N_NF = N_ZONES * NF_PER_ZONE
STEP_SECONDS = 5
DURATION = 1800
WARMUP = 300
CHALLENGES_PER_TICK = 4  # exactly 24 / (30s / 5s) for every CU policy
CU_BYTES = 260  # assumed request+response bytes, not a real-world measurement
NF_TYPES = ("AMF", "SMF", "UDM", "AUSF", "PCF", "NSSF", "NRF", "SCP")

@dataclass(frozen=True)
class Attack:
    nf: int
    start: int
    end: int
    kind: str
    fraction: float

class Sample(NamedTuple):
    latency: float
    errors: float
    reported: int
    transit: int
    processing: float

@dataclass(frozen=True)
class ControlUnit:
    nf: int
    cycle: int
    created: int
    nonce: str
    reported: int
    processing: float
    mac: str

def payload(fields: dict) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()

def sign_control_unit(key: bytes, fields: dict) -> str:
    return hmac.new(key, payload(fields), hashlib.sha256).hexdigest()

def make_control_unit(nf: int, cycle: int, now: int, reported: int,
                      processing: float, key: bytes, rng: random.Random) -> ControlUnit:
    fields = dict(nf=nf, cycle=cycle, created=now,
                  nonce=f"{rng.getrandbits(128):032x}", reported=reported,
                  processing=round(processing, 4))
    return ControlUnit(**fields, mac=sign_control_unit(key, fields))

def verify_control_unit(cu: ControlUnit, key: bytes, now: int, last_cycle: int) -> bool:
    fields = dict(nf=cu.nf, cycle=cu.cycle, created=cu.created,
                  nonce=cu.nonce, reported=cu.reported, processing=cu.processing)
    return cu.cycle > last_cycle and 0 <= now - cu.created <= STEP_SECONDS and hmac.compare_digest(
        cu.mac, sign_control_unit(key, fields))

def median(xs):
    return statistics.median(xs)

def mad(xs, center=None):
    if center is None:
        center = median(xs)
    return 1.4826 * median([abs(x-center) for x in xs]) + .32

class World:
    """Matched random scenarios: every policy sees identical signal traces."""
    def __init__(self, seed: int):
        self.seed = seed
        rng = random.Random(seed)
        self.keys = [hashlib.sha256(f"lab|{seed}|nf|{i}".encode()).digest()
                     for i in range(N_NF)]
        self.attacks: list[Attack] = []
        self.bursts = []
        attacked = rng.sample(range(N_NF), 9)
        for j, nf in enumerate(attacked):
            start = rng.randrange(480, 1190, STEP_SECONDS)
            end = start + rng.choice([150, 180, 210])
            kind, frac = [("counter-forgery", .32),
                          ("stealth-drift", .16), ("low-amplitude", .095)][j % 3]
            self.attacks.append(Attack(nf, start, end, kind, frac))
        for nf in rng.sample([i for i in range(N_NF) if i not in attacked], 9):
            start = rng.randrange(460, 1250, STEP_SECONDS)
            self.bursts.append((nf, start, start + 145))
        self.samples: list[list[Sample]] = []
        for t in range(0, DURATION, STEP_SECONDS):
            common = [rng.gauss(0, .23) for _ in range(N_ZONES)]
            items = []
            for nf in range(N_NF):
                zone = nf // NF_PER_ZONE
                attack = next((a for a in self.attacks if a.nf == nf and a.start <= t < a.end), None)
                burst = any(n == nf and start <= t < end for n, start, end in self.bursts)
                seasonal = .65 * math.sin(2 * math.pi * t / 900)
                latency = (4.8 + .12 * (nf % NF_PER_ZONE) + seasonal + common[zone]
                           + rng.gauss(0, .52) + (1.05 if attack else 0) + (1.65 if burst else 0))
                errors = max(0., .65 + .2 * seasonal + rng.gauss(0, .27)
                             + (.62 if attack else 0) + (.85 if burst else 0))
                expected = max(1, int(175 + 13*(nf % 5) + 23*seasonal + rng.gauss(0, 9)))
                reported = int(expected * (1.55 if burst else 1))
                if attack:
                    # Compromised NF owns MAC key but reports a falsified request count.
                    transit = max(1, int(reported * (1 + attack.fraction) + rng.gauss(0, 5)))
                else:
                    transit = max(1, int(reported + rng.gauss(0, 5)))
                processing = max(.1, 1.8 + rng.gauss(0, .35)
                                 + (1.0 if attack else 0) + (.4 if burst else 0))
                items.append(Sample(latency, errors, reported, transit, processing))
            self.samples.append(items)

    def active_attack(self, nf: int, t: int) -> bool:
        return any(a.nf == nf and a.start <= t < a.end for a in self.attacks)

class Detector:
    """Unsupervised robust statistics on clean warmup + temporal/spatial scores."""
    def __init__(self, world: World):
        warm = world.samples[:WARMUP // STEP_SECONDS]
        self.center = []; self.scale = []
        self.error_center = []; self.error_scale = []
        self.spatial_center = []; self.spatial_scale = []
        self.ema = [0.0] * N_NF
        for nf in range(N_NF):
            lats = [row[nf].latency for row in warm]
            ers = [row[nf].errors for row in warm]
            z = (nf // NF_PER_ZONE) * NF_PER_ZONE
            residual = [row[nf].latency - median([row[n].latency for n in range(z, z + NF_PER_ZONE)]) for row in warm]
            self.center.append(median(lats)); self.scale.append(mad(lats))
            self.error_center.append(median(ers)); self.error_scale.append(mad(ers))
            self.spatial_center.append(median(residual)); self.spatial_scale.append(mad(residual))

    def risks(self, row: list[Sample]):
        zone_medians = [median([row[i].latency for i in range(z*NF_PER_ZONE, (z+1)*NF_PER_ZONE)]) for z in range(N_ZONES)]
        local, spatial = [], []
        for i, s in enumerate(row):
            lat_z = max(0., (s.latency - self.center[i]) / self.scale[i])
            err_z = max(0., (s.errors - self.error_center[i]) / self.error_scale[i])
            score = min(8., .6 * lat_z + .4 * err_z)
            self.ema[i] = .7 * self.ema[i] + .3 * score
            local.append(self.ema[i])
            sp = ((s.latency - zone_medians[i // NF_PER_ZONE]) - self.spatial_center[i]) / self.spatial_scale[i]
            spatial.append(max(0., min(8., sp)))
        return local, [local[i] + .6 * spatial[i] for i in range(N_NF)]


def choose_policy(policy: str, scores: list[float], last: list[int], t: int,
                  tick: int) -> list[int]:
    if policy == "fixed":
        offset = (tick * CHALLENGES_PER_TICK) % N_NF
        return [(offset + j) % N_NF for j in range(CHALLENGES_PER_TICK)]
    return sorted(range(N_NF), key=lambda i: (-(2.8 * scores[i] +
               .095 * min(120, t - last[i])), i))[:CHALLENGES_PER_TICK]


def run_policy(world: World, policy: str):
    if policy not in ("fixed", "local_adaptive", "zone_adaptive", "passive"):
        raise ValueError(policy)
    det = Detector(world)
    rng = random.Random(world.seed + 987)
    last = [-30] * N_NF
    cycles = [0] * N_NF
    verified = [0] * N_NF
    found = {a.nf: None for a in world.attacks}
    probes = true_probes = tp = fp = fn = tn = 0
    for tick, row in enumerate(world.samples):
        t = tick * STEP_SECONDS
        if t < WARMUP:
            continue
        local, spatial = det.risks(row)
        selected = (range(N_NF) if policy == "passive" else
                    choose_policy(policy, spatial if policy == "zone_adaptive" else local,
                                  last, t, tick))
        for nf in selected:
            s = row[nf]
            if policy == "passive":
                alert = local[nf] > 2.35
            else:
                probes += 1
                cycles[nf] += 1
                cu = make_control_unit(nf, cycles[nf], t, s.reported,
                                       s.processing, world.keys[nf], rng)
                assert verify_control_unit(cu, world.keys[nf], t, verified[nf])
                verified[nf] = cycles[nf]
                discrepancy = abs(s.transit - cu.reported) / max(1, s.transit)
                # A valid NF MAC is NOT proof of an honest NF report.
                # Gateway/SCP transit counts are a separately protected observer.
                alert = discrepancy > .19 or (discrepancy > .075 and spatial[nf] > 1.00)
                last[nf] = t
            attacked = world.active_attack(nf, t)
            if attacked:
                if policy != "passive": true_probes += 1
                if alert:
                    tp += 1
                    if found[nf] is None: found[nf] = t
                else: fn += 1
            else:
                if alert: fp += 1
                else: tn += 1
    delays = [min(DURATION - a.start, found[a.nf] - a.start) if found[a.nf] is not None else DURATION - a.start
              for a in world.attacks]
    detected = sum(found[a.nf] is not None for a in world.attacks)
    precision = tp / max(1, tp + fp)
    sample_recall = tp / max(1, tp + fn)
    return dict(policy=policy, seed=world.seed, attacks=len(world.attacks),
                detected=detected, event_recall=detected / len(world.attacks),
                mean_censored_delay_s=statistics.mean(delays),
                median_censored_delay_s=median(delays), delays=delays,
                probes=probes, compromised_probes=true_probes,
                cu_bytes=probes * CU_BYTES,
                cu_bytes_per_s=probes * CU_BYTES / (DURATION-WARMUP),
                tp=tp, fp=fp, fn=fn, tn=tn,
                precision=precision, sample_recall=sample_recall,
                f1=2*precision*sample_recall/max(1e-12, precision+sample_recall),
                false_alarms_per_1000_checks=1000*fp/max(1, fp+tn))