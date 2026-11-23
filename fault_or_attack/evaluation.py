"""Summaries and scoring: single-run report, the all-scenarios table and the multi-seed evaluation."""

from __future__ import annotations

import random
from dataclasses import dataclass, replace
from statistics import mean

from .config import Config
from .detector import Verdict, diagnose, findings
from .plant import Record, TankSimulator
from .scenarios import ATTACKS, MODES, PHYSICAL_SCENARIOS, SCENARIOS, SMART_ATTACKS, STRESS_ATTACKS


SEVERITY = {"ok": 0, "warn": 1, "danger": 2}


@dataclass
class Summary:
    min_level: float
    max_level: float
    final_level: float
    detected_after: int | None   # ticks between injection and the first non-OK status (None = never noticed)
    worst_status: str
    mean_duty: float             # mean commanded pump duty after the fault starts
    mean_run_duty: float         # mean share of time the pump really ran after the fault starts


def summarize(records: list[Record], cfg: Config) -> Summary:
    after = [r for r in records if r.tick >= cfg.inject_at]
    if not after:
        raise ValueError(f"The run ends at second {len(records)}, before the fault starts at {cfg.inject_at}.")
    detected = next((r.tick - cfg.inject_at for r in after if r.tone != "ok"), None)
    worst = max(after, key=lambda r: SEVERITY[r.tone])
    return Summary(
        min_level=min(r.level for r in after),
        max_level=max(r.level for r in after),
        final_level=records[-1].level,
        detected_after=detected,
        worst_status=worst.status if worst.tone != "ok" else "Within limits",
        mean_duty=sum(r.duty for r in after) / len(after),
        mean_run_duty=sum(r.run_duty for r in after) / len(after),
    )


def _verdict_ok(key: str | None, verdict: Verdict | None, cfg: Config) -> bool:
    """Did the detector call it right? Healthy runs must stay silent, and a verdict
    raised before the fault or attack started is a false alarm, even if its label matches."""
    if key is None:
        return verdict is None
    return verdict is not None and verdict.tick >= cfg.inject_at and verdict.label == SCENARIOS[key].kind


def _delay(verdict: Verdict | None, cfg: Config) -> str:
    if verdict is None:
        return "never"
    d = verdict.tick - cfg.inject_at
    return f"{d} s" if d >= 0 else f"{-d} s early"


def print_single(sim: TankSimulator, records: list[Record]) -> None:
    cfg = sim.cfg
    s = summarize(records, cfg)
    info = SCENARIOS.get(sim.fault) if sim.fault else None
    print()
    print(f"Scenario: {info.name if info else 'none (healthy)'}   |   duration: {sim.mode}   |   "
          f"backup sensor: {'on' if sim.backup_sensor else 'off'}")
    if info:
        print(f"Truth:            {info.kind} ({info.category})")
        print(f"What happens:     {info.what_happens}")
        print(f"How it is caught: {info.how_caught}")
    print()
    print(f"Level from second {cfg.inject_at}:     min {s.min_level:.0f}%   max {s.max_level:.0f}%   final {s.final_level:.0f}%")
    if cfg.control == "pid":
        # In PID mode the pump always runs; the duty windows hold how far the supply valve is open.
        print(f"Mean valve command:        {s.mean_duty * 100:.0f}% open  (healthy is about 50%)")
        if abs(s.mean_run_duty - s.mean_duty) >= 0.01:
            print(f"Valve really open:         {s.mean_run_duty * 100:.0f}%  (differs from what the controller commanded)")
    else:
        print(f"Mean pump duty:            {s.mean_duty * 100:.0f}%  (healthy is about 50%)")
        if abs(s.mean_run_duty - s.mean_duty) >= 0.01:
            print(f"Pump really running:       {s.mean_run_duty * 100:.0f}%  (differs from what the controller commanded)")
    det = "never raised an alarm" if s.detected_after is None else f"{s.detected_after} s after it started"
    print(f"First alarm:               {det}")
    print(f"Worst status:              {s.worst_status}")

    verdict, timeline = diagnose(records, cfg)
    print()
    print("FAULT OR ATTACK?")
    if verdict is None:
        print("  Detector verdict:        nothing abnormal seen")
    else:
        print(f"  Detector verdict:        {verdict.label} - {verdict.culprit}  ({_delay(verdict, cfg)} after it started)")
        print(f"  Why:                     {verdict.reason}")
        if verdict.mitre:
            print(f"  MITRE ATT&CK for ICS:    {verdict.mitre}")
        print(f"  Recommended action:      {verdict.action}")
    if info or verdict:
        print(f"  Correct call:            {'yes' if _verdict_ok(sim.fault, verdict, cfg) else 'NO'}")
    if len(timeline) > 1:
        print("  Evidence over time:")
        for v in timeline:
            print(f"    second {v.tick:>3}: {v.label:<7} {v.culprit}")
    print()


def print_table(cfg: Config, mode: str, seed: int) -> None:
    header = (f"{'Scenario':<22}{'Truth':<8}{'Backup':<8}{'Max':>5}{'Final':>7}  "
              f"{'Verdict':<8}{'Culprit':<27}{'After':<10}OK")
    print()
    print(f"Every fault and attack, duration = {mode}, starts at second {cfg.inject_at}")
    print(header)
    print("-" * len(header))
    right = total = 0
    for key, info in SCENARIOS.items():
        if key == next(iter(ATTACKS)):
            print("-" * len(header))
        for backup in (False, True):
            records = TankSimulator(cfg, key, mode, backup, seed).run()
            s = summarize(records, cfg)
            v, _ = diagnose(records, cfg)
            ok = _verdict_ok(key, v, cfg)
            right += ok
            total += 1
            print(f"{info.name:<22}{info.kind:<8}{'on' if backup else 'off':<8}{s.max_level:>4.0f}%"
                  f"{s.final_level:>6.0f}%  {v.label if v else '-':<8}{v.culprit if v else '-':<27}"
                  f"{_delay(v, cfg):<10}{'yes' if ok else 'NO'}")
    healthy, _ = diagnose(TankSimulator(cfg, None, mode, False, seed).run(), cfg)
    print("-" * len(header))
    print(f"Fault-vs-attack calls correct: {right}/{total}.   "
          f"Healthy run: {'no false alarm' if healthy is None else 'FALSE ALARM - ' + healthy.culprit}")
    print()


def print_eval(cfg: Config, seeds: int) -> dict:
    """Score the detector over many random seeds, every duration mode and backup on/off.

    Prints the tables and also returns the numbers (used by the accuracy dashboard)."""
    results: dict = {"seeds": seeds, "plant": cfg.control, "scenarios": []}
    print()
    plant = "realistic plant (PID valve, valve lag, rounded readings, correlated noise)" if cfg.control == "pid" else "simple plant (on/off pump)"
    print(f"Detector accuracy on the {plant}")
    print(f"over {seeds} seeds x {len(MODES)} duration modes x backup on/off")
    header = f"{'Scenario':<24}{'Truth':<8}{'Correct':>10}{'Mean time to verdict':>23}   Most common culprit"
    print(header)
    print("-" * len(header))
    grand = grand_total = 0
    # confusion[truth][called]: called is FAULT, ATTACK, UNKNOWN or "none"
    confusion = {kind: {c: 0 for c in ("FAULT", "ATTACK", "UNKNOWN", "none")} for kind in ("FAULT", "ATTACK")}
    for key, info in SCENARIOS.items():
        right = total = 0
        delays: list[int] = []
        culprits: dict[str, int] = {}
        for seed in range(1, seeds + 1):
            for mode in MODES:
                for backup in (False, True):
                    v, _ = diagnose(TankSimulator(cfg, key, mode, backup, seed).run(), cfg)
                    ok = _verdict_ok(key, v, cfg)
                    right += ok
                    total += 1
                    confusion[info.kind][v.label if v else "none"] += 1
                    if v:
                        culprits[v.culprit] = culprits.get(v.culprit, 0) + 1
                        if ok:
                            delays.append(v.tick - cfg.inject_at)
        grand += right
        grand_total += total
        top = max(culprits, key=culprits.get) if culprits else "-"
        avg = f"{mean(delays):.1f} s" if delays else "-"
        name = info.name + (" *" if key in SMART_ATTACKS else "")
        print(f"{name:<24}{info.kind:<8}{right:>5}/{total:<4}{avg:>23}   {top}")
        results["scenarios"].append({"key": key, "name": name, "kind": info.kind, "right": right, "total": total,
                                     "delay": mean(delays) if delays else None})
    print("-" * len(header))
    print(f"Overall: {grand}/{grand_total} correct ({grand / grand_total:.1%}).   "
          f"* = smart attacker added after the detector was first tuned")

    # Baselines (research advice: always compare with trivial detectors).
    n_fault = sum(confusion["FAULT"].values())
    n_attack = sum(confusion["ATTACK"].values())
    print(f"Baselines: always say FAULT {n_fault / grand_total:.0%},  always say ATTACK "
          f"{n_attack / grand_total:.0%},  coin flip 50%")
    print()
    print(f"{'':<14}{'called FAULT':>14}{'called ATTACK':>15}{'UNKNOWN':>10}{'nothing':>10}")
    for kind in ("FAULT", "ATTACK"):
        row = confusion[kind]
        print(f"{'truly ' + kind:<14}{row['FAULT']:>14}{row['ATTACK']:>15}{row['UNKNOWN']:>10}{row['none']:>10}")

    # False alarms: short healthy runs, plus long healthy runs for a per-hour rate.
    short = sum(diagnose(TankSimulator(cfg, None, "permanent", b, s).run(), cfg)[0] is not None
                for s in range(1, seeds + 1) for b in (False, True))
    hours = min(seeds, 5) * 2
    long_cfg = replace(cfg, ticks=3600, inject_at=3599)
    alarms = sum(sum(v.label != "UNKNOWN" for v in diagnose(TankSimulator(long_cfg, None, "permanent", b, s).run(),
                                                              long_cfg)[1])
                 for s in range(1, hours // 2 + 1) for b in (False, True))
    print()
    print(f"False alarms: {short}/{seeds * 2} short healthy runs,  {alarms} in {hours} hours of healthy plant time")
    print()
    results.update(right=grand, total=grand_total, confusion=confusion, short_false=short,
                   short_runs=seeds * 2, long_alarms=alarms, hours=hours,
                   always_fault=n_fault / grand_total, always_attack=n_attack / grand_total)
    return results


def print_stress(cfg: Config, seeds: int) -> dict:
    """Score the adaptive-attacker stress tests, with the hard-wired witness check off and on.

    Kept apart from print_eval so the headline accuracy stays comparable with earlier runs. Besides the
    verdict, it records whether the tank overflowed before a correct verdict arrived."""
    plant = "realistic plant (PID valve)" if cfg.control == "pid" else "simple plant (on/off pump)"
    print()
    print(f"Stress test on the {plant}: an adaptive attacker who knows how the detector works")
    print(f"over {seeds} seeds x {len(MODES)} duration modes, scored separately from the headline accuracy")
    header = (f"{'Scenario':<24}{'Witness check':<15}{'Backup B':<10}{'Correct':>9}{'FAULT':>7}{'UNKNOWN':>9}"
              f"{'nothing':>9}{'Caught before overflow':>24}{'Mean time':>11}")
    print(header)
    print("-" * len(header))
    out: dict = {"seeds": seeds, "plant": cfg.control, "rows": []}
    for key, info in STRESS_ATTACKS.items():
        for witness in (False, True):
            c = replace(cfg, witness_check=witness)
            for backup in (False, True):
                calls = {"ATTACK": 0, "FAULT": 0, "UNKNOWN": 0, "none": 0}
                before = total = 0
                delays: list[int] = []
                for seed in range(1, seeds + 1):
                    for mode in MODES:
                        records = TankSimulator(c, key, mode, backup, seed).run()
                        v, _ = diagnose(records, c)
                        total += 1
                        calls[v.label if v else "none"] += 1
                        ok = v is not None and v.label == info.kind and v.tick >= c.inject_at
                        if ok:
                            delays.append(v.tick - c.inject_at)
                            spill = next((r.tick for r in records if r.level >= 99.5), None)
                            before += spill is None or v.tick < spill
                avg = f"{mean(delays):.0f} s" if delays else "-"
                print(f"{info.name:<24}{'on' if witness else 'off':<15}{'on' if backup else 'off':<10}"
                      f"{calls['ATTACK']:>4}/{total:<4}{calls['FAULT']:>7}{calls['UNKNOWN']:>9}{calls['none']:>9}"
                      f"{before:>17}/{total:<6}{avg:>11}")
                out["rows"].append({"key": key, "witness": witness, "backup": backup, "total": total,
                                    "calls": calls, "before_overflow": before,
                                    "delay": mean(delays) if delays else None})
    print("-" * len(header))
    print("Correct = called ATTACK after the attack began. Caught before overflow = correct, and before the real tank")
    print("reached 99.5%. In transient and intermittent runs the attack may stop before the tank fills, so those count.")
    print()
    return out


def print_physical(cfg: Config, seeds: int) -> dict:
    """Score the physical-side scenarios: slow faults, on-site tampering and physical damage.

    Runs are 30 minutes long and the event starts after 400 healthy seconds, because the slow checks average over
    minutes. "Before the limit" = called right before the real tank overflowed or ran dry (or it never did)."""
    c = replace(cfg, ticks=1800, inject_at=400)
    plant = "realistic plant (PID valve)" if c.control == "pid" else "simple plant (on/off pump)"
    print()
    print(f"Physical side on the {plant}: {seeds} seeds x backup on/off, 30-minute runs")
    header = f"{'Scenario':<32}{'Truth':<10}{'Correct':>9}{'Before the limit':>18}{'Mean time':>11}   Most common call"
    print(header)
    print("-" * len(header))
    out: dict = {"seeds": seeds, "plant": c.control, "rows": []}
    right_all = total_all = 0
    for key, info in PHYSICAL_SCENARIOS.items():
        right = before = total = 0
        delays: list[int] = []
        calls: dict[str, int] = {}
        for seed in range(1, seeds + 1):
            for backup in (False, True):
                records = TankSimulator(c, key, "permanent", backup, seed).run()
                v, _ = diagnose(records, c)
                total += 1
                call = f"{v.label}: {v.culprit}" if v else "nothing"
                calls[call] = calls.get(call, 0) + 1
                ok = (v is None) if info.kind == "NONE" else (v is not None and v.label == info.kind and v.tick >= c.inject_at)
                right += ok
                if ok:
                    limit = next((r.tick for r in records if r.tick >= c.inject_at and (r.level >= 99.5 or r.level <= 0.5)), None)
                    before += v is None or limit is None or v.tick < limit
                    if v is not None:
                        delays.append(v.tick - c.inject_at)
        right_all += right
        total_all += total
        avg = f"{mean(delays):.0f} s" if delays else "-"
        top = max(calls, key=calls.get)
        print(f"{info.name:<32}{info.kind:<10}{right:>4}/{total:<4}{before:>11}/{total:<6}{avg:>11}   {top}")
        out["rows"].append({"key": key, "name": info.name, "kind": info.kind, "right": right, "total": total,
                            "before": before, "delay": mean(delays) if delays else None, "top": top})
    print("-" * len(header))
    print(f"Overall: {right_all}/{total_all} correct. PHYSICAL = send site security; NONE = planned work, must stay silent.")
    print()
    out.update(right=right_all, total=total_all)
    return out


# --- deeper physical-side tests ---------------------------------------------------------------------------------

# How big each slow event is, in % of the tank per second, from far below the old per-second limit up to large.
SWEEP = {
    "corrosion": ("Corrosion leak (constant)", "FAULT", "corrosion_start", (0.002, 0.005, 0.01, 0.02, 0.05, 0.1)),
    "theft": ("Fuel theft", "PHYSICAL", "theft_flow", (0.005, 0.01, 0.02, 0.05, 0.1, 0.2)),
    "water": ("Water getting into the tank", "FAULT", "water_rate", (0.005, 0.01, 0.02, 0.05, 0.1)),
}


def print_sweep(cfg: Config, seeds: int) -> dict:
    """Detection curve: each slow event at a range of sizes, starting at a different time in each run.

    One-hour runs; the event starts at 300, 600, 900 or 1200 s (picked per seed), so a size is only 'caught' if
    the detector finds it however long the plant has been running. Corrosion is held constant here (no growth), so
    the size is the true leak rate throughout."""
    plant = "realistic plant (PID valve)" if cfg.control == "pid" else "simple plant (on/off pump)"
    print()
    print(f"Detection curve on the {plant}: {seeds} seeds x backup on/off, one-hour runs, random start time")
    header = f"{'Scenario':<30}{'Size (%/s)':>11}{'Right':>9}{'Wrong call':>12}{'Missed':>8}{'Mean time':>11}"
    print(header)
    print("-" * len(header))
    out: dict = {"seeds": seeds, "plant": cfg.control, "rows": []}
    for key, (name, truth, knob, sizes) in SWEEP.items():
        for size in sizes:
            right = wrong = missed = 0
            delays: list[int] = []
            for seed in range(1, seeds + 1):
                at = random.Random(seed * 7 + 3).choice((300, 600, 900, 1200))
                c = replace(cfg, ticks=3600, inject_at=at, **{knob: size}, **({"corrosion_growth": 0.0} if key == "corrosion" else {}))
                for backup in (False, True):
                    v, _ = diagnose(TankSimulator(c, key, "permanent", backup, seed).run(), c)
                    if v is None or v.tick < at:
                        missed += v is None
                        wrong += v is not None
                    elif v.label == truth:
                        right += 1
                        delays.append(v.tick - at)
                    else:
                        wrong += 1
            total = 2 * seeds
            avg = f"{mean(delays):.0f} s" if delays else "-"
            print(f"{name:<30}{size:>11.3f}{right:>5}/{total:<3}{wrong:>12}{missed:>8}{avg:>11}")
            out["rows"].append({"key": key, "size": size, "right": right, "wrong": wrong, "missed": missed,
                                "total": total, "delay": mean(delays) if delays else None})
    print("-" * len(header))
    print("Normal flow is 2%/s; a size of 0.01 is half a percent of that. Wrong call = a verdict before the event")
    print("began, or the wrong kind (e.g. theft called a leak). Missed = nothing said in the whole hour.")
    print()
    return out


# (name, main scenario, second event, seconds between them, acceptable first answers, causes that should both appear)
MIXED = (
    ("Cyber attack, then fuel theft", "spoof", "theft", 60, {"ATTACK", "PHYSICAL"},
     (("ATTACK", ""), ("PHYSICAL", ""))),
    ("Network flood, then corrosion leak", "dos", "corrosion", 60, {"ATTACK", "FAULT"},
     (("ATTACK", ""), ("FAULT", "leak"))),
    ("Corrosion leak after sensor B died", "corrosion", "b_fail", -120, {"FAULT"},
     (("FAULT", "leak"),)),
    ("Drone strike during planned work", "bypass_planned", "drone", 120, {"PHYSICAL"},
     (("PHYSICAL", "damage"),)),
    ("Corrosion leak and water ingress", "corrosion", "water", 0, {"FAULT"},
     (("FAULT", "leak"), ("FAULT", "water"))),
    ("Theft under cover of a work order", "bypass_planned", "theft", 120, {"PHYSICAL"},
     (("PHYSICAL", "theft"),)),
    ("Theft by someone over the fence", None, "theft_fence", 0, {"PHYSICAL"},
     (("PHYSICAL", "theft"),)),
)


def print_mixed(cfg: Config, seeds: int) -> dict:
    """Two things at once: a cyberattack with a theft, a leak with a dead backup sensor, a drone during planned work.

    'First answer right' = the first verdict names one of the true causes (and comes after the first one began).
    'Both found' = every true cause shows up during the run, as a main verdict or as a second finding beside one."""
    c = replace(cfg, ticks=1800, inject_at=400)
    plant = "realistic plant (PID valve)" if c.control == "pid" else "simple plant (on/off pump)"
    print()
    print(f"Mixed cases on the {plant}: {seeds} seeds x backup on/off, 30-minute runs")
    header = f"{'Case':<38}{'First answer right':>20}{'Both found':>12}   Most common first answer"
    print(header)
    print("-" * len(header))
    out: dict = {"seeds": seeds, "plant": c.control, "rows": []}
    for name, main, second, gap, ok_first, causes in MIXED:
        first_ok = both = 0
        calls: dict[str, int] = {}
        for seed in range(1, seeds + 1):
            for backup in (False, True):
                recs = TankSimulator(c, main, "permanent", backup, seed, second=second, second_delay=gap).run()
                v, _ = diagnose(recs, c)
                timeline = findings(recs, c)
                start = min(c.inject_at, c.inject_at + gap)
                call = f"{v.label}: {v.culprit}" if v else "nothing"
                calls[call] = calls.get(call, 0) + 1
                first_ok += v is not None and v.tick >= start and v.label in ok_first
                seen = [(x.label, x.culprit.lower()) for x in timeline if x.tick >= start]
                both += all(any(lab == want and key in cul for lab, cul in seen) for want, key in causes)
        total = 2 * seeds
        top = max(calls, key=calls.get)
        print(f"{name:<38}{first_ok:>14}/{total:<5}{both:>7}/{total:<4}   {top}")
        out["rows"].append({"name": name, "first_ok": first_ok, "both": both, "total": total, "top": top})
    print("-" * len(header))
    print()
    return out


def print_healthy(cfg: Config, hours: int) -> dict:
    """False alarms over long healthy runs with ordinary disturbances switched on: rain showers filling the bund,
    gas-detector bump tests, planned visits (door opened under a work order), and the product warming and cooling
    over the day. Every verdict here is a false alarm. Runs are 24 hours long (shorter for the last one)."""
    plant = "realistic plant (PID valve)" if cfg.control == "pid" else "simple plant (on/off pump)"
    print()
    print(f"False alarms on the {plant}: {hours} healthy hours with rain, gas-detector tests, planned visits and the daily "
          "temperature swing")
    alarms: list[tuple[int, int, str]] = []
    left, seed = hours, 0
    while left > 0:
        seed += 1
        span = min(24, left)
        left -= span
        c = replace(cfg, ticks=span * 3600, inject_at=span * 3600 - 1)
        recs = TankSimulator(c, None, "permanent", seed % 2 == 0, 500 + seed, disturbances=True).run()
        _, timeline = diagnose(recs, c)
        alarms += [(500 + seed, x.tick, f"{x.label}: {x.culprit}") for x in timeline]
    by_rule: dict[str, int] = {}
    for _, _, call in alarms:
        by_rule[call] = by_rule.get(call, 0) + 1
    print(f"Verdicts raised: {len(alarms)} in {hours} hours ({100 * len(alarms) / hours:.1f} per 100 hours)")
    for call, n in sorted(by_rule.items(), key=lambda kv: -kv[1]):
        print(f"  {n:>3}  {call}")
    for seed, tick, call in alarms[:20]:
        print(f"  seed {seed}, hour {tick / 3600:.1f}: {call}")
    print()
    return {"hours": hours, "plant": cfg.control, "alarms": len(alarms), "by_rule": by_rule}
