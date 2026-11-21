"""Summaries and scoring: single-run report, the all-scenarios table and the multi-seed evaluation."""

from __future__ import annotations

from dataclasses import dataclass, replace
from statistics import mean

from .config import Config
from .detector import Verdict, diagnose
from .plant import Record, TankSimulator
from .scenarios import ATTACKS, MODES, SCENARIOS, SMART_ATTACKS


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
