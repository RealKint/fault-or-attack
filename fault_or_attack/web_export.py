"""Records every demonstration for the website (web/data.js)."""

from __future__ import annotations


from .config import PROJECT_DIR, Config, realistic
from .detector import FaultOrAttackDetector, diagnose
from .evaluation import _verdict_ok, print_eval, print_healthy
from .hai_validation import HaiDataError, hai_main
from .learning import learn_from_normal
from .plant import Record, TankSimulator
from .scenarios import SCENARIOS, SMART_ATTACKS


def _record_run(sim: TankSimulator, records: list[Record], cfg: Config) -> dict:
    """One simulated run, compacted for the web page: per-second signals plus the detector's view."""
    det = FaultOrAttackDetector(cfg)
    per_tick = list(getattr(records, "verdicts", [])) if getattr(records, "cfg", None) == cfg else []
    if len(per_tick) != len(records):
        per_tick = [det.observe(r) for r in records]
    verdicts: list[dict] = []
    now: list[int | None] = []
    for v in per_tick:
        if v is None:
            now.append(None)
            continue
        last = verdicts[-1] if verdicts else None
        if not last or (last["label"], last["culprit"]) != (v.label, v.culprit) or now[-1] is None:
            verdicts.append({"t": v.tick, "label": v.label, "culprit": v.culprit, "reason": v.reason,
                             "mitre": v.mitre, "action": v.action})
        now.append(len(verdicts) - 1)
    first, _ = diagnose(records, cfg)
    pid = cfg.control == "pid"
    r2 = lambda x: None if x is None else round(x, 2)
    return {
        "control": cfg.control, "inject": cfg.inject_at, "ticks": len(records),
        "level": [round(r.level, 2) for r in records],
        "a": [r2(r.sensor) for r in records], "b": [r2(r.sensor_b) for r in records],
        "cmd": [r2(r.valve_cmd) if pid else int(r.pump_cmd) for r in records],
        "fb": [r2(r.valve_pos) if pid else int(r.pump_feedback) for r in records],
        "real": [r2(r.valve_real) if pid else int(r.pump_flow) for r in records],
        "outflow": [r2(r.outflow) for r in records], "packets": [r.packets for r in records],
        "writes": [r.unknown_writes for r in records], "power": [int(r.power_ok) for r in records],
        "newdev": next((r.tick for r in records if r.new_devices), None),
        "probe": [int(r.probe) for r in records], "hi": [int(r.switch_high) for r in records],
        "lo": [int(r.switch_low) for r in records], "active": [int(r.fault_active) for r in records],
        "alarm": [r.screen_alarm for r in records],
        "now": now, "verdicts": verdicts,
        "first": None if first is None else {"t": first.tick, "label": first.label, "culprit": first.culprit},
        "correct": _verdict_ok(sim.fault, first, cfg),
    }


def export_web(out_dir: str = "web", seeds: int = 3, eval_seeds: int = 20, hai: bool = True,
               healthy_hours: int = 120) -> None:
    """Write web/data.js for the website: recorded runs of every scenario on both plants,
    the accuracy evaluation, and the real HAI results (if the dataset is downloaded)."""
    import json
    from datetime import date
    from pathlib import Path

    out = PROJECT_DIR / out_dir          # relative to the project folder, not where you run from
    hai_dir = PROJECT_DIR / "data" / "hai"
    out.mkdir(exist_ok=True)
    base = Config()
    plants = {"simple": base, "realistic": learn_from_normal(realistic(base))}
    data: dict = {
        "generated": date.today().isoformat(),
        "scenarios": {k: {"name": i.name, "kind": i.kind, "category": i.category, "what": i.what_happens,
                          "how": i.how_caught} for k, i in SCENARIOS.items()},
        "smart": list(SMART_ATTACKS), "runs": {}, "eval": {}, "hai": [],
        "config": {"high_alarm": base.high_alarm, "low_alarm": base.low_alarm, "setpoint": base.setpoint,
                   "pump_on_below": base.pump_on_below, "pump_off_above": base.pump_off_above,
                   "normal_packets": base.normal_packets},
    }
    total = len(plants) * (len(SCENARIOS) + 1) * 2 * seeds
    done = 0
    for plant, cfg in plants.items():
        for key in [None, *SCENARIOS]:
            for backup in (False, True):
                for seed in range(1, seeds + 1):
                    sim = TankSimulator(cfg, key, "permanent", backup, seed)
                    data["runs"][f"{plant}|{key or 'healthy'}|{int(backup)}|{seed}"] = _record_run(sim, sim.run(), cfg)
                    done += 1
            print(f"  recorded {done}/{total} runs", end="\r")
    print(f"  recorded {total} runs.            ")
    if eval_seeds:
        print(f"Scoring both plants over {eval_seeds} seeds for the results section (a few minutes)...")
        for plant, cfg in plants.items():
            data["eval"][plant] = print_eval(cfg, eval_seeds)
        if healthy_hours:
            # The long false-alarm test: healthy days with rain, gas-detector tests, planned visits and the
            # daily temperature swing (about ten minutes per plant).
            print(f"Counting false alarms over {healthy_hours} healthy hours per plant (several minutes)...")
            data["healthy"] = {plant: print_healthy(cfg, healthy_hours) for plant, cfg in plants.items()}
    if hai:
        for test in (hai_dir / "test1.csv", hai_dir / "test2.csv"):
            try:
                open(test).close()
                open(hai_dir / "train1.csv").close()
            except OSError:
                print(f"  (skipping real-data section: {test} not found)")
                continue
            try:
                data["hai"].append(hai_main(str(hai_dir / "train1.csv"), str(test)))
            except HaiDataError as problem:
                print(f"  (skipping real-data section: {problem})")
    # Photo credits for the page footer: one source of truth, web/img/credits.json (kept with the photos).
    try:
        credits = json.loads((PROJECT_DIR / "web" / "img" / "credits.json").read_text(encoding="utf-8"))
        keep = ("title", "creator", "license", "licenseCode", "licenseUrl", "page", "via")
        data["credits"] = [{k: c.get(k) for k in keep} for c in credits if isinstance(c, dict)]
    except (OSError, ValueError):
        data["credits"] = []
    target = out / "data.js"
    target.write_text("window.FOA_DATA = " + json.dumps(data, separators=(",", ":")) + ";\n", encoding="utf-8")
    print(f"Wrote {target} ({target.stat().st_size / 1e6:.1f} MB). Open {out / 'index.html'} in a browser.")
