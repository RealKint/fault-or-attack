"""Where the console's readings come from, one Record per second.

SimulatedSource  the project's tank simulator, running forever, with a lab panel to start drills.
CsvSource        recorded readings (a historian export, or a file made with --make-sample), played back in order.

A future Modbus or OPC UA source only has to provide the same three things: next(), lab (False) and describe().
"""

from __future__ import annotations

import csv
from collections import deque
from dataclasses import fields, replace

from ..config import Config
from ..plant import Record, TankSimulator, choose_reading, classify, screen_alarm
from ..scenarios import KNOWN_SCENARIOS, MODES, REPLAYS


NEVER = 10 ** 12   # "the scenario has not been scheduled": a start second the plant never reaches

# Columns a CSV may carry: everything the detector is allowed to see. Hidden plant truth (real level, whether the
# pump really ran, real valve position) is never needed. Only "sensor" is required.
VISIBLE_FIELDS = (
    "tick", "sensor", "sensor_b", "pump_cmd", "pump_feedback", "outflow", "packets", "unknown_writes", "new_devices",
    "probe", "power_ok", "valve_cmd", "valve_pos", "switch_high", "switch_low", "tamper", "door", "work_order",
    "bypass", "gas_alarm", "bund", "interface", "wall", "it_alert",
)
BOOL_FIELDS = {"pump_cmd", "pump_feedback", "probe", "power_ok", "switch_high", "switch_low", "tamper", "door",
               "work_order", "bypass", "gas_alarm", "it_alert"}
INT_FIELDS = {"tick", "packets", "unknown_writes", "new_devices"}

# Scenarios offered in the lab panel, grouped the way an instructor thinks about them.
LAB_GROUPS = {
    "Equipment faults": ("drift", "stuck", "pump", "valve", "leak", "power", "maint_leak", "water", "thinning"),
    "Cyberattacks": ("spoof", "replay", "smart_replay", "stealth", "command", "dos", "forge"),
    "Physical (on site)": ("theft", "hand_valve", "bypass", "tamper_b", "drone", "corrosion"),
    "Office IT incidents": ("it_hit", "it_spread", "it_fault"),
    "Planned work (should stay quiet)": ("bypass_planned",),
}


class SimulatedSource:
    """The tank simulator, stepped one second at a time with no end. Scenarios are started from the lab panel."""

    kind = "simulated"
    lab = True

    def __init__(self, cfg: Config, backup: bool = True, seed: int = 1, disturbances: bool = True):
        self.base_cfg, self.backup, self.seed, self.disturbances = cfg, backup, seed, disturbances
        self.resets = 0
        self.reset()

    def reset(self) -> None:
        """A fresh, healthy plant. The simulator gets its own copy of the settings, because a drill moves its
        start second (inject_at) while the plant is running."""
        cfg = replace(self.base_cfg, ticks=NEVER + 1, inject_at=NEVER)
        self.sim = TankSimulator(cfg, None, "permanent", self.backup, self.seed + self.resets,
                                 disturbances=self.disturbances)
        self.resets += 1
        self.drill: dict | None = None

    @property
    def tick(self) -> int:
        return self.sim.tick

    def next(self) -> Record:
        return self.sim.step()

    def request_probe(self) -> None:
        """The detector asked the controller to run a probe (realistic plant only)."""
        self.sim.probe_requested = True

    def start_drill(self, key: str, mode: str = "permanent", lead: int = 60, hidden: bool = False) -> dict:
        if key not in KNOWN_SCENARIOS:
            raise ValueError(f"Unknown scenario {key!r}")
        if mode not in MODES:
            raise ValueError(f"Unknown mode {mode!r}")
        if self.drill is not None:
            raise ValueError("A drill is already running. End it first.")
        # Site events (a door, a work order) happen up to 60 s before the event itself, and a replay attacker
        # needs time to record, so the scenario starts a little after the button is pressed.
        lead = max(lead, 60 if key in ("theft", "hand_valve", "maint_leak", "bypass_planned") else 0,
                   self.sim.cfg.replay_length if key in REPLAYS else 0, 1)
        s = self.sim
        s.fault, s.mode = key, mode
        s.cfg.inject_at = s.tick + lead
        # Forget anything left over from an earlier drill.
        s.announced, s.replay_i, s.fake, s.twin, s.frozen = False, None, None, None, None
        s.stealth_offset = s.drift = 0.0
        info = KNOWN_SCENARIOS[key]
        self.drill = {"key": key, "name": info.name, "kind": info.kind, "mode": mode, "starts_at": s.cfg.inject_at,
                      "hidden": hidden, "what_happens": info.what_happens, "how_caught": info.how_caught}
        return self.drill

    def describe(self) -> dict:
        cfg = self.base_cfg
        return {"kind": self.kind, "name": "Simulated tank (" + ("realistic PI valve" if cfg.control == "pid"
                                                                 else "simple on/off pump") + ")",
                "backup_sensor": self.backup, "lab": True}


def _parse(name: str, text: str):
    text = (text or "").strip()
    if text == "" or text.lower() in ("none", "null", "nan"):
        return None
    if name in BOOL_FIELDS:
        low = text.lower()
        if low in ("1", "true", "yes", "on", "y", "t"):
            return True
        if low in ("0", "false", "no", "off", "n", "f"):
            return False
        return float(text) != 0
    if name in INT_FIELDS:
        return int(float(text))
    return float(text)


class CsvSource:
    """Recorded readings played back in order. Missing columns get a quiet default (no network events, power on,
    no site signals). The detector only ever sees what a control room could see, so the hidden truth fields of
    the Record are filled with neutral values that nothing reads."""

    kind = "recorded"
    lab = False

    def __init__(self, path: str, cfg: Config, column_map: dict[str, str] | None = None):
        self.path, self.cfg = path, cfg
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames or []
            rename = {v: k for k, v in (column_map or {}).items()}   # file column -> our field
            cols = {rename.get(c, c).strip(): c for c in header}
            if "sensor" not in cols:
                raise ValueError(f"{path}: needs a 'sensor' column (sensor A's level in %). Found: {header}. "
                                 "Use --columns to map your own names, e.g. --columns sensor=LIT101,pump_cmd=P101")
            self.rows = []
            for row in reader:
                self.rows.append({k: _parse(k, row[c]) for k, c in cols.items() if k in VISIBLE_FIELDS})
        if not self.rows:
            raise ValueError(f"{path}: no data rows")
        self.columns = sorted(k for k in cols if k in VISIBLE_FIELDS)
        self.i = 0
        self.tick = 0
        self.last_rx = cfg.start_level
        self.duty_window: deque[float] = deque(maxlen=cfg.duty_window)

    @property
    def finished(self) -> bool:
        return self.i >= len(self.rows)

    def next(self) -> Record | None:
        if self.finished:
            return None
        row, cfg = self.rows[self.i], self.cfg
        self.i += 1
        get = lambda k, default: default if row.get(k) is None else row[k]   # noqa: E731
        tick = get("tick", self.i - 1)
        self.tick = tick
        sensor, sensor_b = row.get("sensor"), row.get("sensor_b")
        power_ok = get("power_ok", True)
        trusted, mismatch, a_lost = choose_reading(sensor, sensor_b, self.last_rx, cfg)
        self.last_rx = trusted
        pump_cmd = get("pump_cmd", False)
        valve_cmd = row.get("valve_cmd")
        self.duty_window.append(valve_cmd / 100 if valve_cmd is not None else (1.0 if pump_cmd else 0.0))
        duty = sum(self.duty_window) / len(self.duty_window)
        tone, status = classify(trusted, power_ok, mismatch, cfg, a_lost, sensor_b is not None)
        return Record(
            tick=tick, level=trusted, sensor=sensor, sensor_b=sensor_b, pump_cmd=pump_cmd,
            pump_flow=get("pump_feedback", pump_cmd), pump_feedback=get("pump_feedback", pump_cmd),
            outflow=row.get("outflow"), packets=get("packets", cfg.normal_packets),
            unknown_writes=get("unknown_writes", 0), new_devices=get("new_devices", 0), probe=get("probe", False),
            power_ok=power_ok, valve_cmd=valve_cmd, valve_pos=row.get("valve_pos"), valve_real=None,
            switch_high=get("switch_high", False), switch_low=get("switch_low", False),
            duty=duty, run_duty=duty, fault_active=False, tone=tone, status=status,
            screen_alarm=screen_alarm(trusted, power_ok, mismatch, a_lost, sensor_b is not None, cfg),
            tamper=get("tamper", False), door=get("door", False), work_order=get("work_order", False),
            bypass=get("bypass", False), gas_alarm=get("gas_alarm", False), bund=get("bund", 0.0),
            interface=row.get("interface"), wall=row.get("wall"), it_alert=get("it_alert", False),
        )

    def describe(self) -> dict:
        return {"kind": self.kind, "name": f"Recorded data: {self.path}", "rows": len(self.rows),
                "columns": self.columns, "lab": False}


def write_sample_csv(path: str, cfg: Config, scenario: str | None, seed: int = 1, backup: bool = True,
                     mode: str = "permanent") -> int:
    """Write a simulated run as a CSV of visible readings only, in the format CsvSource reads. Handy for trying the
    recorded-data path, or as a template for a historian export."""
    sim = TankSimulator(cfg, scenario, mode, backup, seed)
    recs = sim.run()
    names = [f.name for f in fields(Record) if f.name in VISIBLE_FIELDS]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(names)
        for r in recs:
            row = []
            for n in names:
                v = getattr(r, n)
                row.append("" if v is None else int(v) if isinstance(v, bool) else v)
            w.writerow(row)
    return len(recs)
