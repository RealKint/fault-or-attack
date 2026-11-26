"""The console's engine: reads one second of plant data, asks the detector, and updates the incidents.

Runs in its own thread so the web page can ask for the state at any time.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import asdict

from ..config import Config
from ..detector import FaultOrAttackDetector, Verdict
from ..plant import Record
from .demos import BY_ID as DEMOS, Demo
from .incidents import IncidentLog
from .sources import VISIBLE_FIELDS, CsvSource, SimulatedSource


TREND_SECONDS = 600   # seconds of history the page can draw
ROLLOVER = 6 * 3600   # the detector keeps every reading it has seen; start a fresh one this often ...
WARMUP = 3600         # ... warmed up on this many recent seconds, so its longest windows are full again


class Engine:
    def __init__(self, source: SimulatedSource | CsvSource, cfg: Config, log: IncidentLog, speed: float = 1.0):
        self.source, self.cfg, self.log = source, cfg, log
        self.speed = speed
        self.paused = False
        self.finished = False
        self.lock = threading.RLock()
        self.detector = FaultOrAttackDetector(cfg)
        self.trend: deque[dict] = deque(maxlen=TREND_SECONDS)
        self.recent: deque[Record] = deque(maxlen=WARMUP)   # for warming up a fresh detector
        self.detector_since = 0                            # console second the current detector started
        self.rollovers = 0
        self.last: Record | None = None
        self.last_verdict: Verdict | None = None
        self.last_verdict_tick: int | None = None
        self.alarms = 0                          # incidents opened so far (the page beeps when it goes up)
        self.drill_result: dict | None = None    # the last drill's reveal
        self.demo: Demo | None = None            # the scripted demo being shown, if the drill is one
        self.started = time.time()
        # The console's own second counter. It keeps counting when the simulated plant is reset (the plant's
        # own clock starts again from 0), so incidents and the trend chart never go back in time.
        self.clock = 0
        self._stop = threading.Event()
        self.thread: threading.Thread | None = None

    # --- running -------------------------------------------------------------------
    def step(self) -> Record | None:
        """One second of plant time."""
        with self.lock:
            rec = self.source.next()
            if rec is None:
                self.finished = True
                return None
            self.clock += 1
            v = self.detector.observe(rec)
            if self.detector.want_probe and isinstance(self.source, SimulatedSource):
                self.source.request_probe()
                self.detector.want_probe = False
            opened = self.log.observe(v, self.clock)
            self.alarms += len(opened)
            if v is not None:
                self.last_verdict, self.last_verdict_tick = v, self.clock
            self.last = rec
            self.recent.append(rec)
            self.trend.append(self._point(rec, v))
            self._maybe_rollover()
            return rec

    def _maybe_rollover(self) -> None:
        """Keep memory bounded on a console left running for days. The detector stores every reading (about
        200 MB a day), so every ROLLOVER seconds, while nothing is wrong, it is replaced by a fresh one that has
        re-read the last hour. Only done when quiet, so no evidence for an open problem is lost."""
        if self.clock - self.detector_since < ROLLOVER or self.log.headline() is not None:
            return
        fresh = FaultOrAttackDetector(self.cfg)
        for r in self.recent:
            fresh.observe(r)
        fresh.want_probe = False
        self.detector, self.detector_since = fresh, self.clock
        self.rollovers += 1

    def _point(self, r: Record, v: Verdict | None) -> dict:
        return {"t": self.clock, "plant_t": r.tick, "a": r.sensor, "b": r.sensor_b, "pump": r.pump_cmd, "fb": r.pump_feedback,
                "valve": r.valve_pos, "pk": r.packets, "v": v.label if v else None,
                # Plant truth, shown only when the instructor ticks "show the real level" in the lab panel.
                "real": round(r.level, 2) if isinstance(self.source, SimulatedSource) else None}

    def run_forever(self) -> None:
        while not self._stop.is_set():
            if self.paused or self.finished:
                time.sleep(0.1)
                continue
            began = time.monotonic()
            self.step()
            wait = 1.0 / max(self.speed, 0.01) - (time.monotonic() - began)
            if wait > 0:
                self._stop.wait(wait)

    def start(self) -> None:
        self.thread = threading.Thread(target=self.run_forever, name="foa-engine", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()

    # --- controls ------------------------------------------------------------------
    def set_speed(self, speed: float) -> None:
        if not 0.1 <= speed <= 50:
            raise ValueError("Speed must be between 0.1 and 50 plant seconds per real second")
        self.speed = speed

    def reset_plant(self) -> None:
        """A fresh healthy plant and a fresh detector. The incident log is kept, but its incidents are marked as no
        longer seen, because the fresh detector has not seen them."""
        with self.lock:
            if not isinstance(self.source, SimulatedSource):
                raise ValueError("Only the simulated plant can be reset")
            self.source.reset()
            self.log.plant_restarted(self.clock)
            self.detector = FaultOrAttackDetector(self.cfg)
            self.detector_since = self.clock
            self.recent.clear()
            self.last_verdict = None
            self.last_verdict_tick = None

    def start_demo(self, demo_id: str) -> dict:
        """One click on stage: finish whatever is running, give the audience a healthy tank, then run the demo."""
        with self.lock:
            demo = DEMOS.get(demo_id)
            if demo is None:
                raise ValueError(f"Unknown demo {demo_id!r}")
            if not isinstance(self.source, SimulatedSource):
                raise ValueError("Demos need the simulated plant")
            if self.source.drill is not None:
                self.end_drill()                 # scores it and resets the plant
            else:
                self.reset_plant()
            self.paused = False
            d = self.start_drill(demo.scenario, demo.mode, demo.lead, False)
            self.demo = demo
            return d

    def start_drill(self, key: str, mode: str, lead: int, hidden: bool) -> dict:
        with self.lock:
            if not isinstance(self.source, SimulatedSource):
                raise ValueError("Drills need the simulated plant")
            self.drill_result = None
            self.demo = None
            d = self.source.start_drill(key, mode, lead, hidden)
            # The plant record with tick == starts_at will be console second clock + (starts_at - next tick) + 1.
            d["clock_start"] = self.clock + d["starts_at"] - self.source.tick + 1
            return d

    def end_drill(self) -> dict:
        """Reveal what the drill was, score the detector's first answer, and give the plant a fresh start."""
        with self.lock:
            src = self.source
            if not isinstance(src, SimulatedSource) or src.drill is None:
                raise ValueError("No drill is running")
            d = src.drill
            start = d["clock_start"]
            mine = [i for i in self.log.items if i.last_tick >= start - 60]
            early = [i for i in mine if i.first_tick < start]
            after = sorted((i for i in mine if i.first_tick >= start), key=lambda i: i.first_tick)
            firm = [i for i in after if not i.secondary and i.label != "UNKNOWN"]
            # Office IT drills unfold in stages (IT first, then the plant is hit), so they are judged on the latest
            # firm answer; everything else on the first, as in the project's own evaluation.
            first = (firm[-1] if d["key"].startswith("it_") else firm[0]) if firm else None
            if d["kind"] == "NONE":
                right = not after
                verdict = "stayed quiet, as it should" if right else f"raised {after[0].label}, a false alarm"
            else:
                right = first is not None and first.label == d["kind"]
                verdict = (f"answered {first.label} ({first.culprit}) {first.first_tick - start} s after it began"
                           if first else "never gave a firm answer")
            text = f"Drill: {d['name']} ({d['kind']})"
            self.log.tag_drill(start - 60, text)
            self.drill_result = {**d, "right": right, "verdict": verdict,
                                 "false_alarms_before": len(early), "incidents": [i.id for i in mine]}
            self.reset_plant()
            return self.drill_result

    # --- views ---------------------------------------------------------------------
    def state(self, since: int | None = None, show_hidden_drill: bool = False) -> dict:
        with self.lock:
            src = self.source
            rec = self.last
            plant = {k: getattr(rec, k) for k in VISIBLE_FIELDS} if rec else None
            if plant is not None and isinstance(src, SimulatedSource):
                plant["real"] = round(rec.level, 2)
            head = self.log.headline()
            trend = [p for p in self.trend if since is None or p["t"] > since]
            if since is not None and self.trend and since > self.trend[-1]["t"]:
                trend = list(self.trend)            # the plant was reset: send everything again
            drill = None
            if isinstance(src, SimulatedSource) and src.drill is not None:
                d = src.drill
                drill = {"starts_in": d["starts_at"] - src.tick, "mode": d["mode"], "hidden": d["hidden"],
                         **({} if d["hidden"] and not show_hidden_drill else
                            {k: d[k] for k in ("key", "name", "kind", "what_happens", "how_caught")})}
            v = self.last_verdict
            return {
                "source": src.describe(),
                "tick": self.clock if rec else None,
                "plant_tick": rec.tick if rec else None,
                "speed": self.speed, "paused": self.paused, "finished": self.finished,
                "uptime": int(time.time() - self.started),
                "plant": plant,
                "headline": None if head is None else {"id": head.id, "label": head.label, "culprit": head.culprit,
                                                       "reason": head.reason, "action": head.action,
                                                       "mitre": head.mitre, "playbook": head.playbook,
                                                       "status": head.status, "confidence": head.confidence,
                                                       "evidence": head.evidence, "conflicts": head.conflicts},
                "verdict_now": None if v is None or self.clock - (self.last_verdict_tick or 0) > 2 else
                {"label": v.label, "culprit": v.culprit, "confidence": v.confidence},
                "trend": trend,
                "counts": self.log.counts(),
                "alarms": self.alarms,
                "log_version": self.log.version,
                "drill": drill,
                "drill_result": self.drill_result,
                "demo": None if self.demo is None else self.demo.as_dict(),
                "config": {"high_alarm": self.cfg.high_alarm, "low_alarm": self.cfg.low_alarm,
                           "control": self.cfg.control, "normal_packets": self.cfg.normal_packets},
            }

    def verdict_dict(self, v: Verdict) -> dict:
        d = asdict(v)
        d.pop("also", None)
        return d
