"""Tests for the admin console: incidents, drills, recorded-data playback and the web API."""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fault_or_attack.admin.incidents import IncidentLog                      # noqa: E402
from fault_or_attack.admin.server import build, make_handler, parse_columns  # noqa: E402
from fault_or_attack.admin.sources import CsvSource, write_sample_csv       # noqa: E402
from fault_or_attack.config import Config                                    # noqa: E402
from fault_or_attack.detector import Verdict                                 # noqa: E402


def run_drill(engine, key, warmup=120, after=600):
    for _ in range(warmup):
        engine.step()
    engine.start_drill(key, "permanent", 30, False)
    for _ in range(after):
        engine.step()
    return engine.end_drill()


class IncidentLogTests(unittest.TestCase):
    def test_repeated_verdicts_make_one_incident(self):
        log = IncidentLog()
        for t in range(1, 50):
            log.observe(Verdict(t, "FAULT", "Leak", "loss"), t)
        self.assertEqual(len(log.items), 1)
        self.assertEqual(log.items[0].seconds_seen, 49)

    def test_incident_clears_when_the_detector_goes_quiet(self):
        log = IncidentLog(clear_after=30)
        log.observe(Verdict(1, "FAULT", "Leak", "loss"), 1)
        log.observe(None, 20)
        self.assertTrue(log.items[0].active)
        log.observe(None, 40)
        self.assertFalse(log.items[0].active)
        self.assertIsNone(log.headline())
        self.assertEqual(log.items[0].status, "new")       # still needs an operator to close it

    def test_resolving_while_still_seen_does_not_reopen_at_once(self):
        log = IncidentLog(clear_after=10)
        log.observe(Verdict(1, "FAULT", "Leak", "loss"), 1)
        log.resolve(1, "Ali", "False alarm", "checked on site")
        for t in range(2, 8):
            log.observe(Verdict(t, "FAULT", "Leak", "loss"), t)
        self.assertEqual(len(log.items), 1)
        for t in range(8, 30):
            log.observe(None, t)
        log.observe(Verdict(30, "FAULT", "Leak", "loss"), 30)
        self.assertEqual(len(log.items), 2)                # a recurrence after a quiet spell is new

    def test_attack_needs_a_note_to_be_closed_as_something_else(self):
        log = IncidentLog()
        log.observe(Verdict(1, "ATTACK", "Replay attack", "x"), 1)
        with self.assertRaises(ValueError):
            log.resolve(1, "Ali", "False alarm", "")
        log.resolve(1, "Ali", "False alarm", "engineer's laptop, confirmed by phone")
        self.assertEqual(log.items[0].status, "resolved")

    def test_firm_answer_absorbs_early_warning_and_names(self):
        log = IncidentLog()
        log.observe(Verdict(1, "UNKNOWN", "Mass balance drifting", "cusum"), 1)
        log.observe(Verdict(2, "ATTACK", "False data injection", "rough"), 2)
        log.observe(Verdict(3, "ATTACK", "Disguised attack", "new device"), 3)
        log.observe(Verdict(4, "UNKNOWN", "Unexplained alarm", "alarm"), 4)
        self.assertEqual([i.label for i in log.items], ["UNKNOWN", "ATTACK"])
        self.assertEqual(log.items[0].status, "resolved")
        self.assertEqual(log.items[1].also_seen, ["Disguised attack"])
        self.assertEqual(log.headline().label, "ATTACK")

    def test_plant_restart_starts_fresh_incidents(self):
        # Before the fix, an ATTACK after a restart was filed into the open ATTACK incident from before it.
        log = IncidentLog()
        log.observe(Verdict(1, "ATTACK", "Command injection", "x"), 1)
        log.observe(Verdict(2, "FAULT", "Leak", "loss"), 2)
        log.plant_restarted(3)
        self.assertIsNone(log.headline())                   # nothing is being watched any more ...
        self.assertEqual(log.counts()["open"], 2)           # ... but the operator still has to close them
        log.observe(Verdict(4, "ATTACK", "Disguised attack", "new device"), 4)
        log.observe(Verdict(5, "FAULT", "Leak", "loss"), 5)
        self.assertEqual([(i.label, i.culprit) for i in log.items[2:]],
                         [("ATTACK", "Disguised attack"), ("FAULT", "Leak")])
        self.assertEqual(log.headline().culprit, "Disguised attack")

    def test_audit_log_and_csv(self):
        with tempfile.TemporaryDirectory() as d:
            log = IncidentLog(Path(d))
            log.observe(Verdict(1, "PHYSICAL", "Product theft", "x"), 1)
            log.acknowledge(1, "Siti", "sent security")
            lines = [json.loads(x) for x in log.log_path.read_text().splitlines()]
            self.assertEqual([x["event"] for x in lines], ["opened", "acknowledged"])
            self.assertEqual(lines[1]["who"], "Siti")
            self.assertIn("Product theft", log.to_csv())


class EngineTests(unittest.TestCase):
    def test_healthy_plant_stays_quiet(self):
        engine = build(Config())
        for _ in range(900):
            engine.step()
        self.assertEqual(engine.log.items, [])

    def test_drills_are_diagnosed(self):
        for key, kind in (("spoof", "ATTACK"), ("leak", "FAULT"), ("hand_valve", "PHYSICAL"), ("it_hit", "IT")):
            with self.subTest(key=key):
                result = run_drill(build(Config()), key)
                self.assertTrue(result["right"], result["verdict"])
                self.assertEqual(result["kind"], kind)

    def test_back_to_back_drills_on_one_console(self):
        # A live demo runs drills one after another on the same console, and a scenario may be repeated.
        engine = build(Config())
        for key in ("leak", "command", "stealth", "stealth", "leak"):
            with self.subTest(key=key):
                result = run_drill(engine, key, warmup=0)
                self.assertTrue(result["right"], result["verdict"])

    def test_demos_keep_their_promises(self):
        # The words on the demo buttons say what the audience will see. Run each one twice, back to back, on both
        # plants, as on stage, and check the console really shows it.
        from fault_or_attack.admin.demos import DEMOS
        from fault_or_attack.config import realistic
        from fault_or_attack.learning import learn_from_normal
        promised = {"fault": {"FAULT": {"Low", "Medium"}}, "attack": {"ATTACK": {"Low", "High"}},
                    "tricky": {"ATTACK": {"High"}}}
        for plant, cfg in (("simple", Config()), ("realistic", learn_from_normal(realistic(Config())))):
            engine = build(cfg)
            for demo in DEMOS + DEMOS:
                with self.subTest(plant=plant, demo=demo.id):
                    engine.start_demo(demo.id)
                    shown: dict[str, set] = {}
                    for _ in range(demo.lead + 240):
                        engine.step()
                        head = engine.state()["headline"]
                        if head and head["label"] != "UNKNOWN":
                            shown.setdefault(head["label"], set()).add(head["confidence"])
                    self.assertEqual(set(shown), {demo.kind})          # never the wrong answer on screen
                    for label, levels in promised[demo.id].items():
                        self.assertLessEqual(levels, shown[label], f"promised {levels}, showed {shown[label]}")
                    if demo.id == "fault":
                        self.assertNotIn("High", shown["FAULT"])
            result = engine.end_drill()
            self.assertTrue(result["right"], result["verdict"])

    def test_headline_shows_confidence_and_evidence(self):
        engine = build(Config())
        for _ in range(60):
            engine.step()
        engine.start_drill("stealth", "permanent", 10, False)
        for _ in range(120):
            engine.step()
        head = engine.state()["headline"]
        self.assertEqual(head["label"], "ATTACK")
        self.assertIn(head["confidence"], ("High", "Medium", "Low"))
        self.assertTrue(head["evidence"])
        self.assertIn("confidence", engine.log.to_csv().splitlines()[0])

    def test_planned_work_stays_quiet(self):
        result = run_drill(build(Config()), "bypass_planned")
        self.assertTrue(result["right"], result["verdict"])

    def test_hidden_drill_is_not_shown(self):
        engine = build(Config())
        engine.step()
        engine.start_drill("replay", "permanent", 30, True)
        state = engine.state()
        self.assertNotIn("name", state["drill"])
        self.assertNotIn("replay", json.dumps(state["drill"]))

    def test_detector_rollover_keeps_memory_bounded(self):
        from fault_or_attack.admin import engine as eng
        old = eng.ROLLOVER, eng.WARMUP
        eng.ROLLOVER, eng.WARMUP = 400, 200
        try:
            engine = build(Config())
            engine.recent = eng.deque(maxlen=200)
            for _ in range(900):
                engine.step()
            self.assertEqual(engine.rollovers, 2)
            self.assertLessEqual(len(engine.detector.h), 200 + 100)
            self.assertEqual(engine.log.items, [])           # warming up raised no alarms
            result = run_drill(engine, "spoof", warmup=0)    # and the fresh detector still works
            self.assertTrue(result["right"], result["verdict"])
        finally:
            eng.ROLLOVER, eng.WARMUP = old

    def test_clock_keeps_counting_after_reset(self):
        engine = build(Config())
        for _ in range(50):
            engine.step()
        engine.reset_plant()
        engine.step()
        self.assertEqual(engine.state()["tick"], 51)
        self.assertEqual(engine.state()["plant_tick"], 0)


class CsvTests(unittest.TestCase):
    def test_recorded_attack_is_caught(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "spoof.csv")
            write_sample_csv(path, Config(ticks=300, inject_at=120), "spoof")
            engine = build(Config(), path)
            while engine.step():
                pass
            self.assertTrue(engine.finished)
            first = min((i for i in engine.log.items if i.label != "UNKNOWN"), key=lambda i: i.first_tick)
            self.assertEqual(first.label, "ATTACK")
            self.assertGreaterEqual(first.first_tick, 120)

    def test_column_mapping_and_missing_columns(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "historian.csv")
            Path(path).write_text("LIT101,P101\n50.1,0\n49.0,1\n,1\n")
            src = CsvSource(path, Config(), parse_columns("sensor=LIT101,pump_cmd=P101"))
            recs = [src.next() for _ in range(3)]
            self.assertEqual(recs[1].sensor, 49.0)
            self.assertTrue(recs[1].pump_cmd)
            self.assertIsNone(recs[2].sensor)                  # a blank cell = no message
            self.assertEqual(recs[0].packets, Config().normal_packets)
            self.assertIsNone(src.next())
            with self.assertRaises(ValueError):
                CsvSource(path, Config())                      # no 'sensor' column without the mapping


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = build(Config())
        for _ in range(60):
            cls.engine.step()
        cls.engine.log.observe(Verdict(60, "ATTACK", "Command injection", "foreign write"), 60)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.engine, "pw"))
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def call(self, path, body=None, password="pw"):
        req = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        if password:
            req.add_header("Authorization", "Basic " + base64.b64encode(f"op:{password}".encode()).decode())
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()

    def test_password_is_required(self):
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.call("/api/state", password="wrong")
        self.assertEqual(e.exception.code, 401)

    def test_page_and_state(self):
        status, page = self.call("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Control room", page)
        self.engine.log.observe(Verdict(61, "PHYSICAL", "Product theft", "slow loss after unplanned access"), 61)
        state = json.loads(self.call("/api/state")[1])
        self.assertEqual(state["headline"]["culprit"], "Product theft")
        self.assertNotIn("level", state["plant"])           # only what a control room can see (plus lab truth)

    def test_operator_actions(self):
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.call("/api/incidents/1/ack", {"who": ""})
        self.assertEqual(e.exception.code, 400)
        self.call("/api/incidents/1/ack", {"who": "Zahin", "note": "called the team"})
        self.call("/api/incidents/1/note", {"who": "Zahin", "note": "BruCERT informed"})
        self.call("/api/incidents/1/resolve", {"who": "Zahin", "outcome": "Confirmed attack"})
        items = {i["id"]: i for i in json.loads(self.call("/api/incidents")[1])["items"]}
        self.assertEqual(items[1]["status"], "resolved")
        self.assertEqual([h["what"] for h in items[1]["history"]][-3:],
                         ["Acknowledged", "Note", "Resolved: Confirmed attack"])
        self.assertIn(b"Zahin", self.call("/api/export.csv")[1])

    def test_demo_routes(self):
        demos = json.loads(self.call("/api/demos")[1])["demos"]
        self.assertEqual([d["id"] for d in demos], ["fault", "attack", "tricky"])
        self.call("/api/demo/start", {"id": "tricky"})
        state = json.loads(self.call("/api/state")[1])
        self.assertEqual(state["demo"]["scenario"], "stealth")
        self.assertEqual(state["drill"]["key"], "stealth")
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.call("/api/demo/start", {"id": "nope"})
        self.assertEqual(e.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
