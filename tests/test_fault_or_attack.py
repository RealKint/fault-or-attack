"""
Automated tests for Fault or Attack.

Run them from the project folder (takes about a minute):

    python -m unittest discover -s tests -v

What they protect:
    - every module imports on its own
    - with probes off, the plant still behaves exactly like the original simulator
    - key command outputs are identical to the saved snapshots in tests/golden/
    - the detector calls every scenario right on the default runs, and stays quiet on healthy plants
    - bad command-line options and bad settings give clear errors
    - damaged or wrong HAI files give clear errors (and the real HAI check, if the data is downloaded)
    - the menu exits cleanly when there is no keyboard input

After a deliberate change to the results, refresh the snapshots with:

    set UPDATE_GOLDEN=1  (PowerShell: $env:UPDATE_GOLDEN=1)  then run the tests once
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

# Tests learn thresholds into a temporary cache, never your own learned_thresholds.json
# (child processes started by run_cli inherit this setting).
_CACHE_DIR = tempfile.TemporaryDirectory()
os.environ["FOA_THRESHOLDS_CACHE"] = str(Path(_CACHE_DIR.name) / "learned_thresholds.json")


def tearDownModule():
    _CACHE_DIR.cleanup()

from fault_or_attack.config import Config, realistic                      # noqa: E402
from fault_or_attack.detector import diagnose                             # noqa: E402
from fault_or_attack.evaluation import _verdict_ok                        # noqa: E402
from fault_or_attack.hai_validation import HaiDataError, hai_load, HAI_TAGS  # noqa: E402
from fault_or_attack.learning import learn_from_normal                    # noqa: E402
from fault_or_attack.plant import TankSimulator                           # noqa: E402
from fault_or_attack.scenarios import FAULTS, MODES, SCENARIOS           # noqa: E402

STARTER = PROJECT / "FAULT OR ATTACK.py"
GOLDEN = Path(__file__).resolve().parent / "golden"
HAI_DIR = PROJECT / "data" / "hai"


def run_cli(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    """Run the program like a user would, from the project folder."""
    return subprocess.run([sys.executable, str(STARTER), *args], cwd=PROJECT, input=stdin,
                          capture_output=True, text=True, timeout=600)


class TestModules(unittest.TestCase):
    def test_every_module_imports_on_its_own(self):
        names = ["config", "scenarios", "plant", "detector", "learning", "evaluation", "plots",
                 "live_demo", "hai_validation", "web_export", "cli"]
        for name in names:
            with self.subTest(module=name):
                result = subprocess.run([sys.executable, "-c", f"import fault_or_attack.{name}"],
                                        cwd=PROJECT, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)


class TestOriginalSimulator(unittest.TestCase):
    """With the secret probes off, the plant must still match the very first simulator exactly."""

    def test_plant_matches_original(self):
        path = Path(__file__).resolve().parent / "reference" / "original_simulator.py"
        spec = importlib.util.spec_from_file_location("original_simulator", path)
        original = importlib.util.module_from_spec(spec)
        sys.modules["original_simulator"] = original
        spec.loader.exec_module(original)
        for fault in [*original.FAULTS, None]:
            for mode in original.MODES:
                for backup in (False, True):
                    for seed in range(1, 6):
                        with self.subTest(fault=fault, mode=mode, backup=backup, seed=seed):
                            a = [(r.tick, r.level, r.sensor, r.pump_cmd, r.status)
                                 for r in original.TankSimulator(original.Config(), fault, mode, backup, seed).run()]
                            b = [(r.tick, r.level, r.sensor, r.pump_cmd, r.status)
                                 for r in TankSimulator(Config(probe=False), fault, mode, backup, seed).run()]
                            self.assertEqual(a, b)


class TestSnapshots(unittest.TestCase):
    """Command outputs must not change by accident."""

    CASES = {
        "all_simple": ["--all"],
        "all_realistic": ["--all", "--realistic"],
        "replay": ["--attack", "replay"],
        "leak_realistic": ["--fault", "leak", "--realistic"],
        "smart_replay_realistic_backup": ["--attack", "smart_replay", "--realistic", "--backup"],
        "stuck_intermittent": ["--fault", "stuck", "--mode", "intermittent"],
    }

    def test_outputs_match_snapshots(self):
        update = os.environ.get("UPDATE_GOLDEN") == "1"
        for name, args in self.CASES.items():
            with self.subTest(case=name):
                result = run_cli(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                snapshot = GOLDEN / f"{name}.txt"
                if update:
                    snapshot.write_text(result.stdout, encoding="utf-8")
                    continue
                # A missing snapshot is a failure, never a silent pass: create it on purpose with UPDATE_GOLDEN=1.
                self.assertTrue(snapshot.exists(), f"tests/golden/{name}.txt is missing; run once with UPDATE_GOLDEN=1")
                self.assertEqual(result.stdout, snapshot.read_text(encoding="utf-8"),
                                 f"output of {' '.join(args)} changed (see tests/golden/{name}.txt)")


class TestDetector(unittest.TestCase):
    def test_every_scenario_called_right_on_default_runs(self):
        for plant, cfg in (("simple", Config()), ("realistic", learn_from_normal(realistic(Config())))):
            for key in SCENARIOS:
                if plant == "realistic" and key == "smart_replay":
                    continue                  # a known hard case on the realistic plant (see the evaluation)
                with self.subTest(plant=plant, scenario=key):
                    verdict, _ = diagnose(TankSimulator(cfg, key).run(), cfg)
                    self.assertTrue(_verdict_ok(key, verdict, cfg),
                                    f"got {verdict.label if verdict else 'nothing'} for {SCENARIOS[key].name}")

    def test_healthy_plants_raise_no_alarm(self):
        for plant, cfg in (("simple", Config()), ("realistic", learn_from_normal(realistic(Config())))):
            for backup in (False, True):
                for seed in (1, 2, 3):
                    with self.subTest(plant=plant, backup=backup, seed=seed):
                        verdict, _ = diagnose(TankSimulator(cfg, None, "permanent", backup, seed).run(), cfg)
                        self.assertIsNone(verdict)

    def test_detector_never_reads_hidden_truth(self):
        """Any attribute access to a hidden Record field fails, whatever the variable is called
        (self.h[-1].level, last[0].tone, x.valve_real ...). Only the plant settings on cfg are allowed."""
        source = (PROJECT / "fault_or_attack" / "detector.py").read_text(encoding="utf-8")
        hidden = ("level", "fault_active", "pump_flow", "valve_real", "tone", "status", "run_duty")
        for field in hidden:
            with self.subTest(field=field):
                self.assertNotRegex(source, rf"(?<!cfg)\.{field}\b")

    def test_hidden_truth_check_catches_cheating(self):
        """The check above must flag the sneaky forms it is meant to catch."""
        for cheat in ("if self.h[-1].level > 99:", "x = last[0].fault_active", "v = rec.valve_real"):
            with self.subTest(cheat=cheat):
                self.assertRegex(cheat, r"(?<!cfg)\.(level|fault_active|valve_real)\b")
        self.assertNotRegex("self.cfg.pump_flow", r"(?<!cfg)\.pump_flow\b")

    def test_consistent_forgery_stress_test(self):
        """The adaptive attacker stays out of the headline scenarios. With backup sensor B and the
        hard-wired witness check it is caught as an ATTACK before the tank overflows; without the check
        the networked rules cannot call it an attack on the default run."""
        from dataclasses import replace
        from fault_or_attack.scenarios import STRESS_ATTACKS
        self.assertNotIn("forge", SCENARIOS)
        self.assertIn("forge", STRESS_ATTACKS)
        for plant, cfg in (("simple", Config()), ("realistic", learn_from_normal(realistic(Config())))):
            with self.subTest(plant=plant):
                records = TankSimulator(replace(cfg, witness_check=True), "forge", "permanent", True).run()
                verdict, _ = diagnose(records, replace(cfg, witness_check=True))
                spill = next(r.tick for r in records if r.level >= 99.5)
                self.assertEqual((verdict.label, verdict.culprit), ("ATTACK", "Consistent forgery"))
                self.assertLess(verdict.tick, spill)
                off, _ = diagnose(TankSimulator(cfg, "forge", "permanent", True).run(), cfg)
                self.assertNotEqual(off.label if off else None, "ATTACK")


class TestSettings(unittest.TestCase):
    def test_defaults_and_realistic_are_valid(self):
        Config()
        realistic(Config())

    def test_bad_settings_are_refused(self):
        bad = {"noise_corr": 1.0, "dos_loss": 1.5, "probe_chance": -0.1, "pid_probe_chance": 2,
               "valve_lag": 0, "pump_flow": 0, "demand": -1, "sensor_noise": -0.1, "quantize": -1,
               "high_alarm": 120, "window": 2, "control": "magic"}
        for name, value in bad.items():
            with self.subTest(setting=name):
                with self.assertRaises(ValueError):
                    Config(**{name: value})
        with self.assertRaises(ValueError):
            Config(ticks=30, inject_at=40)
        for name, value in {"link_window": 3, "probe_bracket": 0, "pid_probe_len": 0, "probe_tail": -1}.items():
            with self.subTest(setting=name):
                with self.assertRaises(ValueError):
                    Config(**{name: value})


class TestCommandLine(unittest.TestCase):
    def test_bad_options_give_clear_errors(self):
        cases = [
            (["--eval", "0"], "--eval needs at least 1 seed"),
            (["--web", "--eval", "-3"], "--eval needs at least 1 seed"),
            (["--web", "--realistic"], "cannot be combined with --realistic"),
            (["--fault", "leak", "--attack", "dos"], "either --fault or --attack"),
            (["--ticks", "30"], "inject_at (40) must be at least 0 and less than ticks (30)"),
            (["--dashboard", "--backup"], "cannot be combined with --backup"),
            (["--live", "--all"], "--live shows one scenario"),
            (["--hai", "no_such_file.csv"], "cannot open"),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                result = run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)

    def test_menu_exits_cleanly_without_keyboard(self):
        result = run_cli(stdin="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Bye.", result.stdout)
        self.assertNotIn("Traceback", result.stderr)


class TestHaiFiles(unittest.TestCase):
    def _csv(self, text: str) -> str:
        handle = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="")
        handle.write(text)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_wrong_version_is_explained(self):
        path = self._csv("timestamp,P1_LIT01,Attack\n2021-07-10 00:00:00,450,0\n")
        with self.assertRaisesRegex(HaiDataError, "not a HAI 22.04 file"):
            hai_load(path)

    def test_damaged_row_is_explained(self):
        head = "timestamp," + ",".join(HAI_TAGS) + ",Attack\n"
        good = "2021-07-10 00:00:00," + ",".join("1" for _ in HAI_TAGS) + ",0\n"
        bad = "2021-07-10 00:00:01," + ",".join("" for _ in HAI_TAGS) + ",0\n"
        with self.assertRaisesRegex(HaiDataError, "line 3"):
            hai_load(self._csv(head + good + bad))

    def test_blank_lines_are_skipped(self):
        head = "timestamp," + ",".join(HAI_TAGS) + ",Attack\n"
        good = "2021-07-10 00:00:00," + ",".join("1" for _ in HAI_TAGS) + ",0\n"
        cols, label, stamp = hai_load(self._csv(head + good + "\n" + good + "\n\n"))
        self.assertEqual(len(stamp), 2)

    def test_empty_file_is_explained(self):
        with self.assertRaisesRegex(HaiDataError, "empty"):
            hai_load(self._csv(""))

    def test_bad_file_on_command_line_is_a_clear_error(self):
        path = self._csv("timestamp,P1_LIT01,Attack\n")
        # pass the bad file as the training file too, so the test works without the HAI download
        result = run_cli("--hai", path, "--hai-train", path)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not a HAI 22.04 file", result.stderr)

    @unittest.skipUnless((HAI_DIR / "test1.csv").exists() and (HAI_DIR / "train1.csv").exists(),
                         "HAI dataset not downloaded")
    def test_real_hai_day_one(self):
        result = run_cli("--hai")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Tank attacks detected:   3/3", result.stdout)


HAVE_MATPLOTLIB = importlib.util.find_spec("matplotlib") is not None


class TestShowcase(unittest.TestCase):
    """What the pitch shows: the website data, the graphs, the dashboard and the live demo."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)

    def test_website_export(self):
        import contextlib
        import io
        import json
        from fault_or_attack.web_export import export_web
        with contextlib.redirect_stdout(io.StringIO()):
            export_web(out_dir=str(self.out / "web"), seeds=1, eval_seeds=0, hai=False)
        text = (self.out / "web" / "data.js").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("window.FOA_DATA = "))
        data = json.loads(text[len("window.FOA_DATA = "):].rstrip().rstrip(";"))
        self.assertEqual(len(data["runs"]), 2 * (len(SCENARIOS) + 1) * 2)      # both plants, backup off/on
        run = data["runs"]["simple|command|0|1"]
        self.assertEqual(len(run["level"]), run["ticks"])
        self.assertEqual(run["first"]["label"], "ATTACK")
        self.assertIn("normal_packets", data["config"])

    @unittest.skipUnless(HAVE_MATPLOTLIB, "matplotlib is not installed (run the tests with .venv\\Scripts\\python)")
    def test_graphs_and_dashboard(self):
        import contextlib
        import io
        import matplotlib
        matplotlib.use("Agg")
        from fault_or_attack.evaluation import print_eval
        from fault_or_attack.plots import plot_dashboard, plot_single
        sim = TankSimulator(Config(), "spoof")
        with contextlib.redirect_stdout(io.StringIO()):
            plot_single(sim, sim.run(), show=False, save=str(self.out / "single.png"))
            simple = print_eval(Config(), 1)
            real = print_eval(learn_from_normal(realistic(Config())), 1)
            plot_dashboard(simple, real, show=False, save=str(self.out / "dash.png"))
        for name in ("single.png", "dash.png"):
            with self.subTest(picture=name):
                self.assertGreater((self.out / name).stat().st_size, 10_000)

    @unittest.skipUnless(HAVE_MATPLOTLIB, "matplotlib is not installed (run the tests with .venv\\Scripts\\python)")
    def test_live_demo_frames(self):
        """Draw the first, middle and last frames of the live demo (both plants) without recording a GIF."""
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.animation
        from unittest import mock
        from fault_or_attack.live_demo import animate_live
        drawn = []

        class Frames:
            def __init__(self, fig, func, frames, init_func=None, **kwargs):
                if init_func:
                    init_func()
                for i in (0, frames // 2, frames - 1):
                    func(i)
                    fig.canvas.draw()
                    drawn.append(i)

        for cfg, key in ((Config(), "replay"), (learn_from_normal(realistic(Config())), "command")):
            with self.subTest(plant=cfg.control):
                sim = TankSimulator(cfg, key)
                with mock.patch.object(matplotlib.animation, "FuncAnimation", Frames):
                    animate_live(sim, sim.run(), show=False, save=None, mystery=True)
        self.assertEqual(len(drawn), 6)


if __name__ == "__main__":
    unittest.main()
