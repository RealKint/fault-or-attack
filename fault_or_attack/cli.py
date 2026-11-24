"""Command-line options and the interactive menu shown when you just press Run."""

from __future__ import annotations

import argparse
import random

from pathlib import Path

from .config import PROJECT_DIR, Config, realistic
from .evaluation import (print_eval, print_healthy, print_it, print_mixed, print_physical, print_single, print_stress,
                         print_sweep, print_table)
from .hai_validation import HaiDataError, hai_main
from .learning import learn_from_normal
from .live_demo import animate_live
from .plant import TankSimulator
from .plots import plot_all, plot_dashboard, plot_single
from .scenarios import ATTACKS, FAULTS, MODES, REPLAYS, SCENARIOS
from .web_export import export_web


def _project_path(path: str) -> str:
    """A relative path that does not exist where you started the program is looked up in the project folder."""
    p = Path(path)
    return path if p.is_absolute() or p.exists() else str(PROJECT_DIR / p)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Tank level control loop with injectable faults and cyberattacks, "
                                            "plus a FAULT-or-ATTACK detector.")
    p.add_argument("--fault", choices=list(FAULTS), help="fault to inject")
    p.add_argument("--attack", choices=list(ATTACKS), help="cyberattack to launch")
    p.add_argument("--mode", choices=MODES, default="permanent", help="how long the fault or attack lasts")
    p.add_argument("--backup", action="store_true", help="add a second, healthy, hard-wired level sensor")
    p.add_argument("--all", action="store_true", help="run every fault and attack, with and without the backup sensor")
    p.add_argument("--eval", type=int, metavar="SEEDS", help="score the detector over this many random seeds")
    p.add_argument("--stress", action="store_true",
                   help="stress test against an adaptive attacker who forges every networked signal consistently, "
                        "with the hard-wired witness check off and on (scored apart from the headline accuracy; "
                        "--eval SEEDS sets the seeds, default 20; --realistic for the PID plant)")
    p.add_argument("--physical", action="store_true",
                   help="score the physical side: corrosion, water ingress, theft, valve forced by hand, safety bypass, "
                        "insider tampering, drone strike, planned work (--eval SEEDS sets the seeds, default 10; "
                        "--realistic for the PID plant)")
    p.add_argument("--sweep", action="store_true",
                   help="physical side: detection curve for corrosion leaks, theft and water ingress at a range of "
                        "sizes and start times (--eval SEEDS, default 10)")
    p.add_argument("--mixed", action="store_true",
                   help="physical side: two events at once, such as an attack with a theft or a drone during planned "
                        "work (--eval SEEDS, default 10)")
    p.add_argument("--it", action="store_true",
                   help="office IT incidents (the Colonial Pipeline question): IT hit with the plant fine, an IT hit "
                        "that spreads to the control network, and a fault during an IT incident (--eval SEEDS, default 10)")
    p.add_argument("--healthy", type=int, metavar="HOURS",
                   help="count false alarms over this many healthy hours with rain, gas-detector tests, planned visits "
                        "and the daily temperature swing")
    p.add_argument("--dashboard", action="store_true",
                   help="score both plants and draw a one-page accuracy dashboard "
                        "(saved to accuracy_dashboard.png; --save to choose, --plot to open a window)")
    p.add_argument("--ticks", type=int, default=160, help="length of the run in seconds")
    p.add_argument("--inject-at", type=int, default=40, help="second at which the fault or attack starts")
    p.add_argument("--seed", type=int, default=1, help="random seed for sensor noise")
    p.add_argument("--plot", action="store_true", help="show graphs in a window")
    p.add_argument("--save", metavar="FILE", help="save graphs to an image file (.png), or with --live an animation (.gif)")
    p.add_argument("--live", action="store_true", help="animated demo: watch the tank and the detector second by second")
    p.add_argument("--mystery", action="store_true",
                   help="live demo with the scenario hidden until the detector decides "
                        "(picks a random fault or attack if you do not name one)")
    p.add_argument("--speed", type=float, default=8.0, help="live demo speed in plant seconds per real second")
    p.add_argument("--realistic", action="store_true",
                   help="plant closer to the real HAI testbed: PID valve with lag, rounded readings, correlated noise")
    p.add_argument("--hai", nargs="?", const="data/hai/test1.csv", metavar="TEST.csv",
                   help="validate on REAL data from the public HAI 22.04 dataset (default: data/hai/test1.csv)")
    p.add_argument("--hai-train", default="data/hai/train1.csv", metavar="TRAIN.csv",
                   help="HAI normal-only file used to learn thresholds (default: data/hai/train1.csv)")
    p.add_argument("--web", action="store_true",
                   help="record every demonstration for the website (writes web/data.js; open web/index.html). "
                        "Use --eval SEEDS to change how many seeds the results section scores (default 20)")
    args = p.parse_args(argv)
    if args.eval is not None and args.eval < 1:
        p.error("--eval needs at least 1 seed")
    if args.web:
        clashing = [flag for flag, used in (
            ("--fault", args.fault), ("--attack", args.attack), ("--all", args.all), ("--live", args.live),
            ("--mystery", args.mystery), ("--dashboard", args.dashboard), ("--realistic", args.realistic),
            ("--backup", args.backup), ("--mode", args.mode != "permanent"), ("--seed", args.seed != 1),
            ("--ticks", args.ticks != 160), ("--inject-at", args.inject_at != 40), ("--save", args.save),
            ("--plot", args.plot), ("--hai", args.hai)) if used]
        if clashing:
            p.error(f"--web always records every scenario on both plants with the standard settings, so it "
                    f"cannot be combined with {', '.join(clashing)}. Only --eval SEEDS can be added.")
        export_web(seeds=3, eval_seeds=args.eval or 20)
        return
    if args.hai:
        args.hai, args.hai_train = _project_path(args.hai), _project_path(args.hai_train)
        for path in (args.hai_train, args.hai):
            try:
                open(path).close()
            except OSError:
                p.error(f"cannot open {path}. Download HAI 22.04 from https://github.com/icsdataset/hai "
                        "into data/hai/ (train1.csv, test1.csv, test2.csv).")
        try:
            hai_main(args.hai_train, args.hai)
        except HaiDataError as problem:
            p.error(str(problem))
        return
    if args.fault and args.attack:
        p.error("choose either --fault or --attack, not both")
    if args.mystery:
        args.live = True
        if not (args.fault or args.attack):
            args.attack = random.choice(list(SCENARIOS))   # a surprise; FAULTS keys work here too
    if args.live:
        if args.all or args.eval is not None:
            p.error("--live shows one scenario: use it with --fault or --attack, not --all or --eval")
        if args.speed <= 0:
            p.error("--speed must be more than 0")
        if args.save and not args.save.lower().endswith(".gif"):
            p.error("with --live, --save records an animation: give it a .gif file name")

    try:
        cfg = Config(ticks=args.ticks, inject_at=args.inject_at)
    except ValueError as e:
        p.error(str(e))
    if args.dashboard:
        ignored = [flag for flag, used in (("--live", args.live), ("--all", args.all), ("--fault", args.fault),
                                           ("--attack", args.attack), ("--realistic", args.realistic),
                                           ("--backup", args.backup), ("--mode", args.mode != "permanent"),
                                           ("--seed", args.seed != 1)) if used]
        if ignored:
            p.error(f"--dashboard always scores every scenario on BOTH plants, every duration mode and backup "
                    f"on/off, so it cannot be combined with {', '.join(ignored)}. Use --eval SEEDS to change the "
                    "number of seeds, --save or --plot for the output.")
        if args.save and not args.save.lower().endswith((".png", ".pdf", ".svg")):
            p.error("with --dashboard, --save needs a .png, .pdf or .svg file name")
        seeds = args.eval or 20
        real_cfg = learn_from_normal(realistic(cfg))
        if cfg.inject_at < max(cfg.replay_match, real_cfg.replay_match):
            p.error(f"the replay attack needs at least {real_cfg.replay_match} healthy seconds to record")
        print(f"Scoring both plants over {seeds} seeds. This takes a few minutes...")
        simple_res = print_eval(cfg, seeds)
        real_res = print_eval(real_cfg, seeds)
        save = args.save or (None if args.plot else str(PROJECT_DIR / "accuracy_dashboard.png"))
        plot_dashboard(simple_res, real_res, show=args.plot, save=save)
        return
    if args.realistic:
        # Thresholds for natural repeats are learned from healthy runs only (never the test seeds).
        cfg = learn_from_normal(realistic(cfg))
        print(f"Realistic plant: learned from 3 healthy hours -> stuck sensor after {cfg.flatline_ticks} "
              f"identical readings, replay after {cfg.replay_match} repeated readings.")
    runs_replay = args.attack in REPLAYS or args.all or args.eval is not None
    if runs_replay and cfg.inject_at < cfg.replay_match:
        p.error(f"the replay attack needs at least {cfg.replay_match} healthy seconds to record: "
                f"use --inject-at {cfg.replay_match} or more")
    want_plot = args.plot or args.save

    if args.stress:
        print_stress(cfg, args.eval or 20)
        return

    if args.physical:
        print_physical(cfg, args.eval or 10)
        return

    if args.sweep:
        print_sweep(cfg, args.eval or 10)
        return

    if args.mixed:
        print_mixed(cfg, args.eval or 10)
        return

    if args.it:
        print_it(cfg, args.eval or 10)
        return

    if args.healthy is not None:
        print_healthy(cfg, args.healthy)
        return

    if args.eval is not None:
        print_eval(cfg, args.eval)
        return

    if args.all:
        print_table(cfg, args.mode, args.seed)
        if want_plot:
            plot_all(cfg, args.mode, args.seed, args.plot, args.save)
        return

    sim = TankSimulator(cfg, args.fault or args.attack, args.mode, args.backup, args.seed)
    records = sim.run()
    if args.live:
        if not args.mystery:
            print_single(sim, records)
        animate_live(sim, records, show=not args.save, save=args.save, speed=args.speed, mystery=args.mystery)
        return
    print_single(sim, records)
    if want_plot:
        plot_single(sim, records, args.plot, args.save)


def _ask(prompt: str, choices: list[str]) -> int | None:
    """Show numbered choices and return the index picked, or None to go back."""
    for i, text in enumerate(choices, start=1):
        print(f"   {i:>2}. {text}")
    while True:
        answer = input(f"{prompt} (number, or Enter to go back): ").strip()
        if not answer:
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return int(answer) - 1
        print(f"   Please type a number from 1 to {len(choices)}.")


def _pick_scenario() -> str | None:
    keys = list(SCENARIOS)
    labels = [f"{SCENARIOS[k].name}  ({SCENARIOS[k].kind.lower()})" for k in keys]
    print("\n Which fault or attack?")
    i = _ask(" Scenario", labels)
    return None if i is None else keys[i]


def _scenario_flag(key: str) -> list[str]:
    return ["--fault", key] if key in FAULTS else ["--attack", key]


def menu() -> None:
    """Interactive menu, so every feature is reachable from an IDE's Run button."""
    try:
        _menu_loop()
    except (EOFError, KeyboardInterrupt):
        print()                         # no keyboard input available, or Ctrl+C
        print("Bye.")


def _menu_loop() -> None:
    realistic_plant = False
    items = [
        "Live demo: watch one fault or attack and the detector decide (opens a window)",
        "Mystery demo: a random fault or attack, hidden until the detector decides",
        "Run one fault or attack and show its graphs",
        "Run every fault and attack: results table + overview picture (fault_or_attack_grid.png)",
        "Accuracy dashboard for both plants (takes a few minutes; saves accuracy_dashboard.png)",
        "Check against REAL plant data (HAI dataset, test day 1 and 2)",
        "Build the website (records every demonstration; takes a few minutes)",
        "Switch plant: simple on/off pump  <->  realistic PID valve",
    ]
    while True:
        plant = "realistic (PID valve, like the real HAI testbed)" if realistic_plant else "simple (on/off pump)"
        print("\n" + "=" * 70)
        print(" FAULT OR ATTACK?   Is the tank's problem a broken part or a cyberattack?")
        print(f" Plant: {plant}")
        print("=" * 70)
        choice = _ask(" Choose", items + ["Quit"])
        if choice is None or choice == len(items):
            print("Bye.")
            return
        plant_flag = ["--realistic"] if realistic_plant else []
        runs: list[list[str]] = []
        if choice == 0:
            key = _pick_scenario()
            if key:
                runs = [_scenario_flag(key) + ["--live"] + plant_flag]
        elif choice == 1:
            runs = [["--mystery"] + plant_flag]
        elif choice == 2:
            key = _pick_scenario()
            if key:
                runs = [_scenario_flag(key) + ["--plot"] + plant_flag]
        elif choice == 3:
            runs = [["--all", "--save", str(PROJECT_DIR / "fault_or_attack_grid.png")] + plant_flag]
        elif choice == 4:
            runs = [["--dashboard"]]
        elif choice == 5:
            runs = [["--hai"], ["--hai", "data/hai/test2.csv"]]
        elif choice == 6:
            runs = [["--web"]]
        elif choice == 7:
            realistic_plant = not realistic_plant
            continue
        for argv in runs:
            print(f"\n> python \"FAULT OR ATTACK.py\" {' '.join(argv)}")
            try:
                main(argv)
            except SystemExit as stop:          # argparse errors: show them, stay in the menu
                if stop.code not in (0, None):
                    print("(That option could not run; see the message above.)")
        input("\nPress Enter to return to the menu...")
