"""
fault_sim.py - Tank level control loop with injectable industrial faults.

The plant is a tank that is filled by a pump and drained by downstream demand.
A simple controller reads a level sensor and switches the pump:
    sensor below 40%  -> pump ON
    sensor above 60%  -> pump OFF
Healthy behaviour: the level wobbles around 50% and the pump runs about 50% of the time.

Usage examples
--------------
    python fault_sim.py --all                     # compare every fault, with and without a backup sensor
    python fault_sim.py --all --save grid.png     # same, plus a picture
    python fault_sim.py --fault leak              # run one fault and print a summary
    python fault_sim.py --fault drift --backup    # drift, but with a second (healthy) level sensor
    python fault_sim.py --fault pump --plot       # show a window with graphs (needs matplotlib)
    python fault_sim.py --fault power --mode transient --save power.png

Only the standard library is needed for the simulation itself.
matplotlib is needed only for --plot and --save.
"""

from __future__ import annotations

import argparse
import random
from collections import deque
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# 1. Settings: every "magic number" lives here so you can experiment with it
# ---------------------------------------------------------------------------
@dataclass
class Config:
    ticks: int = 160              # how many time steps (1 tick = 1 second of plant time)
    inject_at: int = 40           # the fault starts at this tick (before that, the plant is healthy)
    start_level: float = 50.0     # starting tank level, in percent

    pump_flow: float = 4.0        # level added per tick while the pump really runs
    demand: float = 2.0           # level drained per tick by normal downstream demand
    pump_on_below: float = 40.0   # controller switches the pump ON below this reading
    pump_off_above: float = 60.0  # controller switches the pump OFF above this reading

    sensor_noise: float = 0.3     # sensor readings wobble by +/- this much
    drift_rate: float = 0.8       # sensor drift grows by this much per tick ...
    drift_max: float = 50.0       # ... up to this limit
    valve_stuck_flow: float = 5.0 # outflow when the outlet valve is stuck open (bigger than pump_flow)
    leak_flow: float = 1.5        # extra outflow caused by a leak

    mismatch_tolerance: float = 8.0   # backup sensor: flag a fault if the two sensors differ by more
    duty_window: int = 30             # pump duty is averaged over this many ticks
    transient_length: int = 30        # a "transient" fault clears after this many ticks
    intermittent_period: int = 6      # an "intermittent" fault flips on/off every this many ticks

    high_alarm: float = 85.0
    low_alarm: float = 15.0


# ---------------------------------------------------------------------------
# 2. Fault catalogue: what each fault is, in words
# ---------------------------------------------------------------------------
@dataclass
class FaultInfo:
    name: str
    category: str
    what_happens: str
    how_caught: str


FAULTS: dict[str, FaultInfo] = {
    "drift": FaultInfo(
        "Sensor drift", "Sensor fault",
        "The level sensor slowly reads lower than the real level, so the controller keeps filling.",
        "Compare against a second sensor or an independent high-level switch.",
    ),
    "stuck": FaultInfo(
        "Sensor stuck", "Sensor fault",
        "The sensor freezes on its last value, so the pump stays in whatever state it was in.",
        "Flat-line checks, or a backup sensor.",
    ),
    "pump": FaultInfo(
        "Pump failure", "Equipment fault",
        "The pump is commanded ON but delivers nothing, so the level drains.",
        "Compare the pump command with flow or motor current.",
    ),
    "valve": FaultInfo(
        "Valve stuck open", "Actuator fault",
        "The outlet valve sticks open and drains faster than the pump can refill.",
        "Compare valve command with position feedback or downstream flow.",
    ),
    "leak": FaultInfo(
        "Leak", "Process fault",
        "Extra outflow. The controller compensates, so the level looks fine and the fault hides.",
        "Watch pump duty and do a mass balance (more pumping for the same demand).",
    ),
    "power": FaultInfo(
        "Power loss", "Utility fault",
        "Pump and sensor go dark and the tank drains downstream with nothing in control.",
        "Power monitoring, backup supply, and fail-safe default positions.",
    ),
}

MODES = ("permanent", "transient", "intermittent")


# ---------------------------------------------------------------------------
# 3. One row of results per tick
# ---------------------------------------------------------------------------
@dataclass
class Record:
    tick: int
    level: float            # the REAL level in the tank
    sensor: float | None    # what sensor A reports (None = no signal)
    pump_cmd: bool          # what the controller asked for
    pump_flow: bool         # whether the pump really delivered water
    duty: float             # pump duty over the last N ticks, 0..1
    fault_active: bool
    tone: str               # "ok", "warn" or "danger"
    status: str


def classify(level: float, power_ok: bool, mismatch: bool, cfg: Config) -> tuple[str, str]:
    """Turn the plant state into a status that an operator would see."""
    if not power_ok:
        return "danger", "No power"
    if level >= 100:
        return "danger", "Overflow"
    if level <= 0:
        return "danger", "Tank dry"
    if mismatch:
        return "warn", "Sensor mismatch, backup in use"
    if level > cfg.high_alarm:
        return "warn", "High-level alarm"
    if level < cfg.low_alarm:
        return "warn", "Low-level alarm"
    return "ok", "Within limits"


# ---------------------------------------------------------------------------
# 4. The simulator
# ---------------------------------------------------------------------------
class TankSimulator:
    def __init__(self, cfg: Config | None = None, fault: str | None = None,
                 mode: str = "permanent", backup_sensor: bool = False, seed: int = 1):
        if fault is not None and fault not in FAULTS:
            raise ValueError(f"Unknown fault {fault!r}. Choose from {list(FAULTS)}")
        if mode not in MODES:
            raise ValueError(f"Unknown mode {mode!r}. Choose from {list(MODES)}")
        self.cfg = cfg or Config()
        self.fault = fault
        self.mode = mode
        self.backup_sensor = backup_sensor
        self.rng = random.Random(seed)          # same seed -> same run every time

        self.tick = 0
        self.level = self.cfg.start_level
        self.pump_cmd = False
        self.drift = 0.0
        self.frozen: float | None = None
        self.duty_window: deque[int] = deque(maxlen=self.cfg.duty_window)

    def _noise(self) -> float:
        return (self.rng.random() - 0.5) * 2 * self.cfg.sensor_noise

    @staticmethod
    def _clamp(value: float) -> float:
        """A level sensor can only report 0 to 100 percent."""
        return max(0.0, min(100.0, value))

    def fault_active(self) -> bool:
        """Is the fault switched on at the current tick? Depends on the duration mode."""
        if self.fault is None or self.tick < self.cfg.inject_at:
            return False
        since = self.tick - self.cfg.inject_at
        if self.mode == "permanent":
            return True
        if self.mode == "transient":
            return since < self.cfg.transient_length
        return (since // self.cfg.intermittent_period) % 2 == 0   # intermittent

    def step(self) -> Record:
        cfg = self.cfg
        active = self.fault_active()
        power_ok = not (active and self.fault == "power")

        # --- sensor A (the one the controller normally trusts) ---
        if self.fault == "drift" and active:
            self.drift = min(cfg.drift_max, self.drift + cfg.drift_rate)
        else:
            self.drift = 0.0
        reading_a = self._clamp(self.level - self.drift + self._noise())

        if self.fault == "stuck" and active:
            if self.frozen is None:
                self.frozen = reading_a        # remember the value at the moment it froze
            reading_a = self.frozen
        else:
            self.frozen = None

        # --- optional backup sensor B (never faulty in this model) ---
        reading_b = self._clamp(self.level + self._noise())
        mismatch = False
        trusted = reading_a
        if power_ok and self.backup_sensor and abs(reading_a - reading_b) > cfg.mismatch_tolerance:
            mismatch = True
            trusted = reading_b

        # --- controller: on/off with a gap (hysteresis) so the pump does not chatter ---
        if power_ok:
            if trusted < cfg.pump_on_below:
                self.pump_cmd = True
            elif trusted > cfg.pump_off_above:
                self.pump_cmd = False
        else:
            self.pump_cmd = False

        # --- the physical plant ---
        pump_really_runs = self.pump_cmd and not (active and self.fault == "pump")
        outflow = cfg.demand
        if active and self.fault == "valve":
            outflow = cfg.valve_stuck_flow
        if active and self.fault == "leak":
            outflow += cfg.leak_flow
        inflow = cfg.pump_flow if pump_really_runs else 0.0
        self.level = max(0.0, min(100.0, self.level + inflow - outflow))

        # --- bookkeeping ---
        self.duty_window.append(1 if self.pump_cmd else 0)
        duty = sum(self.duty_window) / len(self.duty_window)
        tone, status = classify(self.level, power_ok, mismatch, cfg)
        rec = Record(self.tick, self.level, reading_a if power_ok else None,
                     self.pump_cmd, pump_really_runs, duty, active, tone, status)
        self.tick += 1
        return rec

    def run(self) -> list[Record]:
        return [self.step() for _ in range(self.cfg.ticks)]


# ---------------------------------------------------------------------------
# 5. Summary: turn a run into a few numbers
# ---------------------------------------------------------------------------
SEVERITY = {"ok": 0, "warn": 1, "danger": 2}


@dataclass
class Summary:
    min_level: float
    max_level: float
    final_level: float
    detected_after: int | None   # ticks between injection and the first non-OK status (None = never noticed)
    worst_status: str
    mean_duty: float             # mean pump duty after the fault starts


def summarize(records: list[Record], cfg: Config) -> Summary:
    after = [r for r in records if r.tick >= cfg.inject_at]
    detected = next((r.tick - cfg.inject_at for r in after if r.tone != "ok"), None)
    worst = max(after, key=lambda r: SEVERITY[r.tone])
    return Summary(
        min_level=min(r.level for r in after),
        max_level=max(r.level for r in after),
        final_level=records[-1].level,
        detected_after=detected,
        worst_status=worst.status if worst.tone != "ok" else "Within limits",
        mean_duty=sum(r.duty for r in after) / len(after),
    )


def print_single(sim: TankSimulator, records: list[Record]) -> None:
    s = summarize(records, sim.cfg)
    info = FAULTS.get(sim.fault) if sim.fault else None
    print()
    print(f"Fault: {info.name if info else 'none (healthy)'}   |   duration: {sim.mode}   |   "
          f"backup sensor: {'on' if sim.backup_sensor else 'off'}")
    if info:
        print(f"Type:           {info.category}")
        print(f"What happens:   {info.what_happens}")
        print(f"How it is caught: {info.how_caught}")
    print()
    print(f"Level from second {sim.cfg.inject_at}:     min {s.min_level:.0f}%   max {s.max_level:.0f}%   final {s.final_level:.0f}%")
    print(f"Mean pump duty:            {s.mean_duty * 100:.0f}%  (healthy is about 50%)")
    det = "never raised an alarm" if s.detected_after is None else f"{s.detected_after} s after the fault started"
    print(f"Detected:                  {det}")
    print(f"Worst status:              {s.worst_status}")
    print()


def print_table(cfg: Config, mode: str, seed: int) -> None:
    header = f"{'Fault':<18}{'Backup':<8}{'Min':>5}{'Max':>6}{'Final':>7}{'Duty':>7}  {'Detected':<12}Worst status"
    print()
    print(f"All faults, duration = {mode}, fault starts at tick {cfg.inject_at}")
    print(header)
    print("-" * len(header))
    for key, info in FAULTS.items():
        for backup in (False, True):
            sim = TankSimulator(cfg, key, mode, backup, seed)
            s = summarize(sim.run(), cfg)
            det = "never" if s.detected_after is None else f"{s.detected_after} s"
            print(f"{info.name:<18}{'on' if backup else 'off':<8}{s.min_level:>4.0f}%{s.max_level:>5.0f}%"
                  f"{s.final_level:>6.0f}%{s.mean_duty * 100:>6.0f}%  {det:<12}{s.worst_status}")
        print()


# ---------------------------------------------------------------------------
# 6. Plotting (matplotlib is imported only when you ask for a plot)
# ---------------------------------------------------------------------------
def _load_matplotlib(show: bool):
    try:
        import matplotlib
        if not show:
            matplotlib.use("Agg")          # draw to a file, no window needed
        import matplotlib.pyplot as plt
        return plt
    except ImportError:
        raise SystemExit("matplotlib is not installed. Run:  pip install matplotlib")


def _shade_fault(ax, records: list[Record]) -> None:
    """Shade the periods when the fault is switched on."""
    start = None
    for r in records:
        if r.fault_active and start is None:
            start = r.tick
        if not r.fault_active and start is not None:
            ax.axvspan(start, r.tick, color="tab:red", alpha=0.10)
            start = None
    if start is not None:
        ax.axvspan(start, records[-1].tick, color="tab:red", alpha=0.10)


def plot_single(sim: TankSimulator, records: list[Record], show: bool, save: str | None) -> None:
    plt = _load_matplotlib(show)
    cfg = sim.cfg
    t = [r.tick for r in records]
    info = FAULTS.get(sim.fault)
    title = f"{info.name if info else 'Healthy'} ({sim.mode}, backup sensor {'on' if sim.backup_sensor else 'off'})"

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 6), sharex=True, gridspec_kw={"height_ratios": [3, 1.5]})
    ax1.plot(t, [r.level for r in records], label="Real level", color="tab:blue", linewidth=2)
    ax1.plot(t, [r.sensor if r.sensor is not None else float("nan") for r in records],
             label="Sensor A reading", color="black", linestyle="--", linewidth=1.2)
    ax1.axhline(cfg.high_alarm, color="gray", linestyle=":", linewidth=1)
    ax1.axhline(cfg.low_alarm, color="gray", linestyle=":", linewidth=1)
    _shade_fault(ax1, records)
    ax1.set_ylim(-3, 103)
    ax1.set_ylabel("Level (%)")
    ax1.set_title(title)
    ax1.legend(loc="upper right")

    ax2.plot(t, [r.duty * 100 for r in records], color="tab:orange", linewidth=2)
    ax2.axhline(50, color="gray", linestyle=":", linewidth=1)
    _shade_fault(ax2, records)
    ax2.set_ylim(-3, 103)
    ax2.set_ylabel("Pump duty (%)")
    ax2.set_xlabel("Time (s)")
    fig.tight_layout()

    if save:
        fig.savefig(save, dpi=150)
        print(f"Saved plot to {save}")
    if show:
        plt.show()


def plot_all(cfg: Config, mode: str, seed: int, show: bool, save: str | None) -> None:
    plt = _load_matplotlib(show)
    fig, axes = plt.subplots(3, 2, figsize=(10, 9), sharex=True, sharey=True)
    for ax, (key, info) in zip(axes.flat, FAULTS.items()):
        for backup, style, label in ((False, "-", "no backup"), (True, ":", "backup sensor")):
            recs = TankSimulator(cfg, key, mode, backup, seed).run()
            ax.plot([r.tick for r in recs], [r.level for r in recs], style,
                    linewidth=2, label=label, color="tab:blue" if not backup else "tab:green")
        _shade_fault(ax, recs)
        ax.axhline(cfg.high_alarm, color="gray", linestyle=":", linewidth=1)
        ax.axhline(cfg.low_alarm, color="gray", linestyle=":", linewidth=1)
        ax.set_title(info.name)
        ax.set_ylim(-3, 103)
    axes[0][0].legend(loc="lower left", fontsize=8)
    fig.supxlabel("Time (s)")
    fig.supylabel("Real tank level (%)")
    fig.suptitle(f"Real tank level under each fault (duration = {mode}; red = fault active)")
    fig.tight_layout()
    if save:
        fig.savefig(save, dpi=150)
        print(f"Saved plot to {save}")
    if show:
        plt.show()


# ---------------------------------------------------------------------------
# 7. Command line
# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(description="Tank level control loop with injectable faults.")
    p.add_argument("--fault", choices=list(FAULTS), help="fault to inject (leave out for a healthy run)")
    p.add_argument("--mode", choices=MODES, default="permanent", help="how long the fault lasts")
    p.add_argument("--backup", action="store_true", help="add a second, healthy level sensor")
    p.add_argument("--all", action="store_true", help="run every fault, with and without the backup sensor")
    p.add_argument("--ticks", type=int, default=160, help="length of the run in seconds")
    p.add_argument("--inject-at", type=int, default=40, help="second at which the fault starts")
    p.add_argument("--seed", type=int, default=1, help="random seed for sensor noise")
    p.add_argument("--plot", action="store_true", help="show graphs in a window")
    p.add_argument("--save", metavar="FILE.png", help="save graphs to an image file")
    args = p.parse_args()

    cfg = Config(ticks=args.ticks, inject_at=args.inject_at)
    want_plot = args.plot or args.save

    if args.all:
        print_table(cfg, args.mode, args.seed)
        if want_plot:
            plot_all(cfg, args.mode, args.seed, args.plot, args.save)
        return

    sim = TankSimulator(cfg, args.fault, args.mode, args.backup, args.seed)
    records = sim.run()
    print_single(sim, records)
    if want_plot:
        plot_single(sim, records, args.plot, args.save)


if __name__ == "__main__":
    main()