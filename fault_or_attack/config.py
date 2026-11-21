"""Settings: every number the simulator and detector use, and the realistic-plant preset."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

# The project folder (one level above this package). data/, web/, reports/ and saved pictures live
# there, so every path is the same no matter which folder the program is started from.
PROJECT_DIR = Path(__file__).resolve().parent.parent


@dataclass
class Config:
    ticks: int = 160              # how many time steps (1 tick = 1 second of plant time)
    inject_at: int = 40           # the fault/attack starts at this tick (before that, the plant is healthy)
    start_level: float = 50.0     # starting tank level, in percent

    pump_flow: float = 4.0        # level added per tick while the pump really runs
    demand: float = 2.0           # level drained per tick by normal downstream demand
    pump_on_below: float = 40.0   # controller switches the pump ON below this reading
    pump_off_above: float = 60.0  # controller switches the pump OFF above this reading

    sensor_noise: float = 0.3     # sensor readings wobble by +/- this much
    drift_rate: float = 0.8       # sensor drift grows by this much per tick ...
    drift_max: float = 50.0       # ... up to this limit
    valve_stuck_flow: float = 5.0 # outflow when the outlet valve is stuck open (bigger than pump_flow)
    leak_flow: float = 1.5        # extra outflow caused by a leak (it bypasses the outflow meter)

    mismatch_tolerance: float = 8.0   # backup sensor: flag a fault if the two sensors differ by more
    duty_window: int = 30             # pump duty is averaged over this many ticks
    transient_length: int = 30        # a "transient" fault clears after this many ticks
    intermittent_period: int = 6      # an "intermittent" fault flips on/off every this many ticks

    high_alarm: float = 85.0
    low_alarm: float = 15.0

    # --- attacker settings ---
    spoof_min: float = 38.0       # false data injection: fake readings stay between these values,
    spoof_max: float = 50.0       # just under the pump-ON threshold, so the pump never switches off
    replay_length: int = 30       # replay attack: how many healthy seconds the attacker records
    dos_loss: float = 0.8         # denial of service: share of sensor messages that get lost
    normal_packets: int = 10      # network packets per second on a healthy control network
    flood_packets: int = 400      # network packets per second during a flood
    stealth_rate: float = 0.8     # stealthy spoof: fake offset grows this much per tick, like real drift ...
    stealth_max: float = 50.0     # ... up to this limit

    # --- defender's active probe (physical watermarking, after Mo & Sinopoli 2009) ---
    probe: bool = True            # controller briefly pauses the pump at secret random moments
    probe_chance: float = 1 / 5   # chance per second of starting a probe while filling mid-band
    probe_len: int = 2            # seconds the pump is paused for each probe

    # --- realism (all off by default; --realistic switches them on, based on the HAI testbed) ---
    control: str = "onoff"        # "onoff" pump, or "pid": a PI controller drives a supply valve
    setpoint: float = 50.0        # PID mode: level the controller holds
    kp: float = 2.0               # PID mode: proportional gain (% valve per % level error)
    ki: float = 0.05              # PID mode: integral gain
    valve_lag: float = 0.1        # PID mode: valve moves this share of the way to its command each second
    quantize: float = 0.0         # sensor resolution in % (0 = perfect); HAI's real values are rounded
    noise_corr: float = 0.0       # 0 = fresh noise every second; 0.8 = slow wander, like HAI's level sensor
    pid_probe_len: int = 3        # PID mode: seconds the valve is closed for each probe ...
    pid_probe_chance: float = 1 / 30   # ... and how often a probe starts
    probe_tail: int = 8           # PID mode: extra seconds the probe's dip takes to show (valve lag)

    # --- detector settings ---
    window: int = 10              # most checks look at the last this-many seconds
    replay_match: int = 8         # this many readings repeated exactly = replay
    flatline_ticks: int = 5       # this many identical readings = stuck sensor
    fall_limit: float = 1.2       # a fall bigger than this per tick, while the pump fills, is impossible
    roughness_limit: float = 0.9  # mass-balance error jumping around more than this = forged data
    residual_limit: float = 0.5   # steady mass-balance error bigger than this = physical fault
    fault_fit: int = 8            # seconds of running mass-balance total checked for a straight line
    straight_limit: float = 0.4   # how far the running total may wander from a straight line
    cusum_k: float = 0.5          # CUSUM (Urbina et al. 2016): error allowed per second before it counts ...
    cusum_h: float = 5.0          # ... and how much counted error raises an early warning
    probe_limit: float = 2.5      # on/off: a probe whose mean mass-balance error is bigger than this was not echoed
    pid_probe_limit: float = 1.5  # PID: a probe whose summed, baseline-corrected error is bigger was not echoed
    tracking_limit: float = 3.0   # PID mode: valve position this far from where its command should put it
    active_probe: bool = True     # PID mode: before blaming equipment, ask for a probe to check the sensor is live
    probe_bracket: int = 6        # PID mode: seconds before and after a probe used as its baseline
    request_gap: int = 20         # PID mode: wait at least this long between probe requests
    live_timeout: int = 45        # PID mode: give the fault verdict anyway if probes stay inconclusive this long
    link_window: int = 40         # PID mode: seconds over which the level must move with the valve ...
    link_min_activity: float = 0.15   # ... once the valve has moved enough to tell (spread of expected flow) ...
    link_limit: float = -1.0      # ... correlation below this = sensor ignores the valve (-1 = off; learned) ...
    link_persist: int = 5         # ... for this many seconds in a row
    flat_short: int = 5           # a frozen stretch at least this long counts towards "freezing on and off" ...
    flat_runs_limit: int = 0      # ... and this many in a minute is a fault (0 = off; learned from normal data)
    law_limit: float = 0.5        # PID mode: valve command this far from what the control law gives
    fusion_window: int = 120      # a fault-like symptom this soon after a new network device = attack

    def __post_init__(self) -> None:
        """Refuse settings the simulator or detector cannot work with."""
        if not 0 <= self.inject_at < self.ticks:
            raise ValueError(f"inject_at ({self.inject_at}) must be at least 0 and less than ticks ({self.ticks})")
        for name in ("window", "fault_fit", "replay_match", "flatline_ticks"):
            if getattr(self, name) < 3:
                raise ValueError(f"{name} must be at least 3 (got {getattr(self, name)})")
        if self.control not in ("onoff", "pid"):
            raise ValueError(f"control must be 'onoff' or 'pid' (got {self.control!r})")
        # Window and timing settings the PID checks divide up or average over.
        minimums = {"link_window": 8,     # split into 4 quarters of at least 2 seconds each
                    "probe_bracket": 3,   # a probe needs at least 3 seconds of baseline either side
                    "probe_len": 1, "pid_probe_len": 1, "request_gap": 1, "live_timeout": 1, "link_persist": 1}
        for name, low in minimums.items():
            if getattr(self, name) < low:
                raise ValueError(f"{name} must be at least {low} (got {getattr(self, name)})")
        if self.probe_tail < 0 or self.fusion_window < 0:
            raise ValueError("probe_tail and fusion_window cannot be negative")
        # Shares and probabilities must lie between 0 and 1.
        for name in ("dos_loss", "probe_chance", "pid_probe_chance"):
            if not 0 <= getattr(self, name) <= 1:
                raise ValueError(f"{name} is a probability and must be between 0 and 1 (got {getattr(self, name)})")
        # 1 or more would make the noise formula take the square root of a negative number.
        if not 0 <= self.noise_corr < 1:
            raise ValueError(f"noise_corr must be at least 0 and less than 1 (got {self.noise_corr})")
        if not 0 < self.valve_lag <= 1:
            raise ValueError(f"valve_lag must be more than 0 and at most 1 (got {self.valve_lag})")
        if self.pump_flow <= 0:
            raise ValueError(f"pump_flow must be more than 0 (got {self.pump_flow})")
        for name in ("demand", "sensor_noise", "quantize", "leak_flow", "drift_rate", "kp", "ki"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative (got {getattr(self, name)})")
        if not 0 <= self.low_alarm < self.high_alarm <= 100:
            raise ValueError(f"alarms must satisfy 0 <= low_alarm < high_alarm <= 100 "
                             f"(got {self.low_alarm} and {self.high_alarm})")


def realistic(cfg: Config) -> Config:
    """The plant made more like the real HAI testbed: PI-controlled valve with lag,
    sensor readings rounded to 0.1 %, and slowly wandering (correlated) sensor noise."""
    return replace(cfg, control="pid", quantize=0.1, noise_corr=0.8)
