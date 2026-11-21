"""The simulated tank plant: one Record per second, the shared controller logic, and the simulator."""

from __future__ import annotations

import random
from collections import deque
from dataclasses import dataclass

from .config import Config
from .scenarios import MODES, NEW_DEVICE_ATTACKS, REPLAYS, SCENARIOS


class RunRecords(list):
    """A run's records, plus the verdicts its live (closed-loop) detector reached each second."""

    def __init__(self) -> None:
        super().__init__()
        self.verdicts: list = []
        self.cfg: Config | None = None


def choose_reading(received: float | None, backup: float | None, last_rx: float,
                   cfg: Config) -> tuple[float, bool, bool]:
    """Which level reading the controller trusts: returns (reading, mismatch, sensor_a_lost).

    Shared by the simulated controller and the detector's copy of it, so the two can never drift apart."""
    if backup is not None:
        if received is None:
            return backup, False, True
        if abs(received - backup) > cfg.mismatch_tolerance:
            return backup, True, False
        return received, False, False
    if received is None:
        return last_rx, False, True          # no backup: fly blind on the last good value
    return received, False, False


def pi_step(u: float, e_prev: float | None, trusted: float, cfg: Config) -> tuple[float, float]:
    """One step of the velocity-form PI level controller: returns (new valve output, error)."""
    e = cfg.setpoint - trusted
    if e_prev is None:
        e_prev = e
    return min(100.0, max(0.0, u + cfg.kp * (e - e_prev) + cfg.ki * e)), e


@dataclass
class Record:
    tick: int
    level: float                # the REAL level in the tank (the detector is not allowed to see this)
    sensor: float | None        # what sensor A reports to the control room (None = no message)
    sensor_b: float | None      # backup sensor B, hard-wired (None = not fitted or no power)
    pump_cmd: bool              # what the controller asked for
    pump_flow: bool             # whether the pump really delivered water (hidden from the detector)
    pump_feedback: bool         # what the motor feedback says the pump is doing
    outflow: float | None       # downstream outflow meter (a leak bypasses it)
    packets: int                # network packets seen this second
    unknown_writes: int         # write commands from a host that is not the controller
    new_devices: int            # devices seen on the control network for the first time this second
    probe: bool                 # the controller is running one of its own secret pump probes
    power_ok: bool
    valve_cmd: float | None     # PID mode: supply-valve command in % (None in on/off mode)
    valve_pos: float | None     # PID mode: reported valve position in % (None in on/off mode)
    valve_real: float | None    # PID mode: where the valve REALLY is (hidden from the detector)
    switch_high: bool           # hard-wired high-high level switch: tank full / overflowing
    switch_low: bool            # hard-wired low-low level switch: tank (nearly) empty
    duty: float                 # commanded pump duty over the last N ticks, 0..1
    run_duty: float             # how often the pump REALLY ran over the same ticks (hidden from the detector)
    fault_active: bool          # the fault or attack is switched on (hidden from the detector)
    tone: str                   # plant truth: "ok", "warn" or "danger", from the REAL level (hidden from the detector)
    status: str
    screen_alarm: str | None    # what the operator's screen shows, from the reading it trusts (None = no alarm)


def screen_alarm(trusted: float, power_ok: bool, mismatch: bool, a_lost: bool, backup: bool,
                 cfg: Config) -> str | None:
    """The alarm the operator actually sees. It can only use readings, never the real level,
    so a forged sensor can keep this screen quiet while the tank overflows."""
    if not power_ok:
        return "No power"
    if mismatch:
        return "Sensor mismatch, backup in use"
    if a_lost:
        return "Sensor A signal lost" + (", backup in use" if backup else "")
    if trusted > cfg.high_alarm:
        return "High-level alarm"
    if trusted < cfg.low_alarm:
        return "Low-level alarm"
    return None


def classify(level: float, power_ok: bool, mismatch: bool, cfg: Config,
             a_lost: bool = False, backup: bool = False) -> tuple[str, str]:
    """Turn the plant state into a status that an operator would see."""
    if not power_ok:
        return "danger", "No power"
    if level >= 100:
        return "danger", "Overflow"
    if level <= 0:
        return "danger", "Tank dry"
    if mismatch:
        return "warn", "Sensor mismatch, backup in use"
    if a_lost:
        return "warn", "Sensor A signal lost" + (", backup in use" if backup else "")
    if level > cfg.high_alarm:
        return "warn", "High-level alarm"
    if level < cfg.low_alarm:
        return "warn", "Low-level alarm"
    return "ok", "Within limits"


class TankSimulator:
    def __init__(self, cfg: Config | None = None, fault: str | None = None,
                 mode: str = "permanent", backup_sensor: bool = False, seed: int = 1):
        if fault is not None and fault not in SCENARIOS:
            raise ValueError(f"Unknown fault or attack {fault!r}. Choose from {list(SCENARIOS)}")
        if mode not in MODES:
            raise ValueError(f"Unknown mode {mode!r}. Choose from {list(MODES)}")
        self.cfg = cfg or Config()
        if fault in REPLAYS and self.cfg.inject_at < self.cfg.replay_match:
            raise ValueError(f"The replay attack needs at least {self.cfg.replay_match} healthy seconds to record "
                             f"before it starts (inject_at is {self.cfg.inject_at}).")
        self.fault = fault                      # a fault key or an attack key
        self.mode = mode
        self.backup_sensor = backup_sensor
        self.rng = random.Random(seed)          # same seed -> same run every time
        self.net_rng = random.Random(seed + 7919)       # network traffic and message loss
        self.attack_rng = random.Random(seed + 104729)  # the attacker's choices
        self.probe_rng = random.Random(seed + 31337)    # the defender's secret probe schedule

        self.tick = 0
        self.level = self.cfg.start_level
        self.pump_cmd = False                   # the controller's on/off (hysteresis) state
        self.cmd_out = False                    # what it actually sent to the pump (False during a probe)
        self.probe_left = 0                     # seconds left in the current probe
        self.stealth_offset = 0.0
        self.announced = False                  # has the attacker's device shown up on the network yet?
        self.drift = 0.0
        self.frozen: float | None = None
        self.duty_window: deque[int] = deque(maxlen=self.cfg.duty_window)
        self.run_window: deque[int] = deque(maxlen=self.cfg.duty_window)

        self.last_rx = self.cfg.start_level     # controller holds the last message it received
        self.fake: float | None = None          # false data injection: current fake value
        self.recording: deque[tuple[float, bool]] = deque(maxlen=self.cfg.replay_length)
        self.replay_i: int | None = None        # replay: position in the recording

        # Realism: correlated sensor noise state, and the PID valve plant.
        self.noise_state = {"a": 0.0, "b": 0.0}
        equilibrium = 100 * self.cfg.demand / self.cfg.pump_flow   # valve opening that balances demand
        self.u = equilibrium                    # PI controller output (valve command it would send)
        self.e_prev: float | None = None
        self.valve_real = equilibrium           # where the supply valve really is
        self.valve_model = equilibrium          # where it would be if only the controller drove it
        self.last_probe_end = -10_000
        self.probe_requested = False            # the detector asked for a probe

    def _noise(self, which: str = "a") -> float:
        fresh = (self.rng.random() - 0.5) * 2 * self.cfg.sensor_noise
        rho = self.cfg.noise_corr
        if rho == 0:
            return fresh
        # AR(1) noise: same spread as fresh noise, but it wanders slowly like a real level sensor.
        self.noise_state[which] = rho * self.noise_state[which] + (1 - rho * rho) ** 0.5 * fresh
        return self.noise_state[which]

    def _quantize(self, value: float | None) -> float | None:
        """Round to the sensor's resolution, as real instruments and historians do."""
        q = self.cfg.quantize
        if value is None or q <= 0:
            return value
        return round(round(value / q) * q, 6)

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

    def _attack_sensor_data(self, f: str | None, reading: float) -> float:
        """What an attacker does to sensor A's message on its way to the controller."""
        cfg = self.cfg
        if f == "spoof":
            # Believable random wobble, kept just under the pump-ON threshold.
            # It starts from the live value so the switch-over does not show as a jump.
            if self.fake is None:
                self.fake = reading
            new = max(cfg.spoof_min, self.fake + self.attack_rng.uniform(-2.5, 1.5))
            self.fake = min(new, max(cfg.spoof_max, self.fake))   # above the band it may only come down
            reading = self.fake + self.attack_rng.uniform(-cfg.sensor_noise, cfg.sensor_noise)
        else:
            self.fake = None

        if f == "stealth":
            # Smart attacker: a slowly growing offset that looks exactly like an ageing sensor.
            self.stealth_offset = min(cfg.stealth_max, self.stealth_offset + cfg.stealth_rate)
            reading = self._clamp(reading - self.stealth_offset)
        else:
            self.stealth_offset = 0.0

        if f in REPLAYS and self.recording:
            if self.replay_i is None:
                # A careful attacker starts the playback near the live value, at a moment when the
                # pump was doing the same thing as now, so there is no jump and the trend matches.
                same = [i for i, (_, cmd) in enumerate(self.recording) if cmd == self.cmd_out] \
                    or list(range(len(self.recording)))
                self.replay_i = min(same, key=lambda i: abs(self.recording[i][0] - reading))
            reading = self.recording[self.replay_i % len(self.recording)][0]
            if f == "smart_replay":
                # Fresh noise on every replayed value, so no two windows ever match exactly.
                reading = self._clamp(reading + self.attack_rng.uniform(-cfg.sensor_noise, cfg.sensor_noise))
            self.replay_i += 1
        elif self.tick < cfg.inject_at:
            # The attacker quietly records healthy readings, and the pump state that produced each one.
            self.recording.append((reading, self.cmd_out))
        return reading

    def step(self) -> Record:
        cfg = self.cfg
        active = self.fault_active()
        f = self.fault if active else None      # the scenario that is acting on this tick
        power_ok = f != "power"

        # --- sensor A (the one the controller normally trusts) ---
        if f == "drift":
            self.drift = min(cfg.drift_max, self.drift + cfg.drift_rate)
        else:
            self.drift = 0.0
        reading_a = self._quantize(self._clamp(self.level - self.drift + self._noise("a")))

        if f == "stuck":
            if self.frozen is None:
                self.frozen = reading_a        # remember the value at the moment it froze
            reading_a = self.frozen
        else:
            self.frozen = None

        # --- optional backup sensor B (hard-wired, never faulty or attacked in this model) ---
        reading_b_raw = self._quantize(self._clamp(self.level + self._noise("b")))

        # --- the control network between sensor A and the controller ---
        # (a careful attacker rounds forged values to the sensor's resolution too)
        reading_a = self._quantize(self._attack_sensor_data(f, reading_a))
        lost = f == "dos" and self.net_rng.random() < cfg.dos_loss
        if not power_ok:
            packets = 0
        else:
            packets = (cfg.flood_packets if f == "dos" else cfg.normal_packets) + self.net_rng.randint(-2, 2)
        received = reading_a if (power_ok and not lost) else None
        reading_b = reading_b_raw if (self.backup_sensor and power_ok) else None

        # --- which reading does the controller trust? ---
        trusted, mismatch, a_lost = choose_reading(received, reading_b, self.last_rx, cfg)
        a_lost = a_lost and power_ok
        if received is not None:
            self.last_rx = received

        valve_cmd = valve_pos = None
        if cfg.control == "pid":
            # --- PID mode: the pump always runs; a PI controller drives a supply valve (like HAI's LCV01) ---
            if power_ok:
                self.u, self.e_prev = pi_step(self.u, self.e_prev, trusted, cfg)
            else:
                self.probe_left = 0
            self.pump_cmd = power_ok
            # Secret probe: close the valve for a few seconds now and then (physical watermarking).
            # The detector can also ASK for a probe right now (an active challenge).
            requested = self.probe_requested and self.tick - self.last_probe_end > 2
            if (cfg.probe and power_ok and self.probe_left == 0
                    and (requested
                         or (self.tick - self.last_probe_end > cfg.pid_probe_len + cfg.probe_tail + 5
                             and self.probe_rng.random() < cfg.pid_probe_chance))):
                self.probe_left = cfg.pid_probe_len
                self.probe_requested = False
            probing = self.probe_left > 0
            if probing:
                self.probe_left -= 1
                if self.probe_left == 0:
                    self.last_probe_end = self.tick
            valve_cmd = 0.0 if (probing or not power_ok) else self.u
            self.cmd_out = power_ok
            forced = f in ("command", *REPLAYS)      # the attacker forces the valve wide open
            self.valve_real += cfg.valve_lag * ((100.0 if forced else valve_cmd) - self.valve_real)
            self.valve_model += cfg.valve_lag * (valve_cmd - self.valve_model)
            # Replay malware reports where the valve SHOULD be, hiding that it is wide open.
            valve_pos = self.valve_model if f in REPLAYS else self.valve_real
            pump_really_runs = power_ok and f != "pump"
            feedback = pump_really_runs
            inflow = cfg.pump_flow * self.valve_real / 100 if pump_really_runs else 0.0
        else:
            # --- on/off mode: hysteresis so the pump does not chatter ---
            if power_ok:
                if trusted < cfg.pump_on_below:
                    self.pump_cmd = True
                elif trusted > cfg.pump_off_above:
                    self.pump_cmd = False
            else:
                self.pump_cmd = False
                self.probe_left = 0

            # --- defender's secret probe: pause the pump for a moment while filling mid-band ---
            # A live sensor shows the dip; a recording made earlier cannot (physical watermarking).
            if (cfg.probe and power_ok and self.pump_cmd and self.probe_left == 0
                    and 45 <= trusted <= 55 and self.probe_rng.random() < cfg.probe_chance):
                self.probe_left = cfg.probe_len
            probing = self.probe_left > 0
            if probing:
                self.probe_left -= 1
            self.cmd_out = self.pump_cmd and not probing

            pump_really_runs = self.cmd_out
            if f == "pump":
                pump_really_runs = False
            if f in ("command", *REPLAYS):
                pump_really_runs = True             # the attacker forces the pump ON
            if not power_ok:
                pump_really_runs = False
            # Replay malware also fakes the motor feedback so it matches what the controller asked for.
            feedback = self.cmd_out if f in REPLAYS else pump_really_runs
            inflow = cfg.pump_flow if pump_really_runs else 0.0

        new_device = 0
        if f in NEW_DEVICE_ATTACKS and not self.announced:
            self.announced, new_device = True, 1   # e.g. ARP spoofing reveals a never-seen-before MAC

        # --- the physical plant ---
        metered_outflow = cfg.valve_stuck_flow if f == "valve" else cfg.demand
        outflow = metered_outflow + (cfg.leak_flow if f == "leak" else 0.0)
        self.level = max(0.0, min(100.0, self.level + inflow - outflow))

        # --- bookkeeping ---
        if valve_cmd is None:
            self.duty_window.append(1 if self.cmd_out else 0)
            self.run_window.append(1 if pump_really_runs else 0)
        else:
            self.duty_window.append(valve_cmd / 100)
            self.run_window.append(self.valve_real / 100 if pump_really_runs else 0)
        duty = sum(self.duty_window) / len(self.duty_window)
        run_duty = sum(self.run_window) / len(self.run_window)
        tone, status = classify(self.level, power_ok, mismatch, cfg, a_lost, self.backup_sensor)
        rec = Record(
            tick=self.tick, level=self.level, sensor=received, sensor_b=reading_b,
            pump_cmd=self.cmd_out, pump_flow=pump_really_runs, pump_feedback=feedback,
            outflow=metered_outflow if power_ok else None, packets=packets,
            unknown_writes=1 if f == "command" else 0, new_devices=new_device, probe=probing,
            power_ok=power_ok, valve_cmd=valve_cmd, valve_pos=valve_pos,
            valve_real=self.valve_real if cfg.control == "pid" else None,
            # Float switches are independent of sensor A, so a forged or drifting reading cannot hide them.
            switch_high=power_ok and self.level >= 99.5, switch_low=power_ok and self.level <= 0.5,
            duty=duty, run_duty=run_duty, fault_active=active, tone=tone, status=status,
            screen_alarm=screen_alarm(trusted, power_ok, mismatch, a_lost, self.backup_sensor, cfg),
        )
        self.tick += 1
        return rec

    def run(self) -> list[Record]:
        cfg = self.cfg
        if not (cfg.control == "pid" and cfg.probe and cfg.active_probe):
            return [self.step() for _ in range(cfg.ticks)]
        # Closed loop: a detector watches live and may ask the controller for a probe.
        # Its verdicts travel with the records so diagnose() does not have to run it again.
        from .detector import FaultOrAttackDetector   # here, not at the top: detector imports plant
        watcher = FaultOrAttackDetector(cfg)
        records = RunRecords()
        for _ in range(cfg.ticks):
            rec = self.step()
            records.verdicts.append(watcher.observe(rec))
            records.append(rec)
            if watcher.want_probe:
                self.probe_requested, watcher.want_probe = True, False
        records.cfg = cfg
        return records
