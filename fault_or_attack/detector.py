"""The detector: decides FAULT or ATTACK from what the control room can see."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from statistics import correlation, mean, median, pstdev

from .config import Config
from .plant import Record, choose_reading, pi_step
from .scenarios import ATTACK_TECHNIQUES, RESPONSES


UNCONFIRMED = "unconfirmed"   # _sensor_live(): waited long enough, still no probe confirmed sensor A


@dataclass
class Verdict:
    tick: int
    label: str        # "FAULT", "ATTACK", "PHYSICAL" (an on-site person or physical damage) or "UNKNOWN"
    culprit: str      # best guess at what is going on
    reason: str       # the evidence, in words an operator understands
    mitre: str = ""   # MITRE ATT&CK for ICS techniques (attacks only)
    action: str = ""  # what the control room should do next
    also: "Verdict | None" = None   # a second, separate physical finding at the same moment (e.g. a leak during an attack)

    def __post_init__(self) -> None:
        if not self.mitre and self.label == "ATTACK":
            self.mitre = ATTACK_TECHNIQUES.get(self.culprit, "")
        if not self.action:
            self.action = RESPONSES.get(self.label, "")


class FaultOrAttackDetector:
    """Watches only what a real control room can see, one second at a time.

    Allowed: sensor A, backup sensor B, pump command, motor feedback, outflow meter,
    power monitor, network packet count, unknown-host writes, new network devices, the
    controller's own probe schedule and the operator's screen alarm.
    Not allowed: the real level, the plant-truth tone/status, whether the pump really
    delivered water, run_duty, or the fault_active flag. Those are the simulator's secrets.

    Rules run in order, attack fingerprints first, and the first one that fires wins.
    A FAULT verdict is then checked against network evidence (cyber-physical fusion).
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.h: list[Record] = []
        self.res: list[float | None] = []         # mass-balance error per second, worked out once
        self.seen: dict[tuple[float, ...], int] = {}  # past reading windows -> first second they appeared
        self.cusum_up = self.cusum_down = 0.0     # two-sided CUSUM of the mass-balance error
        self.last_new_device: int | None = None   # when a never-seen-before device last appeared
        self.probe_results: deque[bool] = deque(maxlen=3)   # True = the probe was NOT echoed
        self.pending_probe: tuple[int, int] | None = None   # PID mode: probe waiting for its dip to show
        self.strong_miss = False                  # PID mode: the latest probe missed by a wide margin
        self.probe_log: list[tuple[int, bool]] = []   # PID mode: (probe start second, echoed?)
        self.want_probe = False                   # PID mode: asking the controller for a probe now
        self.last_request = -10_000
        self.anomaly_since: int | None = None     # PID mode: when an unexplained mass-balance error began
        self.anomaly_last = -10_000               # PID mode: last second that anomaly was still seen
        self.link_low = 0                         # PID mode: seconds in a row the sensor ignored the valve
        self.flat_run = 1                         # length of the current stretch of identical readings
        self.freeze_ends: deque[int] = deque()    # seconds at which a frozen stretch ended
        # PID mode: the detector's own copy of the control law (the "dual detector" idea, Xue et al. 2025).
        self.u_hat = 100 * cfg.demand / cfg.pump_flow
        self.e_prev_hat: float | None = None
        self.rx_hat = cfg.start_level
        self.law_misses = 0
        self.track_misses = 0
        # Physical side
        self.last_unplanned = None        # last second someone came on site without a work order
        self.b_seen = False               # has backup sensor B ever reported (so its loss means something)

    def observe(self, rec: Record) -> Verdict | None:
        cfg = self.cfg
        self.h.append(rec)
        r = self._residual(self.h[-2], rec) if len(self.h) > 1 else None
        self.res.append(r)
        if r is not None:
            self.cusum_up = max(0.0, self.cusum_up + r - cfg.cusum_k)
            self.cusum_down = max(0.0, self.cusum_down - r - cfg.cusum_k)
        if rec.new_devices:
            self.last_new_device = rec.tick
        if rec.door and not rec.work_order:
            self.last_unplanned = rec.tick
        if rec.sensor_b is not None:
            self.b_seen = True
        if len(self.h) > 1 and rec.sensor is not None and rec.sensor == self.h[-2].sensor:
            self.flat_run += 1
        else:
            if self.flat_run >= cfg.flat_short:
                self.freeze_ends.append(rec.tick)
            self.flat_run = 1
        while self.freeze_ends and rec.tick - self.freeze_ends[0] > 60:
            self.freeze_ends.popleft()
        self._check_probe()
        self._remember_window()
        if cfg.control == "pid":
            self._update_control_checks(rec)
        for rule in (self._site_switches, self._physical_damage, self._power, self._network, self._foreign_writes, self._pump_without_command,
                     self._valve_tracking, self._control_law,
                     self._replay, self._probe_echo, self._ignores_valve, self._physics_violation,
                     self._hardwired_witness, self._pump_no_run,
                     self._outflow_high, self._flatline, self._freezing, self._drift_vs_backup, self._mass_balance,
                     self._slow_balance, self._wall_thinning, self._water_layer, self._bund_leak):
            verdict = rule()
            if verdict:
                verdict = self._fuse(verdict)
                verdict.also = self._second_finding(verdict)
                return verdict
        cusum = max(self.cusum_up, self.cusum_down)
        if cusum > cfg.cusum_h:
            return Verdict(rec.tick, "UNKNOWN", "Mass balance drifting",
                           f"The CUSUM of the mass-balance error has reached {cusum:.1f} (alarm at {cfg.cusum_h:.0f}): "
                           "water is being gained or lost that nothing explains yet.")
        if rec.screen_alarm:
            return Verdict(rec.tick, "UNKNOWN", "Unexplained alarm", f"'{rec.screen_alarm}' with no known signature.")
        return None

    # --- helpers -----------------------------------------------------------
    def _v(self, label: str, culprit: str, reason: str) -> Verdict:
        return Verdict(self.h[-1].tick, label, culprit, reason)

    def _fuse(self, v: Verdict) -> Verdict:
        v = self._fuse_network(v)
        return self._fuse_site(v)

    def _fuse_site(self, v: Verdict) -> Verdict:
        """Physical-side fusion: a symptom that starts soon after someone came on site WITHOUT a work order, with no
        network evidence, has an on-site cause. Planned maintenance (a work order) does not count."""
        if v.label not in ("FAULT", "ATTACK") or self.last_unplanned is None:
            return v
        since = v.tick - self.last_unplanned
        network = (self.last_new_device is not None and v.tick - self.last_new_device <= self.cfg.access_window) \
            or any(r.unknown_writes for r in self.h[-self.cfg.access_window:])
        if since > self.cfg.access_window or network:
            return v
        return Verdict(v.tick, "PHYSICAL", "On-site tampering or theft",
                       f"It looks like '{v.culprit.lower()}', but it began {since} s after someone came on site with no "
                       "work order, and nothing unusual happened on the network. Check the spot and the CCTV.")

    def _fuse_network(self, v: Verdict) -> Verdict:
        """Cyber-physical fusion: a fault-like symptom that starts soon after a never-seen-before
        device joins the control network is treated as an attack in disguise."""
        if v.label != "FAULT" or self.last_new_device is None:
            return v
        since = v.tick - self.last_new_device
        if since > self.cfg.fusion_window:
            return v
        return Verdict(v.tick, "ATTACK", "Disguised attack",
                       f"It looks like '{v.culprit.lower()}', but it began {since} s after a never-seen-before "
                       "device joined the control network. Worn-out equipment does not bring new devices with it.")

    def _check_probe(self) -> None:
        """When one of the controller's secret probes has just ended, check the sensor echoed it."""
        h = self.h
        if self.cfg.control == "pid":
            self._check_probe_pid()
            return
        if len(h) < 3 or not h[-2].probe or h[-1].probe:
            return
        start = len(h) - 2
        while start > 0 and h[start - 1].probe:
            start -= 1
        # A pause during second t shows up in the reading at t+1.
        errors = self.res[start + 1:]
        if errors and None not in errors:
            self.probe_results.append(abs(mean(errors)) > self.cfg.probe_limit)

    def _check_probe_pid(self) -> None:
        """PID mode: the valve's lag smears the dip out, so add up the mass-balance error over the
        probe plus a tail, after removing the error rate seen just before the probe (a leak or drift
        must not count as a missing echo)."""
        h, cfg = self.h, self.cfg
        n = len(h) - 1
        if len(h) >= 2 and h[-2].probe and not h[-1].probe:
            start = n - 1
            while start > 0 and h[start - 1].probe:
                start -= 1
            self.pending_probe = (start, n - 1)
        if self.pending_probe is None:
            return
        start, end = self.pending_probe
        stop = end + 2 + cfg.probe_tail             # first second after the probe's effect has passed
        b = cfg.probe_bracket
        if n < stop + b - 1:
            return
        self.pending_probe = None
        errors = self.res[start + 1: stop]
        # Bracket the probe: the error rate before it and after it must agree, or the plant itself
        # changed during the probe (a fault starting, say) and the probe proves nothing.
        before = [x for x in self.res[max(0, start - b): start] if x is not None]
        after = [x for x in self.res[stop: stop + b] if x is not None]
        if None in errors or len(before) < 3 or len(after) < 3 or abs(mean(before) - mean(after)) > 0.3:
            return
        # A probe only proves something if it really changed the valve (it cannot close a closed valve).
        positions = [r.valve_pos for r in h[start:stop] if r.valve_pos is not None]
        if not positions or h[start].valve_pos is None or h[start].valve_pos - min(positions) < 5:
            return
        surprise = abs(sum(errors) - len(errors) * (mean(before) + mean(after)) / 2)
        self.probe_results.append(surprise > cfg.pid_probe_limit)
        self.probe_log.append((h[start].tick, surprise <= cfg.pid_probe_limit))
        # Only the most recent probe can be decisive on its own; it is replaced by the next probe.
        self.strong_miss = surprise > 2 * cfg.pid_probe_limit

    def _inflow(self, rec: Record) -> float:
        """Inflow the control room expects from what it can see: pump running, and in PID mode
        the reported supply-valve position."""
        if not rec.pump_feedback:
            return 0.0
        if rec.valve_pos is not None:
            return self.cfg.pump_flow * rec.valve_pos / 100
        return self.cfg.pump_flow

    def _residual(self, prev: Record, cur: Record) -> float | None:
        """Mass-balance error for one second.

        Expected change = inflow (pump feedback, plus valve position in PID mode) minus the metered
        outflow. Error = what sensor A actually did minus that. Healthy: only sensor noise, about 0.
        """
        if prev.sensor is None or cur.sensor is None or prev.outflow is None:
            return None
        if not (0.5 < prev.sensor < 99.5 and 0.5 < cur.sensor < 99.5):
            return None                          # a sensor pinned at 0 or 100 tells us nothing
        return (cur.sensor - prev.sensor) - self._expected_change(prev)

    def _expected_change(self, prev: Record) -> float:
        """Level change the control room expects over the next second. At the limits the physics is
        one-sided: a full tank cannot rise (the excess spills), an empty one cannot fall. The
        hard-wired level switches tell the detector when that applies, without trusting sensor A."""
        expected = self._inflow(prev) - prev.outflow
        if prev.switch_high:
            expected = min(expected, 0.0)
        if prev.switch_low:
            expected = max(expected, 0.0)
        return expected

    def _update_control_checks(self, rec: Record) -> None:
        """PID mode: replay the controller's own law on the readings it received, and the valve's
        known lag on its command, and count how often reality disagrees."""
        cfg = self.cfg
        if rec.power_ok:
            trusted = choose_reading(rec.sensor, rec.sensor_b, self.rx_hat, cfg)[0]
            if rec.sensor is not None:
                self.rx_hat = rec.sensor
            self.u_hat, self.e_prev_hat = pi_step(self.u_hat, self.e_prev_hat, trusted, cfg)
            expected_cmd = 0.0 if rec.probe else self.u_hat
            off = rec.valve_cmd is not None and abs(rec.valve_cmd - expected_cmd) > cfg.law_limit
            self.law_misses = self.law_misses + 1 if off else 0
        else:
            self.law_misses = 0
        if len(self.h) >= 2 and rec.valve_pos is not None and self.h[-2].valve_pos is not None and rec.power_ok:
            prev = self.h[-2]
            predicted = prev.valve_pos + cfg.valve_lag * (rec.valve_cmd - prev.valve_pos)
            self.track_misses = self.track_misses + 1 if abs(rec.valve_pos - predicted) > cfg.tracking_limit else 0
        else:
            self.track_misses = 0

    def _residuals(self, n: int) -> list[float]:
        """Mass-balance errors for the last n seconds, skipping seconds with no usable reading."""
        return [x for x in self.res[-n:] if x is not None]

    def _remember_window(self) -> None:
        """Index the reading window that has just become old enough to compare against.

        Only windows that end at least replay_match seconds ago are indexed, so a window is
        never compared with one that overlaps it.
        """
        k = self.cfg.replay_match
        start = len(self.h) - 2 * k
        if start < 0:
            return
        window = tuple(r.sensor for r in self.h[start:start + k])
        if None not in window:
            self.seen.setdefault(window, start)

    @staticmethod
    def _line_fit(ys: list[float]) -> tuple[float, float]:
        """Least-squares straight line through ys (one per second): returns (slope, scatter around it)."""
        xs = range(len(ys))
        x_bar, y_bar = mean(xs), mean(ys)
        slope = sum((x - x_bar) * (y - y_bar) for x, y in zip(xs, ys)) / sum((x - x_bar) ** 2 for x in xs)
        scatter = pstdev(y - (y_bar + slope * (x - x_bar)) for x, y in zip(xs, ys))
        return slope, scatter

    @staticmethod
    def _roughness(values: list[float]) -> float:
        """Typical jump between neighbouring values. Physical errors are smooth; forged data is not.

        The median ignores the odd one-off step (a sensor freezing, a fault switching on), so only
        data that jumps around again and again counts as rough.
        """
        return median(abs(b - a) for a, b in zip(values, values[1:]))

    def _impossible_jumps(self, res: list[float]) -> int:
        """How many jumps in the mass-balance error are bigger than sensor noise can ever make.

        Each error is the difference of two noisy readings, so a jump between neighbouring errors
        involves three readings and can be at most 4 x the noise (plus rounding). Healthy noise can
        sometimes look rough by chance; it can never jump further than that limit. Forged values do.
        """
        cfg = self.cfg
        limit = 4 * cfg.sensor_noise + 2 * cfg.quantize + 0.05
        return sum(abs(b - a) > limit for a, b in zip(res, res[1:]))

    def _second_finding(self, main: Verdict) -> Verdict | None:
        """Physical problems can happen during something else: a leak during a network flood, water getting in while
        the tank also leaks. These rules read hard-wired site signals, so they are checked even after a first verdict,
        and the first one that says something different is reported alongside it."""
        for rule in (self._site_switches, self._physical_damage, self._slow_balance, self._wall_thinning,
                     self._water_layer, self._bund_leak):
            v = rule()
            if v and v.label != "UNKNOWN" and (v.label, v.culprit) != (main.label, main.culprit):
                return v
        return None

    # --- rules -------------------------------------------------------------
    def _site_switches(self):
        """Hard-wired switches people operate on site: a tamper switch or the safety bypass, with no work order."""
        r = self.h[-1]
        if r.work_order:
            return None
        if r.tamper:
            return self._v("PHYSICAL", "Instrument tampering",
                           "A tamper switch on an instrument cabinet opened with no work order. Someone on site is "
                           "touching the instruments; no reading from that cabinet can be trusted until it is checked.")
        if r.bypass:
            return self._v("PHYSICAL", "Safety bypass without a work order",
                           "The overfill trip is switched to bypass and no maintenance is planned. At Buncefield an "
                           "independent high-level switch was left inoperative; check it now.")

    def _physical_damage(self):
        """Several independent hard-wired signs at once: physical damage (a drone, an explosion, a vehicle), not wear."""
        cfg, h = self.cfg, self.h
        n = cfg.damage_window
        if len(h) <= n:
            return None
        old, r = h[-n - 1], h[-1]
        if not r.power_ok:
            return None                       # a power cut darkens sensors too; that is the power rule's job
        signs = []
        if self.b_seen and old.sensor_b is not None and r.sensor_b is None:
            signs.append("backup sensor B went dead")
        if r.gas_alarm and not old.gas_alarm:
            signs.append("the gas detector alarmed")
        if r.bund - old.bund > 2.0 * n:       # a hole, not a leak: ordinary leaks fill the bund far slower
            signs.append(f"the bund filled by {r.bund - old.bund:.0f}% in {n} s")
        if len(signs) >= 2:
            return self._v("PHYSICAL", "Physical damage",
                           "Within a few seconds " + ", ".join(signs) + ". Worn parts fail one at a time; several "
                           "independent signs at once mean physical damage. Keep people clear and call site security.")

    def _wall_thinning(self):
        """Corrosion before it leaks: the hard-wired electrical-resistance probe shows the pipe wall wearing away."""
        cfg = self.cfg
        w = cfg.slow_window
        if len(self.h) <= w:
            return None
        r, old = self.h[-1], self.h[-w - 1]
        if r.wall is None or old.wall is None:
            return None
        lost = old.wall - r.wall
        if lost > cfg.thin_limit:
            return self._v("FAULT", "Pipe wall thinning",
                           f"The corrosion probe shows {lost:.1f}% of the corrosion allowance gone in {w} s, far faster "
                           f"than normal ({r.wall:.0f}% left). Nothing has leaked yet: inspect the line (ultrasonic "
                           "thickness) and plan the repair before it does.")

    def _water_layer(self):
        """The hard-wired water-interface probe on its own: the water layer under the product keeps rising.
        Catches water ingress even when a leak at the same time hides the level gain."""
        cfg = self.cfg
        w = cfg.slow_window
        if len(self.h) <= w:
            return None
        r, old = self.h[-1], self.h[-w - 1]
        if r.interface is None or old.interface is None:
            return None
        rise = r.interface - old.interface
        if rise > 0.5 * w * cfg.slow_limit:
            return self._v("FAULT", "Water getting into the tank",
                           f"The water-interface probe shows the water layer up {rise:.1f}% in {w} s. Check the roof "
                           "seal and drain the water before it corrodes the tank floor.")

    def _bund_leak(self):
        """The bund level and the gas detector together, without trusting sensor A: product is collecting in the bund.
        Rain fills the bund too, but rain does not set off the gas detector. Gas-detector tests run under a work order."""
        cfg = self.cfg
        w = cfg.slow_window
        if len(self.h) <= w:
            return None
        r, old = self.h[-1], self.h[-w - 1]
        if r.work_order or not r.gas_alarm or not self.h[-cfg.damage_window - 1].gas_alarm:
            return None                       # a gas alarm that has only just started: physical damage is checked first
        if r.bund - old.bund > cfg.bund_rise and r.bund - self.h[-cfg.damage_window - 1].bund < 0.5 * (r.bund - old.bund):
            return self._v("FAULT", "Slow leak into the bund",
                           f"The bund rose {r.bund - old.bund:.1f}% in {w} s and the gas detector smells product. A real "
                           "leak, typically corrosion: isolate the section and send a technician.")

    def _slow_balance(self):
        """Slow leaks and gains, such as corrosion or water ingress, far too small for the per-second checks.

        Over minutes the sensor's noise cancels out of the summed water balance (each second's noise is undone by the
        next), so a steady loss of a few hundredths of a percent per second stands out."""
        cfg = self.cfg
        w = cfg.slow_window
        if len(self.res) < w:
            return None
        res = [x for x in self.res[-w:] if x is not None]
        if len(res) < 0.9 * w:
            return None
        rate = mean(res)
        recent = sum(x for x in self.res[-cfg.damage_window:] if x is not None)
        if abs(recent) > 0.5 * abs(sum(res)):
            return None                       # most of it arrived in the last few seconds: sudden, not slow
        r, old = self.h[-1], self.h[-w]
        if r.sensor_b is not None and r.sensor is not None and abs(r.sensor_b - r.sensor) > 3:
            return None                       # the sensors disagree: the drift and witness rules decide
        if rate < -cfg.slow_limit:
            loss = f"{-rate:.2f}%/s of product goes missing that no meter accounts for"
            if r.bund - old.bund > cfg.bund_rise:
                return self._v("FAULT", "Slow leak into the bund",
                               f"{loss.capitalize()}, and the bund around the tank is filling. A slow, real leak, "
                               "typically corrosion: isolate the section and send a technician.")
            if self.last_unplanned is not None and r.tick - self.last_unplanned <= cfg.access_window + w:
                return self._v("PHYSICAL", "Product theft",
                               f"{loss.capitalize()} outside the bund, starting soon after someone came on site with no "
                               "work order. A leak that size would collect in the bund; this looks like a tap.")
            return self._v("FAULT", "Slow leak", f"{loss.capitalize()}, steadily. A slow leak outside the bund, "
                           "typically corrosion" + ("" if r.sensor_b is not None else ", or a slowly drifting sensor") + ".")
        if rate > cfg.slow_limit:
            if r.interface is not None and old.interface is not None and r.interface - old.interface > 0.5 * w * cfg.slow_limit:
                return self._v("FAULT", "Water getting into the tank",
                               f"The level gains {rate:.2f}%/s that no inflow explains, and the water-interface probe "
                               f"shows the water layer up {r.interface - old.interface:.1f}%. Check the roof seal and drain "
                               "the water before it corrodes the tank floor.")
            return self._v("UNKNOWN", "Unexplained slow gain",
                           f"The level gains {rate:.2f}%/s that no inflow explains. Check for an unmetered inflow.")

    def _power(self):
        if not self.h[-1].power_ok:
            return self._v("FAULT", "Power loss",
                           "The power monitor reports the supply is down; pump, sensor and meters went dark together.")

    def _network(self):
        cfg = self.cfg
        recent = [r for r in self.h[-cfg.window:] if r.power_ok]
        if len(recent) < 5:
            return None
        loss = sum(r.sensor is None for r in recent) / len(recent)
        traffic = mean(r.packets for r in recent) / cfg.normal_packets
        if traffic > 3 and loss >= 0.2:
            return self._v("ATTACK", "Denial of service",
                           f"Network traffic is {traffic:.0f}x normal and {loss:.0%} of sensor messages are lost "
                           "while power is healthy. Floods are deliberate; cables do not flood.")
        if all(r.sensor is None for r in recent[-5:]) and traffic < 1.5:
            return self._v("FAULT", "Sensor link failure",
                           "Sensor A went completely silent while network traffic is normal: a cut cable or dead transmitter.")

    def _foreign_writes(self):
        if self.h[-1].unknown_writes:
            return self._v("ATTACK", "Command injection",
                           "The pump or valve received write commands from a host that is not the controller.")

    def _pump_without_command(self):
        last = self.h[-2:]
        if len(last) == 2 and all(r.pump_feedback and not r.pump_cmd and r.power_ok for r in last):
            return self._v("ATTACK", "Unauthorised pump control",
                           "The pump is running although the controller commanded it OFF. "
                           "A failed pump stops; it cannot start itself.")

    def _valve_tracking(self):
        """PID mode: a valve that moves AWAY from its command is being driven by someone else;
        one that fails to follow is sticking."""
        if self.track_misses < 2:
            return None
        cur = self.h[-1]
        prev = self.h[-2]
        if abs(cur.valve_pos - cur.valve_cmd) > abs(prev.valve_pos - cur.valve_cmd):
            return self._v("ATTACK", "Unauthorised valve control",
                           f"The supply valve is moving away from its command (at {cur.valve_pos:.0f}%, commanded "
                           f"{cur.valve_cmd:.0f}%). A sticking valve stops moving; it does not drive itself.")
        return self._v("FAULT", "Valve not following command",
                       f"The supply valve is at {cur.valve_pos:.0f}% but its command is {cur.valve_cmd:.0f}% and it "
                       "is not catching up: a sticking or failed actuator.")

    def _control_law(self):
        """PID mode: the valve command is not what the controller's own law gives for the readings
        it received, so something other than the controller wrote it."""
        if self.law_misses >= 2:
            cur = self.h[-1]
            return self._v("ATTACK", "Controller output forged",
                           f"The valve command is {cur.valve_cmd:.1f}%, but the controller's own PI law gives "
                           f"{(0.0 if cur.probe else self.u_hat):.1f}% for the readings it received.")

    def _replay(self):
        k = self.cfg.replay_match
        if len(self.h) < 2 * k:
            return None
        tail = tuple(r.sensor for r in self.h[-k:])
        if None in tail or max(tail) - min(tail) < 0.5:
            return None                          # a flat line is the stuck-sensor rule's job
        i = self.seen.get(tail)
        if i is not None:
            return self._v("ATTACK", "Replay attack",
                           f"The last {k} readings are an exact copy of seconds {i}-{i + k - 1}. "
                           "Real sensor noise never repeats, so this is a recording.")

    def _probe_echo(self):
        missed = sum(self.probe_results)
        if self.cfg.control == "pid":
            # A frozen sensor cannot echo a probe either: leave that to the stuck-sensor rule.
            tail = [r.sensor for r in self.h[-4:]]
            if len(set(tail)) == 1:
                return None
            if self.strong_miss or missed >= 2:
                return self._v("ATTACK", "Replay attack",
                               "The controller secretly closed the supply valve for a few seconds, and sensor A "
                               "did not show the dip. A live sensor follows the valve; a recording cannot.")
            return None
        if missed >= 2:
            return self._v("ATTACK", "Replay attack",
                           f"The controller secretly paused the pump {len(self.probe_results)} times, and sensor A "
                           f"failed to dip on {missed} of them. A live sensor follows the pump; a recording cannot.")

    def _physics_violation(self):
        cfg = self.cfg
        last = self.h[-4:]
        if len(last) == 4 and all(
            a.sensor is not None and b.sensor is not None and a.outflow is not None
            and self._inflow(a) - a.outflow >= 0.5
            and b.sensor - a.sensor <= -cfg.fall_limit
            for a, b in zip(last, last[1:])
        ):
            return self._v("ATTACK", "False data injection",
                           "Sensor A keeps falling while the pump is confirmed running and the outflow meter is normal. "
                           "Mass balance says the level must rise, so the reading is forged.")
        res = self._residuals(cfg.window)
        if len(res) < cfg.window:
            return None
        rough = self._roughness(res)
        if rough > cfg.roughness_limit and self._impossible_jumps(res) >= cfg.impossible_jumps:
            return self._v("ATTACK", "False data injection",
                           f"Sensor A's mass-balance error typically jumps by {rough:.1f}%/s "
                           "(healthy is about 0.3). Physical faults are smooth; forged data is not.")

    def _hardwired_witness(self):
        """Witnesses an attacker on the network cannot reach: backup sensor B and the high-level float switch.

        An adaptive attacker can forge sensor A, the motor feedback and the valve position so that they
        agree with each other and with physics, so every networked check passes. A worn part cannot do
        that: it breaks the mass balance of sensor A itself. So if sensor A's mass balance closes neatly
        while a hard-wired witness shows water the forged feedback cannot explain, the networked story is
        a lie. (Switch it off with witness_check=False; --stress compares both.)"""
        cfg = self.cfg
        if not cfg.witness_check:
            return None
        n = cfg.witness_window
        recent = self.h[-(n + 1):]
        res_a = self._residuals(cfg.window)
        if len(recent) < n + 1 or len(res_a) < cfg.window:
            return None
        a_closes = abs(mean(res_a)) < cfg.residual_limit and self._roughness(res_a) <= cfg.roughness_limit
        if not a_closes:
            return None                      # sensor A's own physics is broken: the fault rules decide
        # Witness 1: backup sensor B gains water that the (forged) pump feedback and valve cannot explain.
        gains = [b.sensor_b - a.sensor_b - self._expected_change(a) for a, b in zip(recent, recent[1:])
                 if a.sensor_b is not None and b.sensor_b is not None and a.outflow is not None]
        if len(gains) == n and mean(gains) > cfg.witness_gain:
            return self._v("ATTACK", "Consistent forgery",
                           f"Sensor A, the motor feedback and the valve all tell the same healthy story, but hard-wired "
                           f"backup sensor B gains {mean(gains):.1f}%/s more water than they allow. A worn part breaks "
                           "its own physics; only someone forging every networked signal at once keeps it this tidy.")
        # Witness 2: the hard-wired high-level switch says the tank is full, while sensor A reads normal.
        r = self.h[-1]
        if all(x.switch_high for x in recent) and r.sensor is not None and r.sensor < cfg.high_alarm - 10:
            return self._v("ATTACK", "Consistent forgery",
                           f"The hard-wired high-level switch says the tank is full, yet sensor A reads {r.sensor:.0f}% "
                           "and its readings still obey physics perfectly. A failing sensor does not stay this "
                           "consistent with the pump: every networked signal is being forged.")
        return None

    def _pump_no_run(self):
        last = self.h[-2:]
        if len(last) == 2 and all(r.pump_cmd and not r.pump_feedback and r.power_ok for r in last):
            return self._v("FAULT", "Pump failure",
                           "The controller commands the pump ON but the motor feedback shows it is not running.")

    def _outflow_high(self):
        r = self.h[-1]
        if r.outflow is not None and r.outflow > self.cfg.demand + 1.0:
            return self._v("FAULT", "Valve stuck open",
                           f"The outflow meter reads {r.outflow:.1f}%/s against a normal demand of "
                           f"{self.cfg.demand:.1f}%/s: the outlet is passing more than it should.")

    def _flatline(self):
        n = self.cfg.flatline_ticks
        tail = [r.sensor for r in self.h[-n:]]
        if len(tail) == n and None not in tail and len(set(tail)) == 1:
            return self._v("FAULT", "Sensor stuck",
                           f"Sensor A has reported exactly {tail[0]:.1f}% for {n} seconds. A live sensor always has some noise.")

    def _drift_vs_backup(self):
        cfg = self.cfg
        pairs = [(r.sensor_b - r.sensor) for r in self.h[-cfg.window:]
                 if r.sensor is not None and r.sensor_b is not None]
        if len(pairs) < cfg.window or abs(pairs[-1]) < 3:
            return None
        slope, scatter = self._line_fit(pairs)
        if 0.2 <= abs(slope) <= 1.5 and scatter < 0.4 and (slope > 0) == (pairs[-1] > 0):
            live = self._sensor_live()
            if live is None:
                return None
            if live is UNCONFIRMED:
                return self._unconfirmed(f"Sensor A is moving away from backup sensor B at {abs(slope):.1f}%/s")
            return self._v("FAULT", "Sensor drift",
                           f"Sensor A is moving away from backup sensor B at a steady {abs(slope):.1f}%/s. "
                           "Slow, smooth divergence is how sensors age." + live)

    def _mass_balance(self):
        """A steady, unexplained gain or loss of water: the signature of a physical fault.

        Adding up the mass-balance error over the last 1, 2, ... n seconds gives a running total.
        Sensor noise mostly cancels in that sum, so a physical fault draws a straight line
        (the same loss every second). Forged data draws a wobbly random walk, and a fault that
        has only just started draws a bent line, so both are left for other rules or for later.
        """
        cfg = self.cfg
        n = cfg.fault_fit
        res = self._residuals(n)
        if len(res) < n:
            return None
        totals = [sum(res[-k:]) for k in range(1, n + 1)]
        err, scatter = self._line_fit(totals)
        if abs(err) <= cfg.residual_limit or scatter > cfg.straight_limit:
            return None
        r = self.h[-1]
        if r.sensor_b is not None and r.sensor is not None and abs(r.sensor_b - r.sensor) < 2:
            return self._v("FAULT", "Leak",
                           f"Both sensors agree, yet {abs(err):.1f}%/s of water goes missing that no meter accounts for. "
                           "The error is steady, as a physical leak is.")
        live = self._sensor_live()
        if live is None:
            return None
        if live is UNCONFIRMED:
            return self._unconfirmed(f"Sensor A changes {err:+.1f}%/s differently from what the valve and outflow "
                                     "meter predict")
        return self._v("FAULT", "Leak or sensor drift",
                       f"Sensor A changes {err:+.1f}%/s differently from what the pump and outflow meter predict, and the "
                       "error is steady, as physical faults are." + (live or " A backup sensor would tell a leak from drift."))

    def _valve_link(self) -> float | None:
        """PID mode: correlation between how the level moved and how the valve says it should
        have moved, over the last link_window seconds. A leak or drift shifts this by a constant,
        which correlation ignores; a recording cannot follow the valve at all."""
        cfg = self.cfg
        if cfg.control != "pid" or len(self.h) <= cfg.link_window:
            return None
        xs, ys = [], []
        recent = self.h[-cfg.link_window - 1:]
        for a, b in zip(recent, recent[1:]):
            if a.sensor is None or b.sensor is None or a.outflow is None:
                continue
            xs.append(self._expected_change(a))
            ys.append(b.sensor - a.sensor)
        if len(xs) < 0.75 * cfg.link_window or pstdev(xs) < cfg.link_min_activity or pstdev(ys) == 0:
            return None
        # Only judge a window in which the plant itself did not change: the mass-balance error must be
        # the same in both halves. (A fault starting mid-window makes the controller react against a
        # stepping level rate, which would look like the sensor ignoring the valve.)
        err = [y - x for x, y in zip(xs, ys)]
        q = len(err) // 4
        quarters = [mean(err[i * q:(i + 1) * q]) for i in range(4)]
        if max(quarters) - min(quarters) > 0.3 or pstdev(err) > 0.5:
            return None
        return correlation(xs, ys)

    def _ignores_valve(self):
        corr = self._valve_link() if self.cfg.link_limit > -1 else None
        # A recording keeps ignoring the valve; a fault starting can dent the correlation for a
        # second or two. So the sensor must ignore the valve several seconds running.
        self.link_low = self.link_low + 1 if corr is not None and corr < self.cfg.link_limit else 0
        if self.link_low >= self.cfg.link_persist:
            return self._v("ATTACK", "Replay attack",
                           f"Over the last {self.cfg.link_window} s, sensor A's movements match the valve's only "
                           f"{corr:+.2f} (healthy is above {self.cfg.link_limit + 0.35:.2f}). A live sensor follows the "
                           "valve, even with a leak or drift; a recording cannot.")

    def _sensor_live(self) -> str | None:
        """Active challenge before blaming equipment (PID mode).

        A recording can look like a steady loss or a drifting sensor. So before a FAULT verdict,
        ask the controller for a probe and wait until sensor A has visibly echoed it.
        Returns extra wording for the verdict, or None to keep waiting. If probes keep coming back
        inconclusive (the plant itself keeps changing), give the fault verdict after a while anyway.
        """
        cfg, r = self.cfg, self.h[-1]
        if not (cfg.control == "pid" and cfg.probe and cfg.active_probe):
            return ""
        # A new anomaly starts if the last one has not been seen for a while: never let an
        # old probe result vouch for a later, unrelated event.
        if self.anomaly_since is not None and r.tick - self.anomaly_last > 2 * cfg.window:
            self.anomaly_since = None
        if self.anomaly_since is None:
            self.anomaly_since = r.tick - cfg.fault_fit
        self.anomaly_last = r.tick
        since = [ok for start, ok in self.probe_log if start >= self.anomaly_since]
        if any(since):
            return " A probe confirmed sensor A is live, so this is not a recording."
        if r.tick - self.anomaly_since > cfg.live_timeout:
            # No probe could confirm sensor A is live, and none failed decisively either. Do not
            # guess FAULT (an attack labelled a fault lets the attacker hide): escalate instead.
            return UNCONFIRMED
        if self.pending_probe is None and not r.probe and r.tick - self.last_request > cfg.request_gap:
            self.want_probe, self.last_request = True, r.tick
        return None

    def _unconfirmed(self, what: str) -> Verdict:
        return self._v("UNKNOWN", "Sensor A unconfirmed",
                       f"{what}, but no probe could confirm sensor A is live. It could be a fault or a recording: "
                       "field-check the level before deciding.")

    def _freezing(self):
        """A sensor that keeps freezing for a few seconds at a time. Each freeze is too short for the
        stuck-sensor rule, but healthy rounded sensors never freeze this often (limit learned from normal data)."""
        limit = self.cfg.flat_runs_limit
        if limit and len(self.freeze_ends) >= limit:
            return self._v("FAULT", "Sensor stuck",
                           f"Sensor A froze {len(self.freeze_ends)} times in the last minute. Healthy sensors never "
                           "freeze this often: a loose connection or failing transmitter.")


def findings(records: list[Record], cfg: Config) -> list[Verdict]:
    """Every distinct thing the detector said during a run, main verdicts and second findings alike, in order."""
    live = getattr(records, "verdicts", None)
    if live is not None and getattr(records, "cfg", None) == cfg and len(live) == len(records):
        per_tick = live
    else:
        det = FaultOrAttackDetector(cfg)
        per_tick = [det.observe(rec) for rec in records]
    out: list[Verdict] = []
    seen: set[tuple[str, str]] = set()
    for v in per_tick:
        for x in (v, v.also if v else None):
            if x is not None and (x.label, x.culprit) not in seen:
                seen.add((x.label, x.culprit))
                out.append(x)
    return out


def diagnose(records: list[Record], cfg: Config) -> tuple[Verdict | None, list[Verdict]]:
    """Run the detector over a whole run.

    Returns the first firm verdict (FAULT or ATTACK; falls back to UNKNOWN) and a timeline
    that lists each verdict when it first appears or changes.
    """
    # A closed-loop run already watched itself with an identical detector: reuse its verdicts.
    live = getattr(records, "verdicts", None)
    if live is not None and getattr(records, "cfg", None) == cfg and len(live) == len(records):
        per_tick = live
    else:
        det = FaultOrAttackDetector(cfg)
        per_tick = [det.observe(rec) for rec in records]
    timeline: list[Verdict] = []
    first: Verdict | None = None
    unknown: Verdict | None = None
    for v in per_tick:
        if v is None:
            continue
        if not timeline or (timeline[-1].label, timeline[-1].culprit) != (v.label, v.culprit):
            timeline.append(v)
        if v.label == "UNKNOWN":
            unknown = unknown or v
        elif first is None:
            first = v
    return first or unknown, timeline
