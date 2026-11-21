"""Test the Fault-or-Attack detection ideas on REAL plant data (HAI 22.04).

HAI (HIL-based Augmented ICS) is a public security dataset recorded on a real testbed by
NSR/ETRI, South Korea: https://github.com/icsdataset/hai  (licence: CC BY-SA 4.0).
We use the boiler process's RETURN WATER TANK, which is the closest match to our simulated tank:

    P1_LIT01   tank level (mm)                 -> our sensor A
    P1_FT01Z   flow converted from FT01 (l/h)  -> flow into / out of the tank
    P1_FT03Z   outflow (l/h)                   -> our outflow meter
    P1_LCV01D  level-control valve command     -> our pump command
    P1_LCV01Z  level-control valve position    -> our motor feedback
    P1_FCV03D  outflow valve command, P1_FCV03Z its position
    P1_B3004   level setpoint, P1_B3005 outflow setpoint

What carries over from the simulator, and what does not:
    - HAI's level loop is a continuous PID valve, not an on/off pump, so the pump-specific rules
      and the secret pump probes do not apply.
    - HAI labels ATTACKS only. It has no labelled equipment faults, so this section measures how
      well attacks are DETECTED and how few false alarms are raised; it cannot score FAULT vs ATTACK.

Checks (all thresholds learned from normal-only training data, never from the test file):
    1. Mass balance + CUSUM: does the level change the way the flows say it should?
    2. Control-law consistency: is the valve command what the level/flow controller SHOULD have sent?
       (the "dual detector" idea from Xue et al. 2025)
    3. Actuator tracking: does each valve's position follow its command?
    4. Never-seen setpoints: is an operator setpoint outside anything seen in normal operation?
    5. Exact replay: are the last readings an exact copy of an earlier stretch?

Scoring follows the research advice: per attack EVENT (no point-adjust), false alarms counted as
separate alarm events per hour of normal operation.

Usage:
    python "FAULT OR ATTACK.py" --hai                          # data/hai/train1.csv + data/hai/test1.csv
    python "FAULT OR ATTACK.py" --hai data/hai/test2.csv       # second test day (17 attacks)
    python "FAULT OR ATTACK.py" --hai TEST.csv --hai-train TRAIN.csv
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from statistics import mean, pstdev


HAI_TAGS = ["P1_LIT01", "P1_FT01Z", "P1_FT02Z", "P1_FT03Z", "P1_LCV01D", "P1_LCV01Z",
            "P1_FCV03D", "P1_FCV03Z", "P1_B3004", "P1_B3005"]


# Attack timetable for HAI 22.04 test1 (from hai_dataset_technical_details.pdf, page 33).
# "in scope" = targets the return water tank's level/flow loops, which these checks watch.
HAI_ATTACKS_TEST1 = {
    "A101": ("P1_PCV01D pressure-valve command", False),
    "A102": ("P1_LCV01D level-valve command (stealthy)", True),
    "A103": ("P1_FCV03D outflow-valve command + P1_FT03 sensor spoof", True),
    "A104": ("P3_LCV01D (another process)", False),
    "A105": ("P1_B3004 level setpoint", True),
    "A106": ("P1_PP04 heater pump", False),
    "A107": ("P1_FCV01D temperature valve", False),
}


# Attack timetable for HAI 22.04 test2 (same PDF, pages 33-34).
HAI_ATTACKS_TEST2 = {
    "A201": ("P1_B2016 pressure setpoint", False),
    "A202": ("P1_FCV03D outflow-valve command (stealthy)", True),
    "A203": ("P2_AutoSD turbine setpoint", False),
    "A204": ("P1_PCV01D pressure valve + P2_SCO", False),
    "A205": ("P3_LCV01D (another process)", False),
    "A206": ("P1_B2016, P1_PIT01 pressure + P2 turbine", False),
    "A207": ("P1_LCV01D level-valve command", True),
    "A208": ("P2_SCO, P2_SIT01 turbine", False),
    "A209": ("P1_B2016, P1_PIT01, P1_FIT01 pressure loop", False),
    "A210": ("P2_AutoSD turbine setpoint", False),
    "A211": ("P1_PCV01D, P1_PIT01 pressure loop", False),
    "A212": ("P3_LCP01D (another process)", False),
    "A213": ("P1_PP04 heater pump (stealthy)", False),
    "A214": ("P3_LCV01D (another process)", False),
    "A215": ("P1_B3005 outflow setpoint + P1_FT03 sensor spoof", True),
    "A216": ("P1_B2016 pressure setpoint + P1_B3005 outflow setpoint", True),
    "A217": ("P1_FCV03D outflow-valve command", True),
}


HAI_TIMETABLES = {"test1": HAI_ATTACKS_TEST1, "test2": HAI_ATTACKS_TEST2}


HAI_WIN = 10              # seconds per mass-balance step (the level sensor is noisy second to second)


HAI_CUSUM_K = 0.5         # allowance, in standard deviations of the normal residual


HAI_MARGIN = 1.2          # alarm threshold = 1.2 x the largest CUSUM seen in normal training data


HAI_MERGE = 60            # alarms closer than this many seconds are one alarm event


HAI_RECOVERY = 600        # seconds after an attack ends while the process settles (not counted as false alarms)


HAI_REPLAY_K = 8          # readings in a window for the exact-replay check


# Loading and a tiny least-squares solver (standard library only)
class HaiDataError(ValueError):
    """A HAI file that cannot be used, with a message that says what is wrong and how to fix it."""


def hai_load(path: str) -> tuple[dict[str, list[float]], list[int], list[str]]:
    with open(path, newline="") as f:
        reader = csv.reader(f)
        head = next(reader, None)
        if not head:
            raise HaiDataError(f"{path} is empty. Use a HAI 22.04 CSV file (train1.csv, test1.csv or test2.csv).")
        idx = {n.strip(): i for i, n in enumerate(head)}
        missing = [t for t in HAI_TAGS if t not in idx]
        if missing:
            raise HaiDataError(f"{path} is not a HAI 22.04 file: it has no column {', '.join(missing[:3])}"
                               f"{' and more' if len(missing) > 3 else ''}. Download HAI 22.04 from "
                               "https://github.com/icsdataset/hai (other versions use different columns).")
        cols = {t: [] for t in HAI_TAGS}
        label, stamp = [], []
        for line, row in enumerate(reader, start=2):
            if not row or not any(cell.strip() for cell in row):
                continue                         # blank line (e.g. an extra newline at the end): skip it
            try:
                for t in HAI_TAGS:
                    cols[t].append(float(row[idx[t]]))
                label.append(int(float(row[idx["Attack"]])) if "Attack" in idx else 0)
            except (ValueError, IndexError):
                raise HaiDataError(f"{path}, line {line}: a value is missing or not a number. "
                                   "The file may be damaged or only partly downloaded.") from None
            stamp.append(row[0])
    if not stamp:
        raise HaiDataError(f"{path} has a header but no data rows.")
    return cols, label, stamp


def hai_lstsq(X: list[list[float]], y: list[float]) -> list[float]:
    """Solve the normal equations (X'X) b = X'y by Gaussian elimination with a tiny ridge."""
    p = len(X[0])
    A = [[sum(r[i] * r[j] for r in X) + (1e-9 if i == j else 0.0) for j in range(p)] for i in range(p)]
    b = [sum(r[i] * v for r, v in zip(X, y)) for i in range(p)]
    for c in range(p):
        piv = max(range(c, p), key=lambda r: abs(A[r][c]))
        A[c], A[piv], b[c], b[piv] = A[piv], A[c], b[piv], b[c]
        for r in range(c + 1, p):
            f = A[r][c] / A[c][c]
            for k in range(c, p):
                A[r][k] -= f * A[c][k]
            b[r] -= f * b[c]
    coef = [0.0] * p
    for r in range(p - 1, -1, -1):
        coef[r] = (b[r] - sum(A[r][k] * coef[k] for k in range(r + 1, p))) / A[r][r]
    return coef


# The checks. Each one turns the data into a residual per second (None = not available).
def hai_features(d: dict[str, list[float]], name: str, t: int) -> tuple[list[float], float] | None:
    """Regressors and target for one check at second t."""
    if name == "mass balance":
        if t < HAI_WIN:
            return None
        w = range(t - HAI_WIN, t)
        x = [mean(d["P1_FT01Z"][i] for i in w), mean(d["P1_FT02Z"][i] for i in w),
             mean(d["P1_FT03Z"][i] for i in w), mean(d["P1_LCV01Z"][i] for i in w), 1.0]
        return x, d["P1_LIT01"][t] - d["P1_LIT01"][t - HAI_WIN]
    if t < 2:
        return None
    if name == "level controller":
        # Velocity-form PID with feed-forward: the change in valve command should follow the
        # change in error, the error itself, and the change in the outflow valve.
        e = lambda i: d["P1_B3004"][i] - d["P1_LIT01"][i]
        x = [e(t) - e(t - 1), e(t), d["P1_FCV03D"][t] - d["P1_FCV03D"][t - 1],
             d["P1_LCV01D"][t - 1], 1.0]
        return x, d["P1_LCV01D"][t] - d["P1_LCV01D"][t - 1]
    if name == "outflow controller":
        e = lambda i: d["P1_B3005"][i] - d["P1_FT03Z"][i]
        x = [e(t) - e(t - 1), e(t), d["P1_FCV03D"][t - 1], 1.0]
        return x, d["P1_FCV03D"][t] - d["P1_FCV03D"][t - 1]
    if name == "level valve tracking":
        x = [d["P1_LCV01Z"][t - 1], d["P1_LCV01D"][t - 1], d["P1_LCV01D"][t], 1.0]
        return x, d["P1_LCV01Z"][t]
    if name == "outflow valve tracking":
        x = [d["P1_FCV03Z"][t - 1], d["P1_FCV03D"][t - 1], d["P1_FCV03D"][t], 1.0]
        return x, d["P1_FCV03Z"][t]
    raise ValueError(name)


HAI_MODEL_CHECKS = ["mass balance", "level controller", "outflow controller",
                "level valve tracking", "outflow valve tracking"]


@dataclass
class HaiModelCheck:
    name: str
    coef: list[float] = field(default_factory=list)
    sd: float = 1.0
    h: float = 0.0          # CUSUM alarm threshold

    def residuals(self, d: dict[str, list[float]]) -> list[float | None]:
        n = len(d["P1_LIT01"])
        out: list[float | None] = []
        for t in range(n):
            f = hai_features(d, self.name, t)
            if f is None:
                out.append(None)
            else:
                x, y = f
                out.append((y - sum(c * v for c, v in zip(self.coef, x))) / self.sd)
        return out

    def fit(self, d: dict[str, list[float]], step: int = 3) -> None:
        rows = [hai_features(d, self.name, t) for t in range(0, len(d["P1_LIT01"]), step)]
        rows = [r for r in rows if r is not None]
        self.coef = hai_lstsq([x for x, _ in rows], [y for _, y in rows])
        raw = [y - sum(c * v for c, v in zip(self.coef, x)) for x, y in rows]
        self.sd = pstdev(raw) or 1.0
        self.h = HAI_MARGIN * max(hai_cusum(self.residuals(d)))


def hai_cusum(res: list[float | None]) -> list[float]:
    """Two-sided CUSUM (Page 1954; used for ICS by Urbina et al. 2016). Returns max(up, down) per second."""
    up = down = 0.0
    out = []
    for r in res:
        if r is not None:
            up = max(0.0, up + r - HAI_CUSUM_K)
            down = max(0.0, down - r - HAI_CUSUM_K)
        out.append(max(up, down))
    return out


def hai_setpoint_alarms(train: dict[str, list[float]], test: dict[str, list[float]]) -> list[bool]:
    """'Never seen before' values (the Nozomi-style learning idea): setpoint outside its normal range."""
    lim = {t: (min(train[t]), max(train[t])) for t in ("P1_B3004", "P1_B3005")}
    span = {t: hi - lo for t, (lo, hi) in lim.items()}
    return [any(not (lim[t][0] - 0.05 * span[t] <= test[t][i] <= lim[t][1] + 0.05 * span[t]) for t in lim)
            for i in range(len(test["P1_LIT01"]))]


def hai_replay_alarms(d: dict[str, list[float]]) -> list[bool]:
    """Exact repeat of an earlier window of readings (non-flat), on the level and outflow sensors."""
    out = [False] * len(d["P1_LIT01"])
    for tag in ("P1_LIT01", "P1_FT03Z"):
        v = d[tag]
        seen: set[tuple[float, ...]] = set()
        for t in range(2 * HAI_REPLAY_K, len(v)):
            old = tuple(v[t - 2 * HAI_REPLAY_K + 1: t - HAI_REPLAY_K + 1])
            if max(old) - min(old) > 0:
                seen.add(old)
            tail = tuple(v[t - HAI_REPLAY_K + 1: t + 1])
            if max(tail) - min(tail) > 0 and tail in seen:
                out[t] = True
    return out


# Scoring
def hai_events(flags: list[bool], merge: int = 0) -> list[tuple[int, int]]:
    """Turn per-second flags into (start, end) events, merging gaps shorter than `merge`."""
    ev: list[list[int]] = []
    for t, f in enumerate(flags):
        if not f:
            continue
        if ev and t - ev[-1][1] <= max(1, merge):
            ev[-1][1] = t
        else:
            ev.append([t, t])
    return [(a, b) for a, b in ev]


def hai_main(train_path: str = "data/hai/train1.csv", test_path: str = "data/hai/test1.csv") -> dict:
    """Run every real-data check on one HAI test file (thresholds learned from the training file only).
    Prints the results and also returns them (used by the website exporter)."""
    print(f"Loading {train_path} (normal only) and {test_path} (normal + attacks)...")
    train, train_label, _ = hai_load(train_path)
    test, label, stamp = hai_load(test_path)
    if any(train_label):
        print("Warning: the training file contains attack labels; thresholds may be too loose.")

    alarms: dict[str, list[bool]] = {}
    print("\nCalibrating on normal data only:")
    for name in HAI_MODEL_CHECKS:
        chk = HaiModelCheck(name)
        chk.fit(train)
        alarms[name] = [c > chk.h for c in hai_cusum(chk.residuals(test))]
        print(f"  {name:<24} CUSUM alarm threshold {chk.h:8.1f}")
    alarms["never-seen setpoint"] = hai_setpoint_alarms(train, test)
    # A check that already fires on normal training data cannot be trusted: switch it off.
    # (HAI values are rounded, so real readings sometimes repeat exactly; the simulator's never do.)
    train_replay = sum(hai_replay_alarms(train))
    if train_replay:
        print(f"  exact replay             SWITCHED OFF: fires on {train_replay} s of normal training data")
    else:
        alarms["exact replay"] = hai_replay_alarms(test)
        print("  exact replay             on (never fires on normal training data)")

    attack_events = hai_events([bool(x) for x in label])
    stem = test_path.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".csv")
    timetable = HAI_TIMETABLES.get(stem, {})
    names = list(timetable)
    if len(attack_events) != len(names):
        timetable = {}
        names = [f"attack {i + 1}" for i in range(len(attack_events))]

    any_alarm = [any(alarms[c][t] for c in alarms) for t in range(len(label))]
    print("\nPer attack event (detected = any alarm from its start to 60 s after it ends):")
    print(f"  {'ID':<6}{'Target':<58}{'Scope':<8}{'Detected':<10}{'Delay':<8}Checks that fired")
    hit_in = hit_all = n_in = 0
    rows = []
    for name, (s, e) in zip(names, attack_events):
        target, in_scope = timetable.get(name, ("(no timetable for this file)", True))
        fired = [c for c in alarms if any(alarms[c][s:e + 61])]
        first = next((t for t in range(s, min(len(label), e + 61)) if any_alarm[t]), None)
        det = first is not None
        rows.append({"id": name, "target": target, "in_scope": in_scope, "start": s, "end": e,
                     "detected": det, "delay": (first - s) if det else None, "checks": fired})
        hit_all += det
        n_in += in_scope
        hit_in += det and in_scope
        print(f"  {name:<6}{target:<58}{'tank' if in_scope else 'other':<8}{'yes' if det else 'no':<10}"
              f"{(str(first - s) + ' s') if det else '-':<8}{', '.join(fired) or '-'}")

    # False alarms: alarm events that start outside any attack window (+ recovery time).
    busy = [False] * len(label)
    for s, e in attack_events:
        for t in range(s, min(len(label), e + HAI_RECOVERY + 1)):
            busy[t] = True
    normal_hours = sum(not b for b in busy) / 3600
    print("\nFalse alarms (alarm events starting during normal operation):")
    total_fa = 0
    for c in alarms:
        fa = [ev for ev in hai_events(alarms[c], HAI_MERGE) if not busy[ev[0]]]
        total_fa += len(fa)
        print(f"  {c:<24} {len(fa):3d}")
    combined = [ev for ev in hai_events(any_alarm, HAI_MERGE) if not busy[ev[0]]]
    print(f"  {'all checks combined':<24} {len(combined):3d}  over {normal_hours:.1f} h "
          f"= {len(combined) / normal_hours:.2f} per hour")

    print("\nSummary")
    print(f"  Tank attacks detected:   {hit_in}/{n_in}")
    print(f"  All attacks detected:    {hit_all}/{len(attack_events)}")
    print(f"  False alarm events:      {len(combined)} in {normal_hours:.1f} h of normal operation")
    print("  Note: HAI has no labelled equipment faults, so FAULT-vs-ATTACK accuracy cannot be scored here.")

    # Tank level per minute (min / max), for drawing a whole day compactly.
    level = test["P1_LIT01"]
    minutes = [(min(level[i:i + 60]), max(level[i:i + 60])) for i in range(0, len(level), 60)]
    return {"file": stem, "start": stamp[0], "end": stamp[-1], "seconds": len(label),
            "attacks": rows, "alarms": hai_events(any_alarm, HAI_MERGE), "false_alarms": combined,
            "normal_hours": normal_hours, "tank_hit": hit_in, "tank_total": n_in,
            "all_hit": hit_all, "all_total": len(attack_events),
            "level_min": [round(a, 1) for a, _ in minutes], "level_max": [round(b, 1) for _, b in minutes]}
