"""Thresholds learned from healthy runs only (cached in learned_thresholds.json)."""

from __future__ import annotations

from dataclasses import replace

from .config import PROJECT_DIR, Config
from .detector import FaultOrAttackDetector
from .plant import TankSimulator


CACHE_ENTRIES = 8   # learned-threshold sets kept in the cache file
LEARNING_CODE = ("config", "scenarios", "plant", "detector", "learning")
LEARNED_FIELDS = ("flatline_ticks", "replay_match", "flat_runs_limit", "link_limit")


def learn_from_normal(cfg: Config, hours: int = 3) -> Config:
    """Learned thresholds, cached in learned_thresholds.json next to the project files.

    The cache key covers every plant/detector setting (except run length) plus a fingerprint of the
    code that learning depends on, so changing either the settings or the code re-learns automatically."""
    import hashlib
    import json
    import os
    from pathlib import Path

    settings = {k: v for k, v in cfg.__dict__.items() if k not in ("ticks", "inject_at", *LEARNED_FIELDS)}
    # Only the code that can change what is learned (editing a menu label or a chart must not re-learn).
    package = Path(__file__).parent
    code = b"".join((package / f"{m}.py").read_bytes() for m in LEARNING_CODE)
    key = hashlib.sha256(code + repr(sorted(settings.items())).encode()
                         + str(hours).encode()).hexdigest()[:16]
    # The tests point this at a temporary file so they never touch your own cache.
    cache_file = Path(os.environ.get("FOA_THRESHOLDS_CACHE") or PROJECT_DIR / "learned_thresholds.json")
    try:
        cache = json.loads(cache_file.read_text())
        if not isinstance(cache, dict):
            cache = {}
    except (OSError, ValueError):
        cache = {}
    if key in cache:
        return replace(cfg, **cache[key])
    learned = _learn_from_normal_uncached(cfg, hours)
    try:
        # Keep the few most recent entries, so switching between settings does not re-learn each time.
        cache.pop(key, None)
        cache[key] = {f: getattr(learned, f) for f in LEARNED_FIELDS}
        cache = dict(list(cache.items())[-CACHE_ENTRIES:])
        cache_file.write_text(json.dumps(cache, indent=1))
    except OSError:
        pass                                     # read-only folder: just learn again next time
    return learned


def _learn_from_normal_uncached(cfg: Config, hours: int = 3) -> Config:
    """Set the 'repeat' thresholds from healthy runs only, as the HAI validation does.

    Rounded sensors repeat themselves naturally, so the stuck-sensor and exact-replay checks must
    allow for the longest natural repeats. Uses seeds 9001+ so it never sees the evaluation seeds.
    """
    longest_flat = 0
    longest_repeat = 0
    most_freezes = 0
    lowest_link = 1.0
    for seed in range(9001, 9001 + hours):
        healthy = Config(**{**cfg.__dict__, "ticks": 3600, "inject_at": 3599})
        records = TankSimulator(healthy, None, "permanent", False, seed).run()
        sensor = [r.sensor for r in records]
        if cfg.control == "pid":
            # Lowest level-vs-valve correlation a healthy plant ever shows.
            watcher = FaultOrAttackDetector(healthy)
            for rec in records:
                watcher.h.append(rec)
                link = watcher._valve_link()
                if link is not None:
                    lowest_link = min(lowest_link, link)
        run = 1
        ends: list[int] = []
        for t, (a, b) in enumerate(zip(sensor, sensor[1:]), start=1):
            if a == b and a is not None:
                run += 1
            else:
                if run >= cfg.flat_short:
                    ends.append(t)
                run = 1
            longest_flat = max(longest_flat, run)
        # Most natural freezes (of flat_short or more) ever seen within one minute.
        for i, t in enumerate(ends):
            most_freezes = max(most_freezes, sum(1 for u in ends[i:] if u - t <= 60))
        # Longest window (with real movement in it) that repeats an earlier, non-overlapping window.
        k = cfg.replay_match
        while k <= 60:
            seen: set[tuple] = set()
            hit = False
            for t in range(2 * k, len(sensor) + 1):
                old = tuple(sensor[t - 2 * k: t - k])
                if None not in old:
                    seen.add(old)
                tail = tuple(sensor[t - k: t])
                if None not in tail and max(tail) - min(tail) >= 0.5 and tail in seen:
                    hit = True
                    break
            if not hit:
                break
            longest_repeat = max(longest_repeat, k)
            k += 1
    return replace(cfg, flatline_ticks=max(cfg.flatline_ticks, longest_flat + 2),
                   replay_match=max(cfg.replay_match, longest_repeat + 2),
                   flat_runs_limit=max(2, most_freezes + 1),
                   link_limit=(lowest_link - 0.35) if cfg.control == "pid" else -1.0)
