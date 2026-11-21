"""Charts with matplotlib: single-run graphs, the overview grid and the accuracy dashboard."""

from __future__ import annotations


from .config import Config
from .detector import Verdict, diagnose
from .plant import Record, TankSimulator
from .scenarios import MODES, SCENARIOS


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


def _mark_verdict(ax, verdict: Verdict | None) -> None:
    if verdict is not None:
        color = "tab:purple" if verdict.label == "ATTACK" else "tab:brown"
        ax.axvline(verdict.tick, color=color, linestyle="-.", linewidth=1.5,
                   label=f"Verdict: {verdict.label}")


def plot_single(sim: TankSimulator, records: list[Record], show: bool, save: str | None) -> None:
    plt = _load_matplotlib(show)
    cfg = sim.cfg
    t = [r.tick for r in records]
    info = SCENARIOS.get(sim.fault) if sim.fault else None
    verdict, _ = diagnose(records, cfg)
    title = f"{info.name if info else 'Healthy'} ({sim.mode}, backup sensor {'on' if sim.backup_sensor else 'off'})"
    if verdict:
        title += f"\nDetector: {verdict.label} - {verdict.culprit}"

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 6), sharex=True, gridspec_kw={"height_ratios": [3, 1.5]})
    ax1.plot(t, [r.level for r in records], label="Real level", color="tab:blue", linewidth=2)
    ax1.plot(t, [r.sensor if r.sensor is not None else float("nan") for r in records],
             label="Sensor A as reported", color="black", linestyle="--", linewidth=1.2)
    ax1.axhline(cfg.high_alarm, color="gray", linestyle=":", linewidth=1)
    ax1.axhline(cfg.low_alarm, color="gray", linestyle=":", linewidth=1)
    _shade_fault(ax1, records)
    _mark_verdict(ax1, verdict)
    ax1.set_ylim(-3, 103)
    ax1.set_ylabel("Level (%)")
    ax1.set_title(title)
    ax1.legend(loc="upper right")

    ax2.plot(t, [r.duty * 100 for r in records], color="tab:orange", linewidth=2)
    ax2.axhline(50, color="gray", linestyle=":", linewidth=1)
    _shade_fault(ax2, records)
    _mark_verdict(ax2, verdict)
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
    rows = (len(SCENARIOS) + 1) // 2
    fig, axes = plt.subplots(rows, 2, figsize=(11, 2.6 * rows), sharex=True, sharey=True)
    for ax, (key, info) in zip(axes.flat, SCENARIOS.items()):
        verdict = None
        for backup, style, label in ((False, "-", "no backup"), (True, ":", "backup sensor")):
            recs = TankSimulator(cfg, key, mode, backup, seed).run()
            ax.plot([r.tick for r in recs], [r.level for r in recs], style,
                    linewidth=2, label=label, color="tab:blue" if not backup else "tab:green")
            if not backup:
                verdict, _ = diagnose(recs, cfg)
        _shade_fault(ax, recs)
        _mark_verdict(ax, verdict)
        ax.axhline(cfg.high_alarm, color="gray", linestyle=":", linewidth=1)
        ax.axhline(cfg.low_alarm, color="gray", linestyle=":", linewidth=1)
        call = f"{verdict.label}" if verdict else "no verdict"
        ax.set_title(f"{info.name} [{info.kind}] - detector says {call}", fontsize=9)
        ax.set_ylim(-3, 103)
    for ax in list(axes.flat)[len(SCENARIOS):]:
        ax.axis("off")
    axes[0][0].legend(loc="lower left", fontsize=8)
    fig.supxlabel("Time (s)")
    fig.supylabel("Real tank level (%)")
    fig.suptitle(f"Real tank level under each fault and attack (duration = {mode}; red = active)")
    fig.tight_layout()
    if save:
        fig.savefig(save, dpi=150)
        print(f"Saved plot to {save}")
    if show:
        plt.show()


# Dashboard colours (validated: blue/orange pass the colour-blind and contrast checks).
DASH = {
    "surface": "#fcfcfb", "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#8a8984", "grid": "#e4e3df",
    "simple": "#2a78d6", "realistic": "#eb6834", "baseline": "#b4b2a9",
    "ramp": ["#f2f7fd", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"],
}


def plot_dashboard(simple: dict, real: dict, show: bool, save: str | None) -> None:
    """One-page accuracy dashboard: headline numbers, accuracy per scenario on both plants,
    the comparison with trivial baselines, and where the mistakes go (confusion matrices)."""
    plt = _load_matplotlib(show)
    c = DASH
    # Style only this figure: rc_context restores matplotlib's defaults afterwards.
    with plt.rc_context({"font.size": 10, "axes.edgecolor": c["grid"], "axes.labelcolor": c["ink2"],
                         "xtick.color": c["ink2"], "ytick.color": c["ink"], "text.color": c["ink"]}):
        _draw_dashboard(plt, simple, real, show, save)


def _draw_dashboard(plt, simple: dict, real: dict, show: bool, save: str | None) -> None:
    from matplotlib.colors import LinearSegmentedColormap

    c = DASH
    fig = plt.figure(figsize=(15, 10), facecolor=c["surface"])
    grid = fig.add_gridspec(3, 3, height_ratios=[0.8, 3.3, 2.0], width_ratios=[1.25, 1.25, 1.0],
                            hspace=0.5, wspace=0.42, left=0.12, right=0.98, top=0.88, bottom=0.06)
    seeds = simple["seeds"]
    fig.suptitle("Fault or attack?  Detector accuracy", x=0.12, y=0.97, ha="left", fontsize=18, weight="bold")
    fig.text(0.12, 0.925, f"{seeds} random seed{'s' if seeds != 1 else ''} x {len(MODES)} durations (permanent, transient, intermittent) x "
             "backup sensor on/off, per scenario. Simulated plants; real-plant results come from --hai.",
             fontsize=10, color=c["ink2"])

    # --- headline tiles ---
    pct = lambda r: 100 * r["right"] / r["total"]
    hours = simple["hours"] + real["hours"]
    false_alarms = simple["long_alarms"] + real["long_alarms"] + simple["short_false"] + real["short_false"]
    tiles = [
        (f"{pct(simple):.1f}%", "correct on the simple plant", f"{simple['right']} of {simple['total']} runs"),
        (f"{pct(real):.1f}%", "correct on the realistic plant", f"{real['right']} of {real['total']} runs"),
        (f"{false_alarms}", "false alarms on healthy plants", f"over {hours} hours + {simple['short_runs'] * 2} short runs"),
        (f"{real['confusion']['FAULT']['ATTACK']}",
         "faults wrongly called attacks", f"realistic plant (simple: {simple['confusion']['FAULT']['ATTACK']})"),
    ]
    tile_grid = grid[0, :].subgridspec(1, 4, wspace=0.08)
    for i, (big, label, small) in enumerate(tiles):
        ax = fig.add_subplot(tile_grid[0, i])
        ax.set_facecolor("#f4f3f0")
        ax.set_xticks([]), ax.set_yticks([])
        for side in ax.spines.values():
            side.set_visible(False)
        ax.text(0.06, 0.62, big, fontsize=26, weight="bold", va="center", transform=ax.transAxes)
        ax.text(0.06, 0.28, label, fontsize=10.5, color=c["ink"], va="center", transform=ax.transAxes)
        ax.text(0.06, 0.1, small, fontsize=9, color=c["ink2"], va="center", transform=ax.transAxes)

    # --- accuracy per scenario, both plants ---
    ax = fig.add_subplot(grid[1, :2])
    rows = simple["scenarios"]
    real_by_key = {s["key"]: s for s in real["scenarios"]}
    # Faults first, then attacks, with a gap between the groups; top of the chart = first row.
    order = [s for s in rows if s["kind"] == "FAULT"] + [None] + [s for s in rows if s["kind"] == "ATTACK"]
    y, ylabels, ypos = len(order), [], []
    bar_h = 0.36
    for s in order:
        y -= 1
        if s is None:
            continue
        r = real_by_key[s["key"]]
        for value, offset, colour in ((100 * s["right"] / s["total"], bar_h / 2 + 0.02, c["simple"]),
                                      (100 * r["right"] / r["total"], -bar_h / 2 - 0.02, c["realistic"])):
            ax.barh(y + offset, value, height=bar_h, color=colour, edgecolor=c["surface"], linewidth=1)
            if value < 99.95:      # label only the bars that are not perfect
                ax.text(value + 1, y + offset, f"{value:.0f}%", va="center", fontsize=8.5, color=c["ink2"])
        ylabels.append(s["name"])
        ypos.append(y)
    ax.set_yticks(ypos, ylabels)
    # Group headings sit in their own rows (above the faults, and in the gap before the attacks).
    gap_y = len(order) - 1 - order.index(None)
    ax.text(0, len(order) - 0.35, "FAULTS", ha="left", va="center", fontsize=9, weight="bold", color=c["ink2"])
    ax.text(0, gap_y, "ATTACKS", ha="left", va="center", fontsize=9, weight="bold", color=c["ink2"])
    ax.set_ylim(-0.7, len(order) - 0.05)
    ax.set_xlim(0, 108)
    ax.set_xticks([0, 25, 50, 75, 100], ["0%", "25%", "50%", "75%", "100%"])
    ax.grid(axis="x", color=c["grid"], linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_facecolor(c["surface"])
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.set_title("Fault-vs-attack calls correct, per scenario", loc="left", fontsize=12, weight="bold", pad=24)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=c["simple"], label="Simple plant (on/off pump)"),
                       Patch(color=c["realistic"], label="Realistic plant (PID valve, like HAI)")],
              loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2, frameon=False, fontsize=9.5)
    ax.text(1.0, -0.13, "* smart attacker added after the detector was first tuned", transform=ax.transAxes,
            ha="right", va="top", fontsize=8.5, color=c["muted"])

    # --- versus trivial baselines ---
    ax = fig.add_subplot(grid[1, 2])
    bars = [("Coin flip", 50.0, c["baseline"]),
            ("Always say FAULT", 100 * simple["always_fault"], c["baseline"]),
            ("Always say ATTACK", 100 * simple["always_attack"], c["baseline"]),
            ("Detector, simple plant", pct(simple), c["simple"]),
            ("Detector, realistic plant", pct(real), c["realistic"])]
    for i, (label, value, colour) in enumerate(reversed(bars)):
        ax.barh(i, value, height=0.6, color=colour, edgecolor=c["surface"], linewidth=1)
        ax.text(value + 1.5, i, f"{value:.1f}%", va="center", fontsize=9, color=c["ink2"])
    ax.set_yticks(range(len(bars)), [b[0] for b in reversed(bars)])
    ax.set_xlim(0, 115)
    ax.set_xticks([0, 50, 100], ["0%", "50%", "100%"])
    ax.grid(axis="x", color=c["grid"], linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_facecolor(c["surface"])
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.set_title("Compared with trivial guesses", loc="left", fontsize=12, weight="bold", pad=24)

    # --- where the calls go: confusion matrices ---
    cmap = LinearSegmentedColormap.from_list("seq_blue", c["ramp"])
    cols = ("FAULT", "ATTACK", "UNKNOWN", "none")
    col_names = ("called\nFAULT", "called\nATTACK", "still\ninvestigating", "nothing\nfound")
    for i, (res, title) in enumerate(((simple, "Simple plant"), (real, "Realistic plant"))):
        ax = fig.add_subplot(grid[2, i])
        m = [[res["confusion"][kind][col] for col in cols] for kind in ("FAULT", "ATTACK")]
        top = max(max(row) for row in m) or 1
        ax.imshow(m, cmap=cmap, vmin=0, vmax=top, aspect="auto")
        for r_i, row in enumerate(m):
            for c_i, value in enumerate(row):
                dark = value > 0.55 * top
                ax.text(c_i, r_i, f"{value}", ha="center", va="center", fontsize=11,
                        weight="bold" if (r_i == 0 and c_i == 0) or (r_i == 1 and c_i == 1) else "normal",
                        color="white" if dark else c["ink"])
        ax.set_xticks(range(4), col_names, fontsize=8.5)
        ax.set_yticks([0, 1], ["truly FAULT", "truly ATTACK"])
        ax.tick_params(length=0)
        ax.set_xticks([x + 0.5 for x in range(3)], minor=True)
        ax.set_yticks([0.5], minor=True)
        ax.grid(which="minor", color=c["surface"], linewidth=2)
        for side in ax.spines.values():
            side.set_visible(False)
        ax.set_title(f"Where the calls go: {title.lower()}", loc="left", fontsize=12, weight="bold")

    # --- how to read it ---
    ax = fig.add_subplot(grid[2, 2])
    ax.axis("off")
    notes = (
        "How to read this\n\n"
        f"- Each scenario runs {seeds * len(MODES) * 2} ways. A call counts\n"
        "  only if it comes after the event starts.\n"
        "- Realistic plant: PID valve with lag,\n"
        "  rounded readings, wandering noise.\n"
        "- Thresholds learned from healthy runs only.\n"
        "- Bold diagonal = right calls. 'Still\n"
        "  investigating' = escalated, no verdict.\n"
        "- Known limit: an insider faking smooth\n"
        "  drift from a trusted device leaves no trace."
    )
    ax.text(0.0, 1.0, notes, va="top", fontsize=9.5, color=c["ink2"], linespacing=1.35)

    if save:
        fig.savefig(save, dpi=150, facecolor=c["surface"])
        print(f"Saved dashboard to {save}")
    if show:
        plt.show()
    plt.close(fig)
