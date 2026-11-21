"""The animated live demo (and mystery mode) in a matplotlib window or a recorded GIF."""

from __future__ import annotations


from .detector import FaultOrAttackDetector, Verdict
from .evaluation import _verdict_ok
from .plant import Record, TankSimulator
from .plots import _load_matplotlib
from .scenarios import SCENARIOS


BANNER_COLORS = {"ATTACK": "#7b2cbf", "FAULT": "#a0522d", "UNKNOWN": "#e08e0b", "OK": "#2e8b57"}


def animate_live(sim: TankSimulator, records: list[Record], show: bool, save: str | None,
                 speed: float = 8.0, mystery: bool = False) -> None:
    """Animated, stage-ready demo.

    Left: the tank, with the REAL water level and where sensor A CLAIMS it is.
    Right, top: both levels over time, with the attack/fault period shaded and the verdict marked.
    Right, bottom: what the control room sees right now.
    Top: the detector's banner, which turns into FAULT or ATTACK the moment it decides.
    With mystery=True the scenario's name stays hidden until the detector has decided.
    """
    plt = _load_matplotlib(show)
    import textwrap
    from matplotlib.animation import FuncAnimation, PillowWriter
    from matplotlib.patches import Rectangle

    cfg = sim.cfg
    info = SCENARIOS.get(sim.fault) if sim.fault else None
    det = FaultOrAttackDetector(cfg)
    now = [det.observe(r) for r in records]           # the detector's view at each second
    firm: list[Verdict | None] = []                     # the first firm verdict, once reached
    for v in now:
        prev = firm[-1] if firm else None
        firm.append(prev or (v if v is not None and v.label != "UNKNOWN" else None))
    first = firm[-1]
    first_device = next((r.tick for r in records if r.new_devices), None)

    fig = plt.figure(figsize=(13, 7.5))
    grid = fig.add_gridspec(3, 2, height_ratios=[1.35, 2.6, 1.6], width_ratios=[1, 2.4],
                            hspace=0.35, wspace=0.18, left=0.04, right=0.97, top=0.97, bottom=0.04)
    ax_ban = fig.add_subplot(grid[0, :])
    ax_tank = fig.add_subplot(grid[1:, 0])
    ax_lvl = fig.add_subplot(grid[1, 1])
    ax_txt = fig.add_subplot(grid[2, 1])

    # --- banner ---
    ax_ban.axis("off")
    ban_box = Rectangle((0, 0), 1, 1, transform=ax_ban.transAxes, color=BANNER_COLORS["OK"], zorder=0)
    ax_ban.add_patch(ban_box)
    ban_title = ax_ban.text(0.5, 0.78, "", ha="center", va="center", fontsize=22, weight="bold",
                            color="white", transform=ax_ban.transAxes)
    ban_reason = ax_ban.text(0.5, 0.45, "", ha="center", va="center", fontsize=11,
                             color="white", transform=ax_ban.transAxes)
    ban_scene = ax_ban.text(0.5, 0.12, "", ha="center", va="center", fontsize=11, style="italic",
                            color="white", transform=ax_ban.transAxes)

    # --- tank ---
    ax_tank.set_xlim(0, 1)
    ax_tank.set_ylim(-14, 108)
    ax_tank.axis("off")
    ax_tank.set_title("The tank", fontsize=12)
    ax_tank.add_patch(Rectangle((0.2, 0), 0.6, 100, fill=False, linewidth=3, color="#333"))
    water = Rectangle((0.2, 0), 0.6, 0, color="tab:blue", alpha=0.55)
    ax_tank.add_patch(water)
    for y, name in ((cfg.high_alarm, "high alarm"), (cfg.low_alarm, "low alarm")):
        ax_tank.plot([0.2, 0.8], [y, y], ":", color="gray", linewidth=1)
        ax_tank.text(0.22, y + 0.8, name, fontsize=8, va="bottom", color="gray")
    sensor_line, = ax_tank.plot([0.12, 0.88], [0, 0], "--", color="crimson", linewidth=2.5)
    # Sensor label on the right, real-level label on the left, so they never sit on top of each other.
    sensor_lbl = ax_tank.text(0.78, 0, "", ha="right", va="bottom", fontsize=10, color="crimson", weight="bold")
    real_lbl = ax_tank.text(0.22, 0, "", ha="left", va="top", fontsize=10, color="navy", weight="bold")
    pump_lbl = ax_tank.text(0.5, -7, "", ha="center", va="center", fontsize=11, weight="bold")

    # --- level chart ---
    t_all = [r.tick for r in records]
    ax_lvl.set_xlim(0, t_all[-1])
    ax_lvl.set_ylim(-3, 103)
    ax_lvl.set_ylabel("Level (%)")
    ax_lvl.set_xlabel("Time (s)")
    ax_lvl.axhline(cfg.high_alarm, color="gray", linestyle=":", linewidth=1)
    ax_lvl.axhline(cfg.low_alarm, color="gray", linestyle=":", linewidth=1)
    real_plot, = ax_lvl.plot([], [], color="tab:blue", linewidth=2.2, label="Real level (hidden from control room)")
    sens_plot, = ax_lvl.plot([], [], "--", color="crimson", linewidth=1.4, label="Sensor A as reported")
    verdict_line = ax_lvl.axvline(0, color="black", linestyle="-.", linewidth=1.8, visible=False)
    ax_lvl.legend(loc="upper left", fontsize=9)
    # Red shading for each period the fault/attack is on; it grows as time passes.
    segments, start = [], None
    for r in records:
        if r.fault_active and start is None:
            start = r.tick
        if not r.fault_active and start is not None:
            segments.append((start, r.tick))
            start = None
    if start is not None:
        segments.append((start, t_all[-1]))
    spans = [ax_lvl.add_patch(Rectangle((s, -3), 0, 106, facecolor="tab:red", alpha=0.10, linewidth=0))
             for s, _ in segments]

    # --- control room panel ---
    ax_txt.axis("off")
    panel = ax_txt.text(0.0, 1.0, "", va="top", ha="left", family="monospace", fontsize=10,
                        transform=ax_txt.transAxes)

    def scenario_line(t: int) -> str:
        if info is None:
            return "Scenario: healthy plant"
        if mystery and firm[t] is None:
            return "Scenario: ??? Fault or attack? Watch the detector decide."
        if mystery:
            right = "RIGHT" if _verdict_ok(sim.fault, first, cfg) else "WRONG"
            return f"Revealed: it was {info.name} ({info.kind}). The detector was {right}."
        if t < cfg.inject_at:
            return f"{info.name} ({info.kind}) starts in {cfg.inject_at - t} s"
        return f"{info.name} ({info.kind}) started at second {cfg.inject_at}"

    def draw(i: int):
        t = min(i, len(records) - 1)                    # extra frames hold the last picture
        r = records[t]

        # banner
        v_firm, v_now = firm[t], now[t]
        if v_firm is not None:
            key, title = v_firm.label, f"{v_firm.label}: {v_firm.culprit}"
            reason = v_firm.reason
        elif v_now is not None:
            key, title, reason = "UNKNOWN", "ALARM: investigating...", v_now.reason
        else:
            key, title, reason = "OK", "Detector: everything looks normal", ""
        ban_box.set_color(BANNER_COLORS[key])
        ban_title.set_text(title)
        ban_reason.set_text("\n".join(textwrap.wrap(reason, 130)[:2]))
        ban_scene.set_text(f"{scenario_line(t)}   |   second {t}")

        # tank
        water.set_height(r.level)
        real_lbl.set_text(f"real {r.level:.0f}%")
        real_lbl.set_y(max(r.level - 1, 6))
        if r.sensor is None:
            sensor_line.set_visible(False)
            sensor_lbl.set_text("sensor A: NO SIGNAL")
            sensor_lbl.set_y(102)
        else:
            sensor_line.set_visible(True)
            sensor_line.set_ydata([r.sensor, r.sensor])
            sensor_lbl.set_text(f"sensor A says {r.sensor:.0f}%")
            sensor_lbl.set_y(r.sensor + 1)
        cmd = "ON" if r.pump_cmd else "OFF"
        if r.valve_cmd is not None:
            # PID mode: show the supply valve, and flag it when the real valve is not where it reports.
            if not r.pump_flow and r.power_ok:
                pump_lbl.set_text("Pump STOPPED\n(valve " + f"{r.valve_real:.0f}%)")
                pump_lbl.set_color("crimson")
            elif abs(r.valve_real - r.valve_pos) > 5:
                pump_lbl.set_text(f"Valve really {r.valve_real:.0f}% open\n(reports {r.valve_pos:.0f}%)")
                pump_lbl.set_color("crimson")
            else:
                pump_lbl.set_text(f"Valve {r.valve_real:.0f}% open" + ("  (probe)" if r.probe else ""))
                pump_lbl.set_color("black")
        elif r.pump_flow == r.pump_cmd:
            pump_lbl.set_text(f"Pump {cmd}")
            pump_lbl.set_color("black")
        else:
            pump_lbl.set_text(f"Pump really {'ON' if r.pump_flow else 'OFF'}\n(controller said {cmd})")
            pump_lbl.set_color("crimson")

        # level chart
        upto = records[:t + 1]
        real_plot.set_data(t_all[:t + 1], [x.level for x in upto])
        sens_plot.set_data(t_all[:t + 1], [x.sensor if x.sensor is not None else float("nan") for x in upto])
        for patch, (s, e) in zip(spans, segments):
            patch.set_width(max(0, min(t, e) - s))
        if v_firm is not None:
            verdict_line.set_xdata([v_firm.tick, v_firm.tick])
            verdict_line.set_color(BANNER_COLORS[v_firm.label])
            verdict_line.set_visible(True)

        # control room panel
        def fmt(x, unit="%"):
            return "no signal" if x is None else f"{x:5.1f}{unit}"
        device = (f"NEW DEVICE (s {first_device})" if first_device is not None and first_device <= t
                  else "no new devices")
        action = textwrap.shorten(firm[t].action, 66) if firm[t] else "-"
        if r.valve_cmd is not None:
            actuator = (f"  Valve command     {r.valve_cmd:5.1f}%   reported position {r.valve_pos:5.1f}%"
                        f"{'   << probe' if r.probe else ''}\n")
        else:
            actuator = (f"  Pump command      {cmd:<6}   motor feedback  {'ON' if r.pump_feedback else 'OFF'}"
                        f"{'   << secret probe' if r.probe else ''}\n")
        panel.set_text(
            "WHAT THE CONTROL ROOM SEES\n"
            f"  Sensor A          {fmt(r.sensor)}\n"
            f"  Backup sensor B   {fmt(r.sensor_b) if sim.backup_sensor else 'not fitted'}\n"
            + actuator +
            f"  Outflow meter     {fmt(r.outflow, '%/s')}\n"
            f"  Network           {r.packets:4d} pkt/s  unknown writes {r.unknown_writes}  {device}\n"
            f"  Screen alarm      {r.screen_alarm or 'none'}\n"
            f"  Next step         {action}"
        )
        return moving

    # Everything that changes from frame to frame. Blitting redraws only these, not the axes,
    # ticks and labels, which keeps the live window smooth.
    moving = [ban_box, ban_title, ban_reason, ban_scene, water, sensor_line, sensor_lbl, real_lbl, pump_lbl,
              real_plot, sens_plot, verdict_line, panel, *spans]
    for artist in moving:
        artist.set_animated(True)

    hold = int(speed * 3) if save else 0                # keep the final frame on screen in a recording
    anim = FuncAnimation(fig, draw, frames=len(records) + hold, interval=1000 / speed,
                         init_func=lambda: moving, repeat=False, blit=True)
    if save:
        frames = len(records) + hold
        print(f"Recording {frames} frames to {save}. This can take a minute or two...")
        anim.save(save, writer=PillowWriter(fps=speed), dpi=80,
                  progress_callback=lambda i, n: print(f"  {i + 1}/{n} frames", end="\r") if i % 20 == 0 else None)
        print(f"Saved animation to {save}          ")
    if show:
        plt.show()
    plt.close(fig)
