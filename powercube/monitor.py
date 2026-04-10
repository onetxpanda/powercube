#!/usr/bin/env python3
"""
monitor.py — Live Rich dashboard for the Segway PowerCube.

Continuously polls all primary data and displays it in organized panels
with sparkline power graphs and cell-voltage balance visualization.

Usage:
    python3 -m powercube.monitor --address <UUID>
    python3 -m powercube.monitor                   # reads POWERCUBE_ADDRESS env var
"""

import argparse
import asyncio
import collections
import contextlib
import os
import time
from datetime import datetime

from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .client import PowerCube, PowerCubeError

# ── Tuning ────────────────────────────────────────────────────────────────────

FAST_POLL_S = 3.0    # status, temps, ports, errors
BMS_POLL_S  = 20.0   # BMS data (many BLE round-trips per module)
RECONNECT_S = 5.0
HIST_LEN    = 80     # sparkline history depth (80 × 3s ≈ 4 min)
UI_HZ       = 2      # Rich live refresh rate

# ── Unicode helpers ───────────────────────────────────────────────────────────

_SPARK = " ▁▂▃▄▅▆▇█"

# Cell balance thresholds (mV)
_CELL_WARN_MV  = 50   # yellow warning
_CELL_ALERT_MV = 150  # red alert


def _f(c: int | float) -> int:
    """Convert Celsius to Fahrenheit, rounded to nearest integer."""
    return round(c * 9 / 5 + 32)


def _sparkline(values, width: int = 44, vmin: float = 0.0, vmax: float | None = None) -> str:
    """Render a deque/list of floats as a fixed-width Unicode sparkline."""
    pts = list(values)[-width:]
    if not pts:
        return "─" * width
    hi = vmax if vmax is not None else max(pts)
    lo = vmin
    if hi <= lo:
        return "─" * width
    result = []
    for v in pts:
        idx = int((v - lo) / (hi - lo) * 8)
        result.append(_SPARK[max(0, min(8, idx))])
    # pad left with spaces if fewer points than width
    return " " * (width - len(result)) + "".join(result)


def _soc_bar(pct: int, width: int = 28) -> Text:
    filled = max(0, min(width, round(pct / 100 * width)))
    empty  = width - filled
    color  = "green" if pct >= 60 else "yellow" if pct >= 25 else "red"
    t = Text()
    t.append("█" * filled, style=f"bold {color}")
    t.append("░" * empty,  style="bright_black")
    return t


def _flag(on: bool, on_text: str = "ON", off_text: str = "off") -> Text:
    t = Text()
    t.append(on_text if on else off_text, style="bold green" if on else "dim")
    return t


# ── Shared state ──────────────────────────────────────────────────────────────

class _State:
    def __init__(self):
        self.connected   = False
        self.error_msg   = None
        self.last_update = None
        # One-time data
        self.device_info = None
        self.settings    = None
        # Fast-poll data
        self.status      = None
        self.temps       = None
        self.output      = None
        self.errors      = None
        # Slow-poll data
        self.bms: list[dict] = []
        # Sparkline history — total
        self.hist_in  = collections.deque(maxlen=HIST_LEN)
        self.hist_out = collections.deque(maxlen=HIST_LEN)
        # Per-source power history
        # AC in  = input_power_w when is_charging, else 0
        # DC in  = input_power_w when not is_charging (PV/DC charger), else 0
        # AC out = output_info["ac"]["power_w"]
        # DC out = output_info["dc"]["power_w"]
        self.hist_ac_in  = collections.deque(maxlen=HIST_LEN)
        self.hist_ac_out = collections.deque(maxlen=HIST_LEN)
        self.hist_dc_in  = collections.deque(maxlen=HIST_LEN)
        self.hist_dc_out = collections.deque(maxlen=HIST_LEN)


# ── Renderers ─────────────────────────────────────────────────────────────────

def _render_header(s: _State) -> Table:
    table = Table.grid(padding=(0, 2), expand=True)
    table.add_column(ratio=1)   # left: serial + status
    table.add_column(ratio=1)   # right: fw + timestamp

    serial = (s.device_info or {}).get("serial", "PowerCube")
    left = Text()
    left.append(f" {serial} ", style="bold white")
    if s.connected:
        left.append("  ● Connected", style="bold green")
    else:
        left.append("  ● Disconnected", style="bold red")
        if s.error_msg:
            msg = s.error_msg if len(s.error_msg) <= 60 else s.error_msg[:57] + "…"
            left.append(f"  {msg}", style="dim red")

    right = Text(justify="right")
    if s.device_info:
        d = s.device_info
        right.append(
            f"MCU {d.get('mcu_fw','?')}  BLE {d.get('ble_fw','?')}  PV {d.get('pv_fw','?')}  ",
            style="dim",
        )
    if s.last_update:
        age = time.time() - s.last_update
        ts  = datetime.fromtimestamp(s.last_update).strftime("%H:%M:%S")
        right.append(f"Updated {ts}", style="dim")
        if age > FAST_POLL_S * 3:
            right.append(f"  ({age:.0f}s stale)", style="bold red")

    table.add_row(left, right)
    return table


def _render_energy(s: _State) -> Panel:
    st = s.status or {}
    soc       = st.get("soc_pct")
    cap_wh    = st.get("capacity_wh")
    in_w      = st.get("input_power_w",  0)
    out_w     = st.get("output_power_w", 0)
    rem_min   = st.get("remain_time_min")
    is_chg    = st.get("is_charging",    False)
    ac_out    = st.get("ac_output",      False)
    dc_out    = st.get("dc_output",      False)
    temp_c    = st.get("temp_c")

    # Compute a reasonable Y-ceiling for power sparklines.
    max_in  = max(max(s.hist_in,  default=0), in_w,  200)
    max_out = max(max(s.hist_out, default=0), out_w, 200)

    lines: list[Text | str] = []

    # ── SOC bar ──
    if soc is not None:
        bar = _soc_bar(soc)
        row = Text("  ")
        row.append_text(bar)
        row.append(f"  {soc:3d}%", style="bold")
        if cap_wh is not None:
            row.append(f"  {cap_wh:,} Wh", style="bold")
        if rem_min is not None:
            h, m = divmod(rem_min, 60)
            row.append(f"  →  {h}h {m:02d}m remain", style="dim")
        lines.append(row)
    else:
        lines.append(Text("  SOC: --", style="bright_black"))

    # ── Power sparklines ──
    sp_in  = _sparkline(s.hist_in,  vmin=0, vmax=max_in)
    sp_out = _sparkline(s.hist_out, vmin=0, vmax=max_out)

    in_row = Text(f"  Input   {in_w:>5} W  ", style="cyan")
    in_row.append(sp_in, style="cyan")
    out_row = Text(f"  Output  {out_w:>5} W  ", style="magenta")
    out_row.append(sp_out, style="magenta")
    lines += [in_row, out_row]

    # ── Status flags ──
    flags = Text("  ")
    flags.append("AC charge: "); flags.append_text(_flag(is_chg)); flags.append("   ")
    flags.append("AC out: ");    flags.append_text(_flag(ac_out)); flags.append("   ")
    flags.append("DC out: ");    flags.append_text(_flag(dc_out))
    if temp_c is not None:
        color = "red" if temp_c > 45 else "yellow" if temp_c > 35 else "default"
        flags.append(f"   MCU temp: ")
        flags.append(f"{_f(temp_c)}°F", style=f"bold {color}" if color != "default" else "bold")
    lines.append(flags)

    title = "[bold]Energy[/bold]"
    if is_chg:
        title += "  [bold green]⚡ Charging[/bold green]"
    return Panel(Group(*lines), title=title, box=box.ROUNDED, padding=(0, 0))


def _render_bms_panel(b: dict | None, bms_num: int) -> Panel:
    if b is None:
        return Panel(
            Text("  No data yet…", style="bright_black"),
            title=f"[bold]BMS {bms_num}[/bold]",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    grid = Table.grid(padding=(0, 2))
    grid.add_column()
    grid.add_column()

    # Voltage + current
    v_mv = b.get("pack_voltage_mv", 0)
    i_ma = b.get("current_ma", 0)
    grid.add_row(
        Text(f"{v_mv / 1000:.3f} V", style="bold yellow"),
        Text(f"{i_ma:>5} mA", style="dim"),
    )

    # Cell voltage summary + balance warning if delta is significant
    cells = b.get("cell_voltages_mv", [])
    if cells:
        vmin, vmax = min(cells), max(cells)
        delta = vmax - vmin
        cell_row = Text()
        cell_row.append(f"{vmin}–{vmax} mV  Δ{delta} mV", style="dim")
        if delta >= _CELL_ALERT_MV:
            cell_row.append(f"  ⚠ CELL IMBALANCE", style="bold red")
        elif delta >= _CELL_WARN_MV:
            cell_row.append(f"  ⚠ balance warning", style="bold yellow")
        grid.add_row(cell_row, "")

    # Cell temperatures
    cell_temps = [t for t in b.get("cell_temps_c", []) if t != 0]
    if cell_temps:
        t_lo, t_hi = min(cell_temps), max(cell_temps)
        t_color = "red" if t_hi > 45 else "yellow" if t_hi > 35 else "green"
        grid.add_row(
            Text(f"Cells: {_f(t_lo)}–{_f(t_hi)}°F", style=t_color),
            Text(f"Cycles: {b.get('cycle_count', '?')}", style="dim"),
        )

    # Design capacity & lifetime stats
    full_mah  = b.get("full_cap_mah", 0)
    energy_wh = b.get("energy_through_wh", 0)
    grid.add_row(
        Text(f"Design: {full_mah / 1000:.0f} Ah", style="dim"),
        Text(f"Life:   {energy_wh:,} Wh", style="dim"),
    )

    fw   = b.get("fw_ver", "?")
    deep = b.get("deep_discharge", "?")
    mfg  = b.get("mfg_raw", "")
    grid.add_row(
        Text(f"FW {fw}  Mfg {mfg}", style="dim"),
        Text(f"Deep disch: {deep}", style="dim"),
    )

    return Panel(grid, title=f"[bold]BMS {bms_num}[/bold]", box=box.ROUNDED, padding=(0, 1))


# Fixed dimensions for power graph panels — never change with data state
_GRAPH_ROWS  = 5   # bar chart height in text rows
_GRAPH_COLS  = 38  # width of each bar series in characters
_GRAPH_BLOCKS = " ▁▂▃▄▅▆▇█"


def _bar_graph_rows(values, width: int, height: int, vmax: float) -> list[str]:
    """
    Render a fixed-size vertical bar chart as `height` strings of `width` chars.
    Row 0 is the top of the chart. Empty/missing data renders as spaces (same size).
    """
    pts = list(values)[-width:]
    rows = []
    for row_idx in range(height):
        row_top    = (height - row_idx)     / height * vmax
        row_bottom = (height - row_idx - 1) / height * vmax
        chars = []
        for v in pts:
            if v >= row_top:
                chars.append("█")
            elif v > row_bottom:
                frac = (v - row_bottom) / (row_top - row_bottom)
                chars.append(_GRAPH_BLOCKS[max(1, min(8, round(frac * 8)))])
            else:
                chars.append(" ")
        rows.append(" " * (width - len(chars)) + "".join(chars))
    return rows


def _render_power_panel(
    title: str,
    in_label: str,
    out_label: str,
    hist_in,
    hist_out,
    cur_in: float,
    cur_out: float,
) -> Panel:
    """
    Fixed-height power panel: two bar-chart series side by side (In | Out).
    Height is always _GRAPH_ROWS + 1 (header) lines regardless of data state.
    """
    peak = max(max(hist_in, default=0), max(hist_out, default=0), cur_in, cur_out, 100)

    in_rows  = _bar_graph_rows(hist_in,  _GRAPH_COLS, _GRAPH_ROWS, peak)
    out_rows = _bar_graph_rows(hist_out, _GRAPH_COLS, _GRAPH_ROWS, peak)

    # Header line: label + current value for each series
    hdr = Text("  ")
    hdr.append(f"{in_label} ", style="dim")
    hdr.append(f"{cur_in:>5.0f} W", style="bold cyan")
    hdr.append("    ")
    hdr.append(f"{out_label} ", style="dim")
    hdr.append(f"{cur_out:>5.0f} W", style="bold magenta")

    lines: list = [hdr]
    for in_str, out_str in zip(in_rows, out_rows):
        row = Text("  ")
        row.append(in_str,  style="cyan")
        row.append("    ")
        row.append(out_str, style="magenta")
        lines.append(row)

    return Panel(Group(*lines), title=f"[bold]{title}[/bold]", box=box.ROUNDED, padding=(0, 0))




_TEMP_LABELS = {
    "mcu":        "MCU",
    "mcu_2":      "MCU 2",
    "bms":        "BMS",
    "bms_2":      "BMS 2",
    "ac_inv":     "AC Inv",
    "ac_inv_2":   "AC Inv 2",
    "dc_conv":    "DC Conv",
    "dc_conv_2":  "DC Conv 2",
    "pv_input":   "PV In",
    "pv_input_2": "PV In 2",
}


def _render_temps(s: _State) -> Panel:
    temps = s.temps or {}
    items = list(temps.items())

    # 5 sensors per row; each cell: "Label: XX°C"
    cols = 5
    table = Table.grid(padding=(0, 3), expand=True)
    for _ in range(cols):
        table.add_column(ratio=1)

    def _cell(name: str, val: int) -> Text:
        label = _TEMP_LABELS.get(name, name.replace("_", " "))
        color = "red" if val > 50 else "yellow" if val > 40 else "green" if val > 0 else "bright_black"
        t = Text()
        t.append(f"{label}: ", style="dim")
        t.append(f"{_f(val)}°F", style=f"bold {color}" if val != 0 else "bright_black")
        return t

    for row_start in range(0, len(items), cols):
        chunk = items[row_start: row_start + cols]
        cells = [_cell(n, v) for n, v in chunk]
        # pad to full row width
        while len(cells) < cols:
            cells.append(Text())
        table.add_row(*cells)

    return Panel(table, title="[bold]Temperatures[/bold]", box=box.ROUNDED, padding=(0, 1))


def _render_system(s: _State) -> Panel:
    st  = s.settings or {}
    err = s.errors   or {}

    table = Table.grid(padding=(0, 3))
    table.add_column()
    table.add_column()

    # ── Settings flags ──
    flags = Text()
    flags.append("UPS ");         flags.append_text(_flag(st.get("ups_mode", False)));     flags.append("  ")
    flags.append("Super Pwr ");   flags.append_text(_flag(st.get("super_power_drive", False))); flags.append("  ")
    flags.append("Key Tone ");    flags.append_text(_flag(st.get("key_tone", False)));    flags.append("  ")
    flags.append("Fan Low ");     flags.append_text(_flag(st.get("fan_low_startup", False))); flags.append("  ")
    freq = st.get("frequency_hz", "?")
    flags.append(f"Freq ");
    flags.append(f"{freq} Hz", style="bold")
    flags.append("  ")
    limit = st.get("ac_input_limit_w")
    if limit:
        flags.append(f"AC limit ")
        flags.append(f"{limit} W", style="bold")

    # ── Standby timers ──
    def _stby(minutes):
        return "off" if not minutes else f"{minutes} min"

    stby = Text(style="dim")
    stby.append("Standby — ")
    stby.append(f"AC: {_stby(st.get('ac_standby_min', 0))}  ")
    stby.append(f"DC: {_stby(st.get('dc_standby_min', 0))}  ")
    stby.append(f"Device: {_stby(st.get('device_standby_min', 0))}  ")
    stby.append(f"Screen: {_stby(st.get('screen_time_min', 0))}")

    # ── Errors / warnings ──
    active_errors = err.get("errors",   [])
    active_warns  = err.get("warnings", [])
    if active_errors or active_warns:
        err_text = Text()
        for e in active_errors:
            err_text.append(f"✖ {e}\n", style="bold red")
        for w in active_warns:
            err_text.append(f"⚠ {w}", style="bold yellow")
        table.add_row(flags, err_text)
    else:
        table.add_row(flags, Text("✓ No errors", style="dim green"))

    table.add_row(stby, "")

    return Panel(table, title="[bold]System[/bold]", box=box.ROUNDED, padding=(0, 1))


def _build_layout() -> Layout:
    """
    Create the fixed proportional layout skeleton (called once at startup).

    Terminal space is divided into ratio-based regions that always fill the
    screen — content never drives height.

    Column layout:
        header   (size=3)    — serial, connection status, firmware, timestamp
        upper    (ratio=5)   — left: energy/SOC   right: AC graph / DC graph
        bms_row  (ratio=3)   — BMS 1 (left half) | BMS 2 (right half)
        bottom   (ratio=2)   — left: temperatures  right: system/settings
    """
    root = Layout()
    root.split_column(
        Layout(name="header",  size=3),
        Layout(name="upper",   ratio=5),
        Layout(name="bms_row", ratio=3),
        Layout(name="bottom",  ratio=2),
    )
    root["upper"].split_row(
        Layout(name="energy", ratio=1),
        Layout(name="graphs", ratio=2),
    )
    root["graphs"].split_column(
        Layout(name="ac_power", ratio=1),
        Layout(name="dc_power", ratio=1),
    )
    root["bms_row"].split_row(
        Layout(name="bms1", ratio=1),
        Layout(name="bms2", ratio=1),
    )
    root["bottom"].split_row(
        Layout(name="temps",  ratio=2),
        Layout(name="system", ratio=1),
    )
    return root


def _update_layout(layout: Layout, s: _State) -> None:
    """Refresh all layout sections from current state (called each UI tick)."""
    layout["header"].update(
        Panel(_render_header(s), box=box.HORIZONTALS, padding=(0, 1))
    )
    layout["energy"].update(_render_energy(s))

    st  = s.status or {}
    out = s.output or {}
    is_chg     = st.get("is_charging", False)
    in_w       = st.get("input_power_w", 0)
    cur_ac_in  = in_w if is_chg     else 0
    cur_dc_in  = in_w if not is_chg else 0
    cur_ac_out = out.get("ac", {}).get("power_w", 0)
    cur_dc_out = out.get("dc", {}).get("power_w", 0)

    layout["ac_power"].update(_render_power_panel(
        "AC Power", "Charging In", "AC Outlet Out",
        s.hist_ac_in, s.hist_ac_out, cur_ac_in, cur_ac_out,
    ))
    layout["dc_power"].update(_render_power_panel(
        "DC Power", "DC/PV In   ", "DC 12V Out",
        s.hist_dc_in, s.hist_dc_out, cur_dc_in, cur_dc_out,
    ))

    for n, section in [(1, "bms1"), (2, "bms2")]:
        b = next((x for x in s.bms if x.get("bms_num") == n), None)
        layout[section].update(_render_bms_panel(b, n))

    layout["temps"].update(_render_temps(s))
    layout["system"].update(_render_system(s))


# ── Polling task ──────────────────────────────────────────────────────────────

async def _poll_loop(address: str, ble_name: str, state: _State) -> None:
    bms_due = 0.0

    while True:
        try:
            async with PowerCube(address, ble_name=ble_name) as cube:
                state.connected = True
                state.error_msg = None

                # One-time reads on each fresh connection
                state.device_info = await cube.get_device_info()
                state.settings    = await cube.get_settings()

                while True:
                    # Fast-poll: primary status
                    state.status = await cube.get_status()
                    in_w   = state.status.get("input_power_w",  0)
                    out_w  = state.status.get("output_power_w", 0)
                    is_chg = state.status.get("is_charging",    False)
                    state.hist_in.append(in_w)
                    state.hist_out.append(out_w)

                    state.temps  = await cube.get_temperatures()
                    state.output = await cube.get_output_info()
                    state.errors = await cube.get_errors()

                    # Per-source power history (needs output data)
                    ac_out_w = (state.output or {}).get("ac", {}).get("power_w", 0)
                    dc_out_w = (state.output or {}).get("dc", {}).get("power_w", 0)
                    state.hist_ac_in.append(in_w if is_chg else 0)
                    state.hist_dc_in.append(in_w if not is_chg else 0)
                    state.hist_ac_out.append(ac_out_w)
                    state.hist_dc_out.append(dc_out_w)
                    state.last_update = time.time()

                    # Slow-poll: BMS (many registers, throttled)
                    if time.time() >= bms_due:
                        bms_count = state.device_info.get("bms_count", 2)
                        bms_list: list[dict] = []
                        for n in range(1, min(bms_count + 1, 6)):
                            try:
                                bms_list.append(await cube.get_bms_info(n))
                            except PowerCubeError:
                                pass
                        if bms_list:
                            state.bms = bms_list
                        bms_due = time.time() + BMS_POLL_S

                    await asyncio.sleep(FAST_POLL_S)

        except (PowerCubeError, Exception) as exc:
            state.connected = False
            state.error_msg = str(exc)[:100]
            await asyncio.sleep(RECONNECT_S)


# ── Entry point ───────────────────────────────────────────────────────────────

async def run_monitor(address: str, ble_name: str = "PowerCube") -> None:
    state  = _State()
    layout = _build_layout()
    _update_layout(layout, state)   # populate with empty-state placeholders

    poll_task = asyncio.create_task(_poll_loop(address, ble_name, state))

    with Live(layout, refresh_per_second=UI_HZ, screen=True, console=Console()):
        try:
            while True:
                _update_layout(layout, state)
                await asyncio.sleep(1 / UI_HZ)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            poll_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await poll_task


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Live PowerCube monitor — press Ctrl+C to quit",
    )
    parser.add_argument("--address",  metavar="UUID",
                        help="BLE device UUID (or set POWERCUBE_ADDRESS env var)")
    parser.add_argument("--ble-name", default="PowerCube", metavar="NAME",
                        help="BLE crypto key name (default: PowerCube)")
    args = parser.parse_args()

    address = args.address or os.environ.get("POWERCUBE_ADDRESS")
    if not address:
        parser.error("Provide --address <UUID> or set POWERCUBE_ADDRESS")

    try:
        asyncio.run(run_monitor(address, args.ble_name))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
