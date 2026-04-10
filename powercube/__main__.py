"""
powercube CLI — entry point for `python3 -m powercube`.

Usage:
    python3 -m powercube --address <UUID> --status
    python3 -m powercube --scan
    python3 -m powercube --address <UUID> --pair
    python3 -m powercube --address <UUID> --bms
    python3 -m powercube --address <UUID> --temperatures
    python3 -m powercube --address <UUID> --settings
    python3 -m powercube --address <UUID> --device-info
    python3 -m powercube --address <UUID> --probe 0x41
    python3 -m powercube --address <UUID> --ac-on
    python3 -m powercube --address <UUID> --ac-off
    python3 -m powercube --address <UUID> --dc-on
    python3 -m powercube --address <UUID> --dc-off
"""

import argparse
import asyncio
import logging
import time


def _f(c: int | float) -> int:
    """Convert Celsius to Fahrenheit."""
    return round(c * 9 / 5 + 32)


async def _cli_main(args: argparse.Namespace) -> None:
    from .client import PowerCube, PowerCubeError, scan_for_powercube, find_device_address

    # ── scan ──────────────────────────────────────────────────────────────────
    if args.scan:
        print(f"Scanning for '{args.ble_name}' devices ({args.scan_timeout}s)...")
        devices = await scan_for_powercube(
            timeout=args.scan_timeout, ble_name=args.ble_name
        )
        if not devices:
            print("  No devices found.")
        else:
            for name, address in devices:
                print(f"  {address}  {name or '(unnamed)'}")
        return

    # ── resolve address ───────────────────────────────────────────────────────
    address = args.address
    if not address:
        print(f"Scanning for '{args.ble_name}'...")
        address = await find_device_address(args.ble_name, timeout=args.scan_timeout)
        if not address:
            print(f"No '{args.ble_name}' device found.")
            return
        print(f"Found: {address}")

    # ── pair ──────────────────────────────────────────────────────────────────
    if args.pair:
        async with PowerCube(
            address,
            ble_name=args.ble_name,
            timeout=args.timeout,
            on_pair_prompt=lambda msg: print(f"  → {msg}"),
        ) as cube:
            await cube.pair()
            print("Pairing complete.")
        return

    # ── all other commands require a live connection ──────────────────────────
    async with PowerCube(
        address,
        ble_name=args.ble_name,
        timeout=args.timeout,
        on_pair_prompt=lambda msg: print(f"  → {msg}"),
    ) as cube:

        # ── output control ────────────────────────────────────────────────────
        if args.ac_on:
            await cube.set_ac_output(True)
            print("AC output enabled.")

        if args.ac_off:
            await cube.set_ac_output(False)
            print("AC output disabled.")

        if args.dc_on:
            await cube.set_dc_output(True)
            print("DC output enabled.")

        if args.dc_off:
            await cube.set_dc_output(False)
            print("DC output disabled.")

        if args.ups_mode is not None:
            enable = args.ups_mode.lower() in ("on", "1", "true", "yes")
            await cube.set_ups_mode(enable)
            print(f"UPS mode {'enabled' if enable else 'disabled'}.")

        if args.super_power is not None:
            enable = args.super_power.lower() in ("on", "1", "true", "yes")
            await cube.set_super_power(enable)
            print(f"Super power drive {'enabled' if enable else 'disabled'}.")

        if args.key_tone is not None:
            enable = args.key_tone.lower() in ("on", "1", "true", "yes")
            await cube.set_key_tone(enable)
            print(f"Key tone {'enabled' if enable else 'disabled'}.")

        if args.fan_low is not None:
            enable = args.fan_low.lower() in ("on", "1", "true", "yes")
            await cube.set_fan_low_startup(enable)
            print(f"Fan low startup {'enabled' if enable else 'disabled'}.")

        if args.ac_standby is not None:
            await cube.set_ac_standby(args.ac_standby)
            print(f"AC standby set to {args.ac_standby} min.")

        if args.dc_standby is not None:
            await cube.set_dc_standby(args.dc_standby)
            print(f"DC standby set to {args.dc_standby} min.")

        if args.device_standby is not None:
            await cube.set_device_standby(args.device_standby)
            print(f"Device standby set to {args.device_standby} min.")

        if args.screen_time is not None:
            await cube.set_screen_time(args.screen_time)
            print(f"Screen timeout set to {args.screen_time} min.")

        if args.ac_limit is not None:
            await cube.set_ac_input_limit(args.ac_limit)
            print(f"AC input limit set to {args.ac_limit} W.")

        if args.ac_freq is not None:
            await cube.set_ac_frequency(args.ac_freq)
            print(f"AC frequency set to {args.ac_freq} Hz.")

        if args.sync_time:
            ts = int(time.time())
            await cube.set_unix_time(ts)
            print(f"Device clock synced to Unix timestamp {ts}.")

        # ── status ────────────────────────────────────────────────────────────
        if args.status:
            s = await cube.get_status()
            charging = "charging" if s["is_charging"] else "discharging"
            ac_state = "ON" if s["ac_output"] else "off"
            dc_state = "ON" if s["dc_output"] else "off"
            print(f"SOC:        {s['soc_pct']}%")
            print(f"Capacity:   {s['capacity_wh']} Wh")
            print(f"Temp (MCU): {_f(s['temp_c'])}°F")
            print(f"Input:      {s['input_power_w']} W  ({charging})")
            print(f"Output:     {s['output_power_w']} W")
            print(f"Remain:     {s['remain_time_min']} min")
            print(f"AC output:  {ac_state}   DC output: {dc_state}")

        # ── temperatures ──────────────────────────────────────────────────────
        if args.temperatures:
            temps = await cube.get_temperatures()
            print("Temperatures:")
            for name, val in temps.items():
                print(f"  {name:<20} {_f(val):>4}°F")

        # ── settings ──────────────────────────────────────────────────────────
        if args.settings:
            cfg = await cube.get_settings()
            print(f"AC input limit:    {cfg['ac_input_limit_w']} W")
            print(f"AC standby:        {cfg['ac_standby_min']} min")
            print(f"DC standby:        {cfg['dc_standby_min']} min")
            print(f"Device standby:    {cfg['device_standby_min']} min")
            print(f"Screen timeout:    {cfg['screen_time_min']} min")
            print(f"Frequency:         {cfg['frequency_hz']} Hz")
            print(f"UPS mode:          {'on' if cfg['ups_mode'] else 'off'}")
            print(f"Super power drive: {'on' if cfg['super_power_drive'] else 'off'}")
            print(f"Key tone:          {'on' if cfg['key_tone'] else 'off'}")
            print(f"Fan low startup:   {'on' if cfg['fan_low_startup'] else 'off'}")

        # ── device info ───────────────────────────────────────────────────────
        if args.device_info:
            info = await cube.get_device_info()
            print(f"Serial:     {info['serial']}")
            print(f"MCU FW:     {info['mcu_fw']}")
            print(f"BLE FW:     {info['ble_fw']}")
            print(f"PV FW:      {info['pv_fw']}")
            print(f"BMS count:  {info['bms_count']}")

        # ── BMS ───────────────────────────────────────────────────────────────
        if args.bms:
            info = await cube.get_device_info()
            bms_count = info["bms_count"]
            if bms_count == 0:
                print("No BMS modules detected.")
            for i in range(1, bms_count + 1):
                b = await cube.get_bms_info(i)
                pack_v = b["pack_voltage_mv"] / 1000
                cell_mv = b["cell_voltages_mv"]
                cell_min = min(cell_mv)
                cell_max = max(cell_mv)
                cell_delta = cell_max - cell_min
                temps_f = [_f(t) for t in b["cell_temps_c"]]
                print(f"\nBMS {i}:")
                print(f"  Pack voltage:    {pack_v:.3f} V")
                print(f"  Cell min/max:    {cell_min} / {cell_max} mV  (Δ{cell_delta} mV)")
                if cell_delta >= 150:
                    print(f"  !! CELL IMBALANCE: {cell_delta} mV delta")
                elif cell_delta >= 50:
                    print(f"  ! Cell delta elevated: {cell_delta} mV")
                print(f"  Current:         {b['current_ma']} mA")
                print(f"  Full capacity:   {b['full_cap_mah']} mAh")
                print(f"  Design cap:      {b['remain_cap_wh']} Wh")
                print(f"  Cycle count:     {b['cycle_count']}")
                print(f"  Deep discharge:  {b['deep_discharge']}")
                print(f"  Cell temps:      {', '.join(f'{t}°F' for t in temps_f)}")
                print(f"  Lifetime energy: {b['energy_through_wh']} Wh")
                print(f"  Lifetime cap:    {b['cap_through_mah']} mAh")
                print(f"  Extreme charge:  {b['extreme_charge_min']} min")
                print(f"  Extreme use:     {b['extreme_use_min']} min")
                print(f"  FW:              {b['fw_ver']}")
                print(f"  Mfg date (raw):  {b['mfg_raw']}")
                print(f"  Raw info hex:    {b['raw_info_hex']}")

        # ── errors ───────────────────────────────────────────────────────────
        if args.errors:
            e = await cube.get_errors()
            print(f"Error code:   0x{e['error_raw']:04x}")
            print(f"Warning code: 0x{e['warn_raw']:04x}")
            if e["errors"]:
                print("Errors:")
                for msg in e["errors"]:
                    print(f"  ! {msg}")
            else:
                print("Errors: none")
            if e["warnings"]:
                print("Warnings:")
                for msg in e["warnings"]:
                    print(f"  ~ {msg}")
            else:
                print("Warnings: none")

        # ── features ─────────────────────────────────────────────────────────
        if args.features:
            f = await cube.get_features()
            print(f"Frequency switch:  {'yes' if f['frequency_switch'] else 'no'}")
            print(f"Max AC input:      {f['max_ac_input_w'] or 'unknown'} W")
            print(f"AC standby:        {'yes' if f['ac_standby'] else 'no'}")
            print(f"DC standby:        {'yes' if f['dc_standby'] else 'no'}")
            print(f"Device standby:    {'yes' if f['device_standby'] else 'no'}")
            print(f"Screen timeout:    {'yes' if f['screen_timeout'] else 'no'}")
            print(f"Raw FunSupBool:    0x{f['raw']:04x}")

        # ── output info ───────────────────────────────────────────────────────
        if args.output_info:
            ports = await cube.get_output_info()
            print(f"{'Port':<10} {'Voltage':>8} {'Current':>9} {'Power':>8}")
            print("-" * 40)
            for port, vals in ports.items():
                print(
                    f"{port:<10} {vals['voltage_v']:>7.1f}V "
                    f"{vals['current_a']:>8.2f}A "
                    f"{vals['power_w']:>7.1f}W"
                )

        # ── probe ────────────────────────────────────────────────────────────
        if args.probe:
            dst = int(args.probe, 16)
            start = args.probe_start
            end   = args.probe_end
            nbytes = args.probe_bytes
            print(f"Probing module 0x{dst:02x} regs {start}–{end} ({nbytes}B each)...")
            results = await cube.probe_module(
                dst,
                reg_start=start,
                reg_end=end,
                n_bytes=nbytes,
                timeout=2.0,
            )
            for reg, data in sorted(results.items()):
                hex_str = data.hex()
                # Attempt uint16/uint32 decode
                if len(data) == 2:
                    u16 = int.from_bytes(data, "little")
                    i16 = u16 if u16 < 0x8000 else u16 - 0x10000
                    extra = f"  u16={u16}  i16={i16}"
                elif len(data) == 4:
                    u32 = int.from_bytes(data, "little")
                    extra = f"  u32={u32}"
                else:
                    extra = ""
                print(f"  reg {reg:>3d} (0x{reg:02x}): {hex_str}{extra}")


def main() -> None:
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    ap = argparse.ArgumentParser(
        prog="python3 -m powercube",
        description="Segway PowerCube BLE CLI",
    )

    # Connection
    ap.add_argument("--address",      help="BLE device UUID/MAC address")
    ap.add_argument("--ble-name",     default="PowerCube", dest="ble_name",
                    help="Device BLE name (default: PowerCube)")
    ap.add_argument("--timeout",      type=float, default=10.0,
                    help="BLE connection timeout in seconds (default: 10)")
    ap.add_argument("--scan-timeout", type=float, default=10.0, dest="scan_timeout",
                    help="BLE scan duration in seconds (default: 10)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Enable verbose logging")

    # Queries
    ap.add_argument("--scan",        action="store_true", help="Scan for PowerCube devices")
    ap.add_argument("--pair",        action="store_true", help="First-time pairing")
    ap.add_argument("--status",      action="store_true", help="Show device status")
    ap.add_argument("--bms",         action="store_true", help="Show BMS battery info")
    ap.add_argument("--temperatures",action="store_true", help="Show all temperature sensors")
    ap.add_argument("--settings",    action="store_true", help="Show device settings")
    ap.add_argument("--device-info", action="store_true", dest="device_info",
                    help="Show firmware versions and serial")
    ap.add_argument("--errors",      action="store_true", help="Show error and warning codes")
    ap.add_argument("--features",    action="store_true", help="Show supported feature flags")
    ap.add_argument("--output-info", action="store_true", dest="output_info",
                    help="Show per-port current/voltage/power")

    # Module probing
    ap.add_argument("--probe",       metavar="HEX_ADDR",
                    help="Probe all registers of module (e.g. 0x41 for BMS1)")
    ap.add_argument("--probe-start", type=int, default=0,  dest="probe_start",
                    help="First register to probe (default: 0)")
    ap.add_argument("--probe-end",   type=int, default=60, dest="probe_end",
                    help="Last register to probe (default: 60)")
    ap.add_argument("--probe-bytes", type=int, default=2,  dest="probe_bytes",
                    help="Bytes to read per register (default: 2)")

    # Output control
    ap.add_argument("--ac-on",  action="store_true", dest="ac_on",  help="Enable AC output")
    ap.add_argument("--ac-off", action="store_true", dest="ac_off", help="Disable AC output")
    ap.add_argument("--dc-on",  action="store_true", dest="dc_on",  help="Enable DC output")
    ap.add_argument("--dc-off", action="store_true", dest="dc_off", help="Disable DC output")

    # Mode flags (on/off/1/0/true/false/yes/no)
    ap.add_argument("--ups-mode",     metavar="on|off", dest="ups_mode",
                    help="Enable/disable UPS mode")
    ap.add_argument("--super-power",  metavar="on|off", dest="super_power",
                    help="Enable/disable super power drive")
    ap.add_argument("--key-tone",     metavar="on|off", dest="key_tone",
                    help="Enable/disable button beep")
    ap.add_argument("--fan-low",      metavar="on|off", dest="fan_low",
                    help="Enable/disable fan low startup mode")

    # Numeric settings
    ap.add_argument("--ac-standby",     type=int, dest="ac_standby",     metavar="MINUTES",
                    help="Set AC output auto-off time (0=never)")
    ap.add_argument("--dc-standby",     type=int, dest="dc_standby",     metavar="MINUTES",
                    help="Set DC output auto-off time (0=never)")
    ap.add_argument("--device-standby", type=int, dest="device_standby", metavar="MINUTES",
                    help="Set device standby time (0=never)")
    ap.add_argument("--screen-time",    type=int, dest="screen_time",    metavar="MINUTES",
                    help="Set screen timeout (0=always on)")
    ap.add_argument("--ac-limit",       type=int, dest="ac_limit",       metavar="WATTS",
                    help="Set AC charging input power limit")
    ap.add_argument("--ac-freq",        type=int, dest="ac_freq",        metavar="HZ",
                    choices=[50, 60], help="Set AC output frequency (50 or 60)")
    ap.add_argument("--sync-time",      action="store_true", dest="sync_time",
                    help="Sync device clock to current system time")

    args = ap.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Require --address (or --scan which handles missing address itself)
    needs_address = not args.scan
    if needs_address and not args.address:
        # Will auto-scan — that's fine, find_device_address handles it
        pass

    asyncio.run(_cli_main(args))


if __name__ == "__main__":
    main()
