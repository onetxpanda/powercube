#!/usr/bin/env python3
"""
scanner.py — Scan for Segway/Ninebot BLE devices and enumerate GATT services.

Usage:
    python3 scanner.py              # scan 10 seconds for known device names
    python3 scanner.py --all        # show all BLE devices found
    python3 scanner.py --address AA:BB:CC:DD:EE:FF  # enumerate GATT on a known address
"""

import argparse
import asyncio
import logging

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice

logger = logging.getLogger(__name__)

# Device name fragments that suggest a Segway/Ninebot device.
KNOWN_NAME_FRAGMENTS = [
    "nbsc", "nb",
    "misc",
    "segway", "ninebot",
    "powercube", "power cube", "power_cube",
]


def looks_like_segway(device: BLEDevice) -> bool:
    name = (device.name or "").lower()
    return any(frag in name for frag in KNOWN_NAME_FRAGMENTS)


async def scan(duration: float = 10.0, show_all: bool = False) -> list[BLEDevice]:
    print(f"Scanning for {duration:.0f}s ...")
    discovered = await BleakScanner.discover(timeout=duration, return_adv=True)
    entries = list(discovered.values())
    entries.sort(key=lambda x: x[1].rssi or -999, reverse=True)
    results = []
    for d, adv in entries:
        is_known = looks_like_segway(d)
        if show_all or is_known:
            tag = "[SEGWAY?]" if is_known else "        "
            print(f"  {tag}  {d.address}  RSSI={adv.rssi:4}  {d.name!r}")
            results.append(d)
    return results


async def enumerate_gatt(address: str) -> None:
    print(f"\nConnecting to {address} ...")
    async with BleakClient(address) as client:
        print(f"Connected. Services:\n")
        for service in client.services:
            print(f"  Service: {service.uuid}")
            print(f"           {service.description}")
            for char in service.characteristics:
                props = ", ".join(char.properties)
                print(f"    Char:  {char.uuid}  [{props}]")
                print(f"           {char.description}")
                for desc in char.descriptors:
                    print(f"      Desc: {desc.uuid}")
            print()


async def _main(args: argparse.Namespace) -> None:
    if args.address:
        await enumerate_gatt(args.address)
    else:
        await scan(duration=args.duration, show_all=args.all)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan for Segway PowerCube BLE devices")
    parser.add_argument("--address", metavar="ADDR", help="Skip scan; enumerate GATT on this address")
    parser.add_argument("--all", action="store_true", help="Show all BLE devices, not just Segway")
    parser.add_argument("--duration", type=float, default=10.0, help="Scan duration in seconds")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    asyncio.run(_main(args))


if __name__ == "__main__":
    main()
