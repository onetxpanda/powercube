# powercube

Python library for controlling the **Segway PowerCube** portable power station over Bluetooth LE.

## Features

- Full BLE communication using the Ninebot encrypted protocol
- First-time device pairing (press power button to confirm)
- Read status: battery %, capacity, input/output power, temperatures
- Per-port power, voltage, and current (USB-A, USB-C, DC, AC)
- Control: AC/DC output, UPS mode, super power drive, frequency
- Adjust standby timers and screen timeout
- Battery module (BMS) data: cell voltages, cycle count, temperatures

## Installation

```bash
pip install git+https://github.com/onetxpanda/powercube.git
```

Or clone and install in editable mode:

```bash
git clone https://github.com/onetxpanda/powercube.git
cd powercube
pip install -e .
```

## Quick Start

```python
import asyncio
from powercube import PowerCube

async def main():
    async with PowerCube("AA:BB:CC:DD:EE:FF") as cube:
        status = await cube.get_status()
        print(f"Battery: {status['soc_pct']}%  Power out: {status['output_power_w']}W")

asyncio.run(main())
```

## First-Time Pairing

```bash
python3 -m powercube --address AA:BB:CC:DD:EE:FF --pair
```

Press the power button on the device when prompted. Credentials are saved to `~/.config/powercube/<address>.json` and loaded automatically on subsequent connections.

## CLI Reference

```
python3 -m powercube --address <ADDR> [options]

Discovery:
  --scan                Scan for PowerCube devices

Status:
  --status              Battery, power, temperature
  --bms [N]             BMS module data (default: 1)
  --temperatures        All temperature sensors
  --settings            Device settings
  --device-info         Firmware versions, serial, BMS count
  --errors              Active errors and warnings
  --features            Supported feature flags
  --output-info         Per-port voltage, current, power

Control:
  --pair                First-time pairing
  --ac-on / --ac-off    Toggle AC output
  --dc-on / --dc-off    Toggle DC 12V output
  --ups-on / --ups-off  Toggle UPS mode
  --freq 50|60          Set AC frequency
  --ac-limit W          Set AC input limit (watts)
  --ac-standby MIN      Set AC standby timeout
  --dc-standby MIN      Set DC standby timeout
  --device-standby MIN  Set device standby timeout
```

## License

MIT
