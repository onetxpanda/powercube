"""
powercube — Python client for the Segway PowerCube BLE API.

Usage:
    from powercube import PowerCube

    async with PowerCube("AA:BB:CC:DD:EE:FF") as cube:
        await cube.pair()           # first time only — press button on device
        status = await cube.get_status()
        print(status)
"""

from .protocol import NinebotFrame, build_frame, parse_frame

def __getattr__(name):
    if name == "PowerCube":
        from .client import PowerCube
        return PowerCube
    if name == "PowerCubeError":
        from .client import PowerCubeError
        return PowerCubeError
    raise AttributeError(f"module 'powercube' has no attribute {name!r}")

__all__ = ["PowerCube", "PowerCubeError", "NinebotFrame", "build_frame", "parse_frame"]
