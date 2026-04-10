"""
protocol.py — Segway PowerCube BLE frame encode/decode.

Frame layout (all values little-endian):
    [0:2]   0x5A 0xA5      Header magic
    [2]     data_len       Byte count of payload only
    [3]     src            Source module address
    [4]     dst            Destination module address
    [5]     cmd            Command byte (see CMD_* constants)
    [6]     arg            Register index (s_index)
    [7..]   payload        Command data (data_len bytes)
    [-2:]   checksum       Little-endian uint16 sum of bytes [2:-2]

Checksum covers everything from the data_len byte through the end of payload.
"""

import os
import struct
from dataclasses import dataclass, field
from typing import Optional


# ── Module addresses ─────────────────────────────────────────────────────────

ADDR_HOST  = 0x3E   # App / host (sender address for outgoing frames)
ADDR_BLE   = 0x12   # BLE module                   (s_id/r_id = 18)
ADDR_MCU   = 0x06   # Main MCU (primary controller) (s_id/r_id = 6)
ADDR_PV    = 0x15   # Photovoltaic / solar input     (s_id/r_id = 21)
ADDR_INVS  = 0x11   # Inverter status / AC output    (s_id/r_id = 17)
ADDR_INVP  = 0x16   # Inverter power measurement     (s_id/r_id = 22)
ADDR_BMS1  = 0x41   # Battery module 1               (s_id/r_id = 65)
ADDR_BMS2  = 0x42   # Battery module 2               (s_id/r_id = 66)
ADDR_BMS3  = 0x43   # Battery module 3               (s_id/r_id = 67)
ADDR_BMS4  = 0x44   # Battery module 4               (s_id/r_id = 68)
ADDR_BMS5  = 0x45   # Battery module 5               (s_id/r_id = 69)

BMS_ADDRS = [ADDR_BMS1, ADDR_BMS2, ADDR_BMS3, ADDR_BMS4, ADDR_BMS5]

_ADDR_NAMES = {
    ADDR_HOST: "Host",
    ADDR_BLE:  "BLE",
    ADDR_MCU:  "MCU",
    ADDR_PV:   "PV",
    ADDR_INVS: "INVS",
    ADDR_INVP: "INVP",
    ADDR_BMS1: "BMS1",
    ADDR_BMS2: "BMS2",
    ADDR_BMS3: "BMS3",
    ADDR_BMS4: "BMS4",
    ADDR_BMS5: "BMS5",
}


# ── Command bytes ────────────────────────────────────────────────────────────

CMD_READ      = 0x01   # Read register(s)               — ops: "read"
CMD_WRITE     = 0x02   # Write register(s), no response — ops: "write"
CMD_WRITE_NR  = 0x03   # Write register(s), no response — ops: "writeNR"
CMD_READ_ACK  = 0x04   # Read with explicit ACK
CMD_WRITE_ACK = 0x05   # Write with explicit ACK
CMD_IAP_BEGIN = 0x07   # Begin firmware update
CMD_IAP_WRITE = 0x08   # Write firmware page
CMD_IAP_CRC   = 0x09   # Verify firmware CRC
CMD_REBOOT    = 0x0A   # Reboot / reset
CMD_ACTIVE    = 0x57   # Wake/activate device (sent to MCU)
CMD_AUTH_PROBE = 0x5B  # Auth: probe — device returns serial
CMD_AUTH_KEY   = 0x5C  # Auth: send session key
CMD_AUTH_PAIR  = 0x5D  # Auth: complete pairing


# ── BLE GATT UUIDs (Nordic UART Service) ─────────────────────────────────────

SERVICE_UUID   = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
CMD_WRITE_UUID = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"  # Write channel — all app→device commands go here
NOTIFY_UUID    = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"  # Notify — device→app; subscribe here
WRITE_UUID     = "6e400004-b5a3-f393-e0a9-e50e24dcca9e"  # Alt write char (notify+write, not used for commands)

FRAME_HEADER = b"\x5a\xa5"
WRITE_CHUNK  = 20   # safe BLE write-without-response chunk size


# ── Encrypted frame protocol ──────────────────────────────────────────────────
#
# All BLE traffic is encrypted using a session key negotiated via 4-step handshake.
# Wire format:  5a a5 | ext_len(1B) | body(ext_len+8 bytes) | counter(2B LE)
#
# Handshake sequence:
#   1. App → Device:  ext_len=0x00, body=ENC_HELLO_BODY (fixed), counter=0x0000
#   2. Device → App:  ext_len=0x1e, body=38 bytes (device challenge), counter=0x0000
#   3. App → Device:  ext_len=0x0e, body=22 bytes (computed response), counter=0x0002
#   4. Device → App:  ext_len=0x00, body=8 bytes (ack), counter=0x0006
#
# After handshake: regular frames use ext_len=0x01 (poll) / 0x02 (control/response).
# ENC_HELLO_BODY is app-session-stable (same value for all connections in one app session).

ENC_HELLO_BODY = bytes.fromhex("5ab2cf1e000054ff")


@dataclass
class EncFrame:
    """Encrypted transport frame wrapping all BLE traffic to/from PowerCube."""
    ext_len: int   # extra bytes beyond the base 8-byte body
    body: bytes    # ext_len + 8 bytes of encrypted payload
    counter: int   # 16-bit LE counter (BLE connection event counter)

    @classmethod
    def parse(cls, data: bytes) -> "Optional[EncFrame]":
        if len(data) < 13:
            return None
        if data[:2] != FRAME_HEADER:
            return None
        ext_len = data[2]
        body_len = ext_len + 8
        total = 2 + 1 + body_len + 2
        if len(data) < total:
            return None
        body = bytes(data[3 : 3 + body_len])
        counter = struct.unpack_from("<H", data, 3 + body_len)[0]
        return cls(ext_len=ext_len, body=body, counter=counter)

    def build(self) -> bytes:
        return FRAME_HEADER + bytes([self.ext_len]) + self.body + struct.pack("<H", self.counter)

    def __str__(self) -> str:
        return f"<EncFrame ext_len=0x{self.ext_len:02x} counter=0x{self.counter:04x} body={self.body.hex()}>"


def build_enc_hello() -> bytes:
    """Build the fixed encrypted hello frame (step 1 of handshake)."""
    return FRAME_HEADER + b"\x00" + ENC_HELLO_BODY + b"\x00\x00"


# ── PowerCube MCU register map ───────────────────────────────────────────────
# All registers are on dst=ADDR_MCU (0x06) unless noted.

class MCU:
    ERROR_CODE          = 39   # s_data=2  — error code bitmask
    WARN_CODE           = 40   # s_data=2  — warning code bitmask
    BOOL_STATUS         = 41   # s_data=2  — rBool: general status bits
    FUN_SUP_BOOL        = 43   # s_data=2  — rFunSupBool: supported features
    INPUT_POWER         = 48   # s_data=2  — rInputPower: total input watts
    OUTPUT_POWER        = 49   # s_data=2  — rOutputPower: total output watts
    SOC_TEMP            = 50   # s_data=2  — rSocTemp: SOC% (byte0) + temp °C (byte1)
    CAPACITY            = 51   # s_data=2  — rCapacity: capacity Wh
    REMAIN_TIME         = 52   # s_data=2  — rRemainTime: remaining minutes
    OUTPUT_INFO         = 63   # s_data=32 — rOutputInfo: USB/DC/AC current+voltage
    MCU_FW_VER          = 23   # s_data=2  — rMcuV
    SN                  = 32   # s_data=14 — rSN: serial number (ASCII)
    CPU_ID              = 24   # s_data=12 — rCPUId
    ERROR_CODE_REG      = 39   # s_data=2
    WARN_CODE_REG       = 40   # s_data=2
    BMS_COUNT           = 170  # s_data=2  — number of connected BMS modules
    TEMP                = 171  # s_data=10 — rTemp: multiple temperatures
    BLE_FW_VER          = 178  # s_data=2  — rBleV
    PV_FW_VER           = 179  # s_data=2  — rPvV
    INVP_FW_VER         = 180  # s_data=2  — rInvpV
    INVS_FW_VER         = 181  # s_data=2  — rInvsV
    BMS1_FW_VER         = 182  # s_data=2  — rBms1V
    BMS2_FW_VER         = 183  # s_data=2
    BMS3_FW_VER         = 184  # s_data=2
    BMS4_FW_VER         = 185  # s_data=2
    BMS5_FW_VER         = 186  # s_data=2
    FUN_BOOL            = 192  # s_data=2  — rFunBool / setFunBool (output enables)
    FUN_BOOL2           = 193  # s_data=2  — rFunBool2 / setFunBool2 (settings)
    AC_INPUT_PWR_LIMIT  = 208  # s_data=2  — rACInputPowerLimit / wACInputPowerLimit
    FREQUENCY           = 210  # s_data=2  — rFrequencySwitchValue / wFrequencySwitchValue
    DEVICE_STANDBY_TIME = 211  # s_data=2  — rDeviceStandbyTime / wDeviceStandbyTime
    AC_STANDBY_TIME     = 212  # s_data=2  — rACStandbyTime / wACStandbyTime
    DC_STANDBY_TIME     = 213  # s_data=2  — rDCStandbyTime / wDCStandbyTime
    UNIX_TIME           = 218  # s_data=4  — wUnixTime (write-only)
    SCREEN_DISPLAY_TIME = 220  # s_data=2  — rScreenDisplayTime / wScreenDisplayTime
    LED_MODE            = 221  # s_data=2  — rLedMode / wLedMode
    ATMOSPHERE_MODE     = 222  # s_data=2
    RHYTHM_MODE         = 227  # s_data=2


# ── FunBool bit masks (MCU reg 192 — rFunBool / setFunBool) ──────────────────

FUNBOOL_DC_OUTPUT  = 0x0001   # bit 0: DC 12V output enable
FUNBOOL_AC_OUTPUT  = 0x0002   # bit 1: AC output enable

# ── FunBool status bits (MCU reg 41 — rBool) ─────────────────────────────────

BOOL_IS_CHARGING   = 0x8000   # bit 15: AC input / charging active

# ── FunBool2 bit masks (MCU reg 193 — rFunBool2 / setFunBool2) ───────────────

FUNBOOL2_UPS        = 0x0002   # bit 1: UPS (uninterruptible power) mode
FUNBOOL2_SUPER_PWR  = 0x0004   # bit 2: super power drive
FUNBOOL2_KEY_TONE   = 0x0008   # bit 3: key press beep sound
FUNBOOL2_FAN_LOW    = 0x0010   # bit 4: fan low-startup mode (0=high startup)

# ── FunSupBool feature flags (MCU reg 43 — rFunSupBool) ──────────────────────

FUNSUP_FREQUENCY     = 0x0001  # bit 0: AC frequency switch (50/60 Hz) supported
FUNSUP_AC_LIMIT_1250 = 0x0100  # bits 8-9 == 0x0100: 1250W AC input limit variant
FUNSUP_AC_LIMIT_1650 = 0x0200  # bits 8-9 == 0x0200: 1650W AC input limit variant
FUNSUP_AC_STANDBY    = 0x0800  # bit 11: AC standby time supported
FUNSUP_DC_STANDBY    = 0x1000  # bit 12: DC standby time supported
FUNSUP_DEV_STANDBY   = 0x2000  # bit 13: device standby time supported
FUNSUP_SCREEN_TIME   = 0x4000  # bit 14: screen display time supported

# ── Error/Warning code bitmasks (MCU regs 39/40) ─────────────────────────────
# Bit definitions (best-effort; may vary by hardware revision)

ERROR_BITS = {
    0x0001: "BMS comms fault",
    0x0002: "BMS over-temperature",
    0x0004: "BMS under-temperature",
    0x0008: "BMS over-voltage",
    0x0010: "BMS under-voltage",
    0x0020: "BMS over-current",
    0x0040: "BMS short circuit",
    0x0080: "BMS cell imbalance",
    0x0100: "Inverter fault",
    0x0200: "Inverter over-temperature",
    0x0400: "AC input fault",
    0x0800: "PV fault",
    0x1000: "Fan fault",
    0x2000: "MCU fault",
    0x4000: "NTC sensor fault",
    0x8000: "System fault",
}

WARN_BITS = {
    0x0001: "BMS temperature warning",
    0x0002: "BMS voltage warning",
    0x0004: "BMS capacity low",
    0x0008: "BMS over-current warning",
    0x0010: "Inverter overload",
    0x0020: "AC input unstable",
    0x0040: "PV voltage high",
    0x0080: "PV voltage low",
    0x0100: "Device overtemperature",
    0x0200: "Fan speed low",
    0x0400: "Capacity nearly full",
    0x0800: "Capacity nearly empty",
}

# ── rTemp register layout (10 bytes at MCU reg 171) ──────────────────────────
# 10 × uint8, each byte is a temperature in °C (signed, two's complement).
# Values > 127 represent negative temperatures (subtract 256).
# Byte 0 corresponds to the same sensor reported in SOC_TEMP.
# Sensor order (best-effort; may vary by hardware revision):
#   [0] MCU/board  [1] MCU2?  [2] BMS  [3] BMS2?
#   [4] AC/inv     [5] AC2?   [6] DC   [7] DC2?
#   [8] PV input   [9] PV2?

TEMP_SENSOR_NAMES = [
    "mcu", "mcu_2", "bms", "bms_2",
    "ac_inv", "ac_inv_2", "dc_conv", "dc_conv_2",
    "pv_input", "pv_input_2",
]

# ── BMS per-battery register map (dst = ADDR_BMS1..5) ────────────────────────

class BMS:
    INFO          = 16   # s_data=14 — ASCII info string (part num / serial)
    CYCLE_COUNT   = 27   # s_data=2  — cycle count
    MFG_DATE      = 32   # s_data=2  — manufacturing date (raw encoding, device-specific format)
    DEEP_DISCHARGE = 39  # s_data=2  — deep discharge event count
    BATTERY_INFO  = 49   # s_data=12 — pack snapshot (see get_bms_info for byte layout)
    CELL_VOLTAGE  = 64   # s_data=32 — 16 × uint16 individual cell voltages in mV
    FULL_CAP_MAH  = 85   # s_data=2  — full/design capacity in mAh
    ENERGY_THROUGH = 128 # s_data=4  — lifetime energy throughput in Wh (uint32)
    CAP_THROUGH   = 130  # s_data=4  — lifetime capacity throughput in mAh (uint32)
    EXTREME_CHARGE = 134 # s_data=4  — extreme charge condition time (minutes, uint32)
    EXTREME_USE   = 136  # s_data=4  — extreme use condition time (minutes, uint32)
    REMAIN_CAP    = 138  # s_data=2  — usable/design capacity in Wh (constant across SOC levels)
    MORE_INFO     = 139  # s_data=2  — additional BMS info (layout may vary by firmware)


# ── rOutputInfo byte layout (32 bytes at MCU reg 63) ─────────────────────────
# Each port: 2 bytes current (×0.01 A) + 2 bytes voltage (×0.1 V)
#
# Byte offsets:
#   0- 1: USB-C1 current    2- 3: USB-C1 voltage
#   4- 5: USB-C2 current    6- 7: USB-C2 voltage
#   8- 9: USB-A1 current   10-11: USB-A1 voltage
#  12-13: USB-A2 current   14-15: USB-A2 voltage
#  16-17: USB-A3 current   18-19: USB-A3 voltage
#  20-21: USB-A4 current   22-23: USB-A4 voltage
#  24-25: DC current       26-27: DC voltage
#  28-29: AC current       30-31: AC voltage

OUTPUT_INFO_PORTS = [
    ("usb_c1", 0),
    ("usb_c2", 4),
    ("usb_a1", 8),
    ("usb_a2", 12),
    ("usb_a3", 16),
    ("usb_a4", 20),
    ("dc",     24),
    ("ac",     28),
]


# ── Frame dataclass ───────────────────────────────────────────────────────────

@dataclass
class NinebotFrame:
    src:          int
    dst:          int
    cmd:          int
    arg:          int = 0
    payload:      bytes = field(default=b"")
    checksum_ok:  bool = field(default=True, compare=False, repr=False)

    def addr_name(self, addr: int) -> str:
        return _ADDR_NAMES.get(addr, f"0x{addr:02X}")

    def __str__(self) -> str:
        src = self.addr_name(self.src)
        dst = self.addr_name(self.dst)
        chk = "OK" if self.checksum_ok else "BAD_CHECKSUM"
        payload_hex = self.payload.hex(" ") if self.payload else "-"
        return (
            f"<Frame {src}→{dst} "
            f"cmd=0x{self.cmd:02X} arg=0x{self.arg:02X} "
            f"payload=[{payload_hex}] {chk}>"
        )


# ── Encode / decode ───────────────────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    return sum(data) & 0xFFFF


def build_frame(
    src: int, dst: int, cmd: int,
    arg: int = 0, payload: bytes = b""
) -> bytes:
    """
    Encode a Ninebot frame.

    Wire: 5A A5 | data_len | src | dst | cmd | arg | payload | chk_lo | chk_hi
    Checksum covers everything from data_len through end of payload.
    """
    body = bytes([len(payload), src, dst, cmd, arg]) + payload
    chk  = _checksum(body)
    return FRAME_HEADER + body + struct.pack("<H", chk)


def parse_frame(data: bytes) -> Optional[NinebotFrame]:
    """
    Decode a Ninebot frame. Returns None if data is invalid/too short.
    Sets checksum_ok=False on checksum mismatch rather than raising.
    """
    if len(data) < 9:
        return None
    if data[:2] != FRAME_HEADER:
        return None

    data_len = data[2]
    total    = 2 + 1 + 4 + data_len + 2

    if len(data) < total:
        return None

    src     = data[3]
    dst     = data[4]
    cmd     = data[5]
    arg     = data[6]
    payload = bytes(data[7 : 7 + data_len])

    body        = data[2 : 7 + data_len]
    stored_chk  = struct.unpack_from("<H", data, 7 + data_len)[0]
    checksum_ok = _checksum(body) == stored_chk

    return NinebotFrame(
        src=src, dst=dst, cmd=cmd, arg=arg,
        payload=payload, checksum_ok=checksum_ok,
    )


def parse_all_frames(data: bytes) -> list:
    """Scan a byte buffer and return every valid Ninebot frame found."""
    frames = []
    i = 0
    while i < len(data) - 1:
        if data[i:i+2] == FRAME_HEADER:
            frame = parse_frame(data[i:])
            if frame:
                frames.append(frame)
                total = 2 + 1 + 4 + len(frame.payload) + 2
                i += total
                continue
        i += 1
    return frames


# ── Frame builders ────────────────────────────────────────────────────────────

def build_inner_frame(
    src: int, dst: int, cmd: int,
    arg: int = 0, payload: bytes = b""
) -> bytes:
    """
    Build the inner plaintext frame for encryption (no checksum).

    This is the format FrameEncryption.encrypt_frame() expects:
        5A A5 | data_len | src | dst | cmd | arg | payload
    The encrypted wire frame is then: encrypt_frame(inner) → adds 6-byte trailer.
    """
    length = len(payload) & 0xFF
    return bytes([0x5A, 0xA5, length, src, dst, cmd, arg]) + payload


def parse_inner_frame(data: bytes) -> Optional[NinebotFrame]:
    """
    Parse a decrypted inner frame (no checksum — integrity is provided by
    the AES-CCM MAC tag in the encrypted wire frame).
    """
    if len(data) < 7:
        return None
    if data[:2] != FRAME_HEADER:
        return None
    data_len = data[2]
    if len(data) < 7 + data_len:
        return None
    return NinebotFrame(
        src=data[3], dst=data[4], cmd=data[5], arg=data[6],
        payload=bytes(data[7:7 + data_len]),
        checksum_ok=True,
    )


def build_read(dst: int, reg: int, n_bytes: int) -> bytes:
    """
    Build a CMD_READ inner frame (for encryption).
    n_bytes: number of bytes to read.
    Payload is n_bytes encoded as uint16 LE.
    """
    return build_inner_frame(ADDR_HOST, dst, CMD_READ, arg=reg,
                             payload=struct.pack("<H", n_bytes))


def build_write_nr(dst: int, reg: int, payload: bytes) -> bytes:
    """Build a CMD_WRITE_NR inner frame (for encryption)."""
    return build_inner_frame(ADDR_HOST, dst, CMD_WRITE_NR, arg=reg, payload=payload)


def build_auth_probe() -> bytes:
    """Build PRE_COMM inner frame (for encryption with device BLE name key)."""
    return build_inner_frame(ADDR_HOST, ADDR_BLE, CMD_AUTH_PROBE)


def build_auth_key(key: Optional[bytes] = None) -> tuple:
    """Returns (inner_frame, key_used). Generates random key if not provided."""
    if key is None:
        key = os.urandom(16)
    return build_inner_frame(ADDR_HOST, ADDR_BLE, CMD_AUTH_KEY, payload=key), key


def build_auth_pair(serial_bytes: bytes) -> bytes:
    """Build AUTH inner frame (for encryption with mKeyPwd+mKeyAuth key)."""
    return build_inner_frame(ADDR_HOST, ADDR_BLE, CMD_AUTH_PAIR, payload=serial_bytes)


def build_activate() -> bytes:
    """Wake/activate the PowerCube MCU."""
    return build_inner_frame(ADDR_HOST, ADDR_MCU, CMD_ACTIVE, arg=0)
