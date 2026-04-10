"""
client.py — Async BLE client for the Segway PowerCube.

All BLE traffic uses the encrypt=2 protocol: every frame (including handshake
frames) is encrypted using an AES-CCM variant session key protocol.

Handshake (performed automatically in connect()):
    1. PRE_COMM (cmd=0x5B): establish session key from device BLE name
       → device responds with mKeyAuth (16 bytes) and serial (14 bytes)
    2a. AUTH (cmd=0x5D): authenticate using stored mKeyPwd
    2b. SET_PWD (cmd=0x5C): first-time pairing — generates random mKeyPwd,
        requires button press on device

After handshake, COMM mode: all frames encrypted with mKeyPwd+mKeyAuth key.

Credentials stored in ~/.config/powercube/<mac_addr>.json

Usage (library):
    import asyncio
    from powercube import PowerCube

    async def main():
        async with PowerCube("AA:BB:CC:DD:EE:FF") as cube:
            status = await cube.get_status()
            print(f"SOC: {status['soc_pct']}%")

    asyncio.run(main())

Usage (CLI):
    python3 -m powercube --address AA:BB:CC:DD:EE:FF --status
    python3 -m powercube --address AA:BB:CC:DD:EE:FF --pair
    python3 -m powercube --address AA:BB:CC:DD:EE:FF --ac-on
"""

import asyncio
import json
import logging
import os
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Optional

from bleak import BleakClient
from bleak.backends.device import BLEDevice

from .crypto import FrameEncryption
from .protocol import (
    # addresses
    ADDR_BLE, ADDR_MCU, ADDR_HOST, BMS_ADDRS,
    # commands
    CMD_READ, CMD_READ_ACK, CMD_WRITE_NR, CMD_AUTH_PROBE, CMD_AUTH_KEY, CMD_AUTH_PAIR,
    # GATT
    NOTIFY_UUID, CMD_WRITE_UUID, WRITE_CHUNK,
    # frame header
    FRAME_HEADER,
    # types
    NinebotFrame,
    # register namespaces
    MCU, BMS,
    # bit masks
    FUNBOOL_AC_OUTPUT, FUNBOOL_DC_OUTPUT,
    BOOL_IS_CHARGING,
    FUNBOOL2_UPS, FUNBOOL2_SUPER_PWR, FUNBOOL2_KEY_TONE, FUNBOOL2_FAN_LOW,
    FUNSUP_FREQUENCY, FUNSUP_AC_LIMIT_1250, FUNSUP_AC_LIMIT_1650,
    FUNSUP_AC_STANDBY, FUNSUP_DC_STANDBY, FUNSUP_DEV_STANDBY, FUNSUP_SCREEN_TIME,
    ERROR_BITS, WARN_BITS, TEMP_SENSOR_NAMES,
    OUTPUT_INFO_PORTS,
    # builders
    build_inner_frame, parse_inner_frame,
    build_read, build_write_nr,
    build_auth_probe, build_auth_key, build_auth_pair, build_activate,
)

logger = logging.getLogger(__name__)


class PowerCubeError(Exception):
    pass


def _creds_path(address: str) -> Path:
    mac = address.replace(":", "").lower()
    d = Path.home() / ".config" / "powercube"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{mac}.json"


class PowerCube:
    """
    Async context manager for communicating with a Segway PowerCube over BLE.

    First-time pairing:
        async with PowerCube("AA:BB:CC:DD:EE:FF") as cube:
            await cube.pair()   # press power button when prompted

    Subsequent connections (credentials auto-loaded from config file):
        async with PowerCube("AA:BB:CC:DD:EE:FF") as cube:
            status = await cube.get_status()
    """

    def __init__(
        self,
        address: str | BLEDevice,
        ble_name: str = "PowerCube",
        timeout: float = 10.0,
        creds_file: Optional[Path] = None,
        mkey_pwd: Optional[bytes] = None,
        on_pair_prompt: Optional[Callable[[str], None]] = None,
    ):
        """
        Parameters
        ----------
        address:        BLE device UUID/MAC address, or a BLEDevice object.
        ble_name:       Device BLE name used as the PRE_COMM crypto key.
        timeout:        BLE connection timeout in seconds.
        creds_file:     Path to the JSON credentials file.  Defaults to
                        ~/.config/powercube/<address>.json.
        mkey_pwd:       Pre-loaded credential bytes.  When provided, skips
                        file I/O entirely — useful for HA config entry storage.
        on_pair_prompt: Called with a human-readable message when the device
                        is waiting for the user to press its power button
                        during first-time pairing.  If None the prompt is
                        silently suppressed (library callers handle it their
                        own way).
        """
        if isinstance(address, BLEDevice):
            self.address: str = address.address
            self._ble_device: Optional[BLEDevice] = address
        else:
            self.address = address
            self._ble_device = None

        self.ble_name  = ble_name
        self.timeout   = timeout
        self._creds_file = creds_file or _creds_path(self.address)
        self._mkey_pwd_override = mkey_pwd
        self._on_pair_prompt: Callable[[str], None] = on_pair_prompt or (lambda _: None)

        self._client: Optional[BleakClient] = None
        self._enc = FrameEncryption()
        self._auth_done = False
        self._device_has_pwd = False  # set by _do_pre_comm; True = already paired
        self._lock = asyncio.Lock()

        # BLE reassembly buffer — notification chunks are accumulated here
        self._rx_buf = bytearray()

        # Queues for different stages
        self._enc_queue: asyncio.Queue = asyncio.Queue()   # raw encrypted frames (handshake)
        self._notify_queue: asyncio.Queue = asyncio.Queue()  # decrypted NinebotFrame (COMM)

        # Set during PRE_COMM, used for SET_PWD / pair()
        self._mKeyAuth: Optional[bytes] = None
        self._device_serial: Optional[bytes] = None

    # ── Context manager ───────────────────────────────────────────────────────

    async def __aenter__(self) -> "PowerCube":
        await self.connect()
        return self

    async def __aexit__(self, *_) -> None:
        await self.disconnect()

    @property
    def is_connected(self) -> bool:
        """True if the BLE connection is currently active."""
        return self._client is not None and self._client.is_connected

    def get_credential(self) -> Optional[bytes]:
        """Return the stored mKeyPwd bytes, or None if not yet paired."""
        if self._mkey_pwd_override is not None:
            return self._mkey_pwd_override
        creds = self._load_creds()
        if creds:
            return bytes.fromhex(creds["pwd"])
        return None

    def update_ble_device(self, device: BLEDevice) -> None:
        """Replace the cached BLEDevice (called by HA on RSSI/address updates)."""
        self._ble_device = device

    # ── Connection + handshake ────────────────────────────────────────────────

    async def _client_connect_only(self) -> None:
        """
        Connect to BLE and run PRE_COMM only — no AUTH, no credentials.

        Sets self._device_has_pwd so callers can branch on pairing status
        before deciding what to do next (e.g. config flow probe step).
        Call disconnect() when done.
        """
        logger.info("Probing %s (PRE_COMM only) ...", self.address)
        target = self._ble_device if self._ble_device is not None else self.address
        self._client = BleakClient(target, timeout=self.timeout)
        await self._client.connect()
        await self._client.start_notify(NOTIFY_UUID, self._on_notify)
        await self._do_pre_comm()

    async def connect(self) -> None:
        """
        Connect to device and perform the encrypted handshake.

        If credentials are stored (file or mkey_pwd constructor arg), performs
        PRE_COMM + AUTH and enters COMM mode.
        If no credentials are stored, only PRE_COMM is done; call pair() next.
        """
        logger.info("Connecting to %s ...", self.address)
        target = self._ble_device if self._ble_device is not None else self.address
        self._client = BleakClient(target, timeout=self.timeout)
        await self._client.connect()
        logger.info("Connected — subscribing to %s", NOTIFY_UUID)
        await self._client.start_notify(NOTIFY_UUID, self._on_notify)

        device_has_pwd = await self._do_pre_comm()

        mkey_pwd = self.get_credential()
        if mkey_pwd:
            await self._do_auth(mkey_pwd)
            self._auth_done = True
            logger.info("Authenticated. COMM mode active.")
        elif device_has_pwd:
            logger.warning(
                "Device has a stored password but we have no credentials. "
                "The device is already paired (possibly by another app). "
                "Factory-reset the device to clear the stored password."
            )
        else:
            logger.info("Device is unpaired — call pair() to set a password.")

    async def _handshake_with_client(self, client: BleakClient) -> None:
        """
        Run the encrypted handshake on an already-connected BleakClient.

        Use this when the caller manages the BLE connection (e.g. via
        bleak_retry_connector) and hands off the connected client.
        """
        self._client = client
        await self._client.start_notify(NOTIFY_UUID, self._on_notify)
        device_has_pwd = await self._do_pre_comm()
        mkey_pwd = self.get_credential()
        if mkey_pwd:
            await self._do_auth(mkey_pwd)
            self._auth_done = True
            logger.info("Authenticated. COMM mode active.")
        elif device_has_pwd:
            logger.warning(
                "Device has a stored password but we have no credentials. "
                "The device is already paired (possibly by another app). "
                "Factory-reset the device to clear the stored password."
            )
        else:
            logger.info("Device is unpaired — call pair() to set a password.")

    async def disconnect(self) -> None:
        if self._client and self._client.is_connected:
            await self._client.stop_notify(NOTIFY_UUID)
            await self._client.disconnect()
            logger.info("Disconnected")

    # ── Low-level BLE transport ───────────────────────────────────────────────

    def _on_notify(self, _handle: int, data: bytearray) -> None:
        """Accumulate BLE notification chunks and dispatch complete frames."""
        self._rx_buf.extend(data)
        self._process_rx_buf()

    def _process_rx_buf(self) -> None:
        """Extract complete encrypted frames from _rx_buf and dispatch them."""
        buf = self._rx_buf
        while len(buf) >= 3:
            # Scan for 5a a5 header
            idx = -1
            for i in range(len(buf) - 1):
                if buf[i] == 0x5A and buf[i + 1] == 0xA5:
                    idx = i
                    break
            if idx < 0:
                # No header found — discard all but last byte (partial header)
                del buf[:max(0, len(buf) - 1)]
                break
            if idx > 0:
                logger.debug("Discarding %d bytes before header", idx)
                del buf[:idx]

            # We have header at buf[0:3]; buf[2] = frame inner payload len
            if len(buf) < 3:
                break
            inner_len = buf[2]
            # Encrypted frame total: header(3) + inner_body(4+inner_len) + trailer(6)
            total = inner_len + 13
            if len(buf) < total:
                break  # incomplete — wait for more chunks

            frame_bytes = bytes(buf[:total])
            del buf[:total]
            self._dispatch_enc_frame(frame_bytes)

    def _dispatch_enc_frame(self, frame_bytes: bytes) -> None:
        """Route a complete encrypted frame to the right queue."""
        if not self._auth_done:
            # Pre-auth: handshake code reads these directly
            self._enc_queue.put_nowait(frame_bytes)
        else:
            # COMM mode: decrypt and parse
            plain = self._enc.decrypt_frame(frame_bytes)
            if plain is None:
                logger.warning("Decrypt failed: %s", frame_bytes.hex())
                return
            frame = parse_inner_frame(plain)
            if frame:
                logger.debug("RX %s", frame)
                self._notify_queue.put_nowait(frame)
            else:
                logger.debug("RX (unrecognised inner frame): %s", plain.hex())

    async def _send_enc(self, inner_frame: bytes) -> None:
        """Encrypt inner_frame and write to device."""
        if not self._client or not self._client.is_connected:
            raise PowerCubeError("Not connected")
        wire = self._enc.encrypt_frame(inner_frame)
        logger.debug("TX %s", wire.hex())
        # Try to send as one write (MTU typically 185+ bytes on macOS/iOS).
        # Fall back to 20-byte chunks if the write fails (older Android/Linux stacks).
        try:
            await self._client.write_gatt_char(CMD_WRITE_UUID, wire, response=False)
        except Exception:
            for i in range(0, len(wire), WRITE_CHUNK):
                await self._client.write_gatt_char(
                    CMD_WRITE_UUID, wire[i:i + WRITE_CHUNK], response=False
                )

    async def _recv_enc(self, timeout: float = 5.0) -> bytes:
        """Wait for one complete encrypted frame from the handshake queue."""
        try:
            return await asyncio.wait_for(self._enc_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            raise PowerCubeError("Timed out waiting for encrypted response")

    async def _recv(
        self,
        expect_cmd: Optional[int] = None,
        timeout: float = 5.0,
    ) -> NinebotFrame:
        if not self._auth_done:
            raise PowerCubeError("Not authenticated — run handshake first")
        try:
            async with asyncio.timeout(timeout):
                while True:
                    frame = await self._notify_queue.get()
                    if expect_cmd is None or frame.cmd == expect_cmd:
                        return frame
                    logger.debug("Skipping frame cmd=0x%02x (want 0x%02x)", frame.cmd, expect_cmd)
        except TimeoutError:
            raise PowerCubeError("Timed out waiting for response")

    async def _request(
        self,
        inner_frame: bytes,
        expect_cmd: Optional[int] = None,
        timeout: float = 5.0,
    ) -> NinebotFrame:
        async with self._lock:
            await self._send_enc(inner_frame)
            return await self._recv(expect_cmd=expect_cmd, timeout=timeout)

    # ── Handshake internals ───────────────────────────────────────────────────

    async def _do_pre_comm(self) -> bool:
        """
        PRE_COMM handshake (cmd=0x5B, counter=0, key=device_BLE_name).

        Returns True if the device already has a stored password (arg != 0),
        False if the device is unpaired (arg == 0).

        Device response inner frame layout:
          [5a a5 1e src dst cmd=5B arg mKeyAuth(16) mKeySn(14)]
          arg=0: device has no password (needs SET_PWD)
          arg=1: device has a password (needs AUTH with stored mKeyPwd)
        """
        logger.info("PRE_COMM: sending encrypted probe (key=%r)", self.ble_name)
        self._enc.crypto_reset_sn()
        self._enc.crypto_setKey(self.ble_name.encode(), None)

        await self._send_enc(build_auth_probe())

        raw_resp = await self._recv_enc(timeout=5.0)
        plain = self._enc.decrypt_frame(raw_resp)
        if plain is None:
            raise PowerCubeError(f"PRE_COMM decrypt failed: {raw_resp.hex()}")

        if len(plain) < 37:
            raise PowerCubeError(
                f"PRE_COMM response too short: {len(plain)} bytes (need ≥37)"
            )

        # inner frame: [5a a5 1e src dst cmd=5B arg mKeyAuth(16) mKeySn(14)]
        arg      = plain[6]   # 0=unpaired, non-0=has password
        mKeyAuth = plain[7:23]
        mKeySn   = plain[23:37]
        logger.info("PRE_COMM ok — mKeyAuth=%s serial=%s arg=0x%02x (%s)",
                    mKeyAuth.hex(), mKeySn.rstrip(b"\x00"), arg,
                    "paired" if arg else "unpaired")

        self._mKeyAuth = mKeyAuth
        self._device_serial = mKeySn
        self._device_has_pwd = (arg != 0)

        # Prepare encryption for with-SN phase
        self._enc.crypto_setAuthParam(mKeyAuth)
        self._enc.crypto_start_sn()  # counter → 1

        return self._device_has_pwd

    async def _do_auth(self, mKeyPwd: bytes) -> None:
        """
        AUTH handshake (cmd=0x5D, with-SN mode, key=mKeyPwd+mKeyAuth).

        Sends encrypted serial number; device responds with result=0x01 on success.
        """
        mKeyAuth = self._mKeyAuth
        if mKeyAuth is None:
            raise PowerCubeError("PRE_COMM not done — no mKeyAuth")

        logger.info("AUTH: sending serial with stored mKeyPwd")
        self._enc.crypto_setKey(mKeyPwd, mKeyAuth)

        await self._send_enc(build_auth_pair(self._device_serial or b""))

        raw_resp = await self._recv_enc(timeout=5.0)
        plain = self._enc.decrypt_frame(raw_resp)
        if plain is None:
            # Device echoes our frame as a NACK (replay protection fires: ctr_plus1 <= counter)
            raise PowerCubeError(
                "AUTH rejected by device (frame echoed as NACK — wrong mKeyPwd or device already paired with different credentials)"
            )

        result = plain[6] if len(plain) > 6 else 0
        if result != 0x01:
            raise PowerCubeError(f"AUTH rejected by device (result=0x{result:02x})")
        logger.info("AUTH accepted (result=0x01)")

    async def _do_set_pwd(self, mKeyPwd: bytes, wait_timeout: float = 60.0) -> None:
        """
        SET_PWD handshake (cmd=0x5C, with-SN mode).

        Encryption key for SET_PWD is SHA1(ble_name || mKeyAuth) — NOT mKeyPwd.

        Protocol:
          - Device responds to each SET_PWD with cmd=0x5C arg=0 (waiting for button)
          - After user presses power button, device responds with arg=1 (success)
          - Client retries sending SET_PWD until arg=1 received

        This method sends SET_PWD in a retry loop, prompts for button press on first
        arg=0 response, and returns when the device acknowledges (arg=1).
        """
        mKeyAuth = self._mKeyAuth
        if mKeyAuth is None:
            raise PowerCubeError("PRE_COMM not done")

        logger.info("SET_PWD: using ble_name=%r as key1", self.ble_name)
        self._enc.crypto_setKey(self.ble_name.encode(), mKeyAuth)

        prompted = False
        try:
            async with asyncio.timeout(wait_timeout):
                while True:
                    inner = build_inner_frame(ADDR_HOST, ADDR_BLE, CMD_AUTH_KEY, payload=mKeyPwd)
                    await self._send_enc(inner)
                    logger.debug("SET_PWD sent (retry loop)")

                    try:
                        raw_resp = await asyncio.wait_for(self._enc_queue.get(), timeout=3.0)
                    except asyncio.TimeoutError:
                        # No response yet — device may still be waiting; retry
                        if not prompted:
                            self._on_pair_prompt(
                                "Press the POWER BUTTON on the device to confirm pairing"
                            )
                            prompted = True
                        continue

                    plain = self._enc.decrypt_frame(raw_resp)
                    if plain is None:
                        logger.warning("SET_PWD response decrypt failed: %s", raw_resp.hex())
                        continue

                    cmd = plain[5] if len(plain) > 5 else 0
                    arg = plain[6] if len(plain) > 6 else 0

                    if cmd != CMD_AUTH_KEY:
                        # Not a SET_PWD response — put back and wait again
                        logger.debug("SET_PWD: ignoring cmd=0x%02x", cmd)
                        continue

                    if arg == 0x01:
                        logger.info("SET_PWD accepted by device (arg=0x01)")
                        return
                    else:
                        # arg=0: device is waiting for button press
                        if not prompted:
                            self._on_pair_prompt(
                                "Press the POWER BUTTON on the device to confirm pairing"
                            )
                            prompted = True
                        logger.debug("SET_PWD: device waiting for button (arg=0x%02x)", arg)
        except TimeoutError:
            raise PowerCubeError("SET_PWD timed out waiting for device confirmation")

    # ── Credentials ───────────────────────────────────────────────────────────

    def _load_creds(self) -> Optional[dict]:
        try:
            return json.loads(self._creds_file.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def _save_creds(self, mKeyPwd: bytes) -> None:
        data = {"pwd": mKeyPwd.hex()}
        self._creds_file.write_text(json.dumps(data))
        self._mkey_pwd_override = mKeyPwd
        logger.info("Credentials saved to %s", self._creds_file)

    # ── Pairing ───────────────────────────────────────────────────────────────

    async def pair(self) -> None:
        """
        First-time pairing flow:
          1. Send SET_PWD with random mKeyPwd (key = ble_name + mKeyAuth)
          2. Device responds arg=0: waiting for button press — prompt user
          3. User presses power button on device
          4. Device responds arg=1: password stored — proceed to AUTH
          5. AUTH with key=(mKeyPwd, mKeyAuth) on same connection
          6. Save credentials

        Everything happens on a SINGLE connection — no reconnect needed.
        Call this once per device. Subsequent connect() calls auto-load creds.
        """
        if self._mKeyAuth is None:
            raise PowerCubeError("Call pair() from within a connected context manager")
        if self._auth_done:
            raise PowerCubeError("Already authenticated — no need to pair again")
        if self._device_has_pwd:
            raise PowerCubeError(
                "Device is already paired (PRE_COMM arg=0x01). "
                "Cannot SET_PWD without authenticating first.\n"
                "Options:\n"
                "  1. Factory-reset the PowerCube to clear stored password\n"
                "  2. Recover the pairing key from your existing paired app and use --mkey-pwd"
            )

        mKeyPwd = os.urandom(16)
        logger.info("Starting SET_PWD — generated random mKeyPwd=%s", mKeyPwd.hex())

        # SET_PWD: loops internally until device confirms (arg=1)
        # Will print button-press prompt when device responds with arg=0
        await self._do_set_pwd(mKeyPwd, wait_timeout=120.0)

        # AUTH on the same connection
        logger.info("SET_PWD succeeded — proceeding to AUTH")
        await self._do_auth(mKeyPwd)
        self._save_creds(mKeyPwd)
        self._auth_done = True
        logger.info("Pairing complete. COMM mode active.")

    # ── Register reads ────────────────────────────────────────────────────────

    def _require_auth(self) -> None:
        if not self._auth_done:
            raise PowerCubeError(
                "Not authenticated. Connect with stored credentials or pair() first."
            )

    async def _read_reg(self, dst: int, reg: int, n_bytes: int) -> bytes:
        self._require_auth()
        # Device responds with CMD_READ_ACK (0x04), not CMD_READ (0x01)
        resp = await self._request(build_read(dst, reg, n_bytes), expect_cmd=CMD_READ_ACK)
        return resp.payload

    async def _read_u16(self, dst: int, reg: int) -> int:
        data = await self._read_reg(dst, reg, 2)
        return struct.unpack_from("<H", data)[0]

    async def _read_i16(self, dst: int, reg: int) -> int:
        data = await self._read_reg(dst, reg, 2)
        return struct.unpack_from("<h", data)[0]

    # ── PowerCube status ──────────────────────────────────────────────────────

    async def get_status(self) -> dict:
        """
        Read the primary PowerCube status from the MCU.

        Returns a dict with keys:
            soc_pct          — state of charge 0-100 %
            temp_c           — internal temperature °C (signed)
            capacity_wh      — current battery capacity Wh
            input_power_w    — total input power W (AC charging + solar)
            output_power_w   — total output power W
            remain_time_min  — estimated remaining time in minutes
            is_charging      — True if AC input active
            ac_output        — True if AC output enabled
            dc_output        — True if DC 12V output enabled
        """
        soc_temp_raw = await self._read_reg(ADDR_MCU, MCU.SOC_TEMP, 2)
        soc_pct, temp_c = struct.unpack("Bb", soc_temp_raw)

        capacity    = await self._read_u16(ADDR_MCU, MCU.CAPACITY)
        input_pwr   = await self._read_u16(ADDR_MCU, MCU.INPUT_POWER)
        output_pwr  = await self._read_u16(ADDR_MCU, MCU.OUTPUT_POWER)
        remain_time = await self._read_u16(ADDR_MCU, MCU.REMAIN_TIME)
        bool_status = await self._read_u16(ADDR_MCU, MCU.BOOL_STATUS)
        fun_bool    = await self._read_u16(ADDR_MCU, MCU.FUN_BOOL)

        return {
            "soc_pct":         soc_pct,
            "temp_c":          temp_c,
            "capacity_wh":     capacity,
            "input_power_w":   input_pwr,
            "output_power_w":  output_pwr,
            "remain_time_min": remain_time,
            "is_charging":     bool(bool_status & BOOL_IS_CHARGING),
            "ac_output":       bool(fun_bool & FUNBOOL_AC_OUTPUT),
            "dc_output":       bool(fun_bool & FUNBOOL_DC_OUTPUT),
        }

    async def get_output_info(self) -> dict:
        """
        Read per-port current and voltage for all USB and AC/DC outputs.

        Returns a dict keyed by port name (usb_c1, usb_c2, usb_a1..usb_a4, dc, ac),
        each with sub-keys: current_a (float), voltage_v (float), power_w (float).
        """
        raw = await self._read_reg(ADDR_MCU, MCU.OUTPUT_INFO, 32)
        result = {}
        for port, offset in OUTPUT_INFO_PORTS:
            current_raw = struct.unpack_from("<H", raw, offset)[0]
            voltage_raw = struct.unpack_from("<H", raw, offset + 2)[0]
            current_a = current_raw * 0.01
            voltage_v = voltage_raw * 0.1
            result[port] = {
                "current_a": round(current_a, 2),
                "voltage_v": round(voltage_v, 1),
                "power_w":   round(current_a * voltage_v, 1),
            }
        return result

    async def get_settings(self) -> dict:
        """
        Read device settings from MCU.

        Returns:
            ac_input_limit_w  — AC charging input power limit (W)
            ac_standby_min    — AC output auto-off time (minutes, 0=never)
            dc_standby_min    — DC output auto-off time
            device_standby_min— device standby time
            screen_time_min   — screen display timeout
            frequency_hz      — AC output frequency (50 or 60)
            ups_mode          — bool: UPS mode enabled
            super_power_drive — bool: super power drive enabled
            key_tone          — bool: button beep enabled
            fan_low_startup   — bool: fan starts in low mode
        """
        ac_limit  = await self._read_u16(ADDR_MCU, MCU.AC_INPUT_PWR_LIMIT)
        ac_stby   = await self._read_u16(ADDR_MCU, MCU.AC_STANDBY_TIME)
        dc_stby   = await self._read_u16(ADDR_MCU, MCU.DC_STANDBY_TIME)
        dev_stby  = await self._read_u16(ADDR_MCU, MCU.DEVICE_STANDBY_TIME)
        scr_time  = await self._read_u16(ADDR_MCU, MCU.SCREEN_DISPLAY_TIME)
        freq      = await self._read_u16(ADDR_MCU, MCU.FREQUENCY)
        fun_bool2 = await self._read_u16(ADDR_MCU, MCU.FUN_BOOL2)

        return {
            "ac_input_limit_w":   ac_limit,
            "ac_standby_min":     ac_stby,
            "dc_standby_min":     dc_stby,
            "device_standby_min": dev_stby,
            "screen_time_min":    scr_time,
            "frequency_hz":       freq,
            "ups_mode":           bool(fun_bool2 & FUNBOOL2_UPS),
            "super_power_drive":  bool(fun_bool2 & FUNBOOL2_SUPER_PWR),
            "key_tone":           bool(fun_bool2 & FUNBOOL2_KEY_TONE),
            "fan_low_startup":    bool(fun_bool2 & FUNBOOL2_FAN_LOW),
        }

    async def get_device_info(self) -> dict:
        """Read firmware versions, serial number, and BMS count."""
        sn_raw  = await self._read_reg(ADDR_MCU, MCU.SN, 14)
        mcu_ver = await self._read_u16(ADDR_MCU, MCU.MCU_FW_VER)
        ble_ver = await self._read_u16(ADDR_MCU, MCU.BLE_FW_VER)
        pv_ver  = await self._read_u16(ADDR_MCU, MCU.PV_FW_VER)
        bms_cnt = await self._read_u16(ADDR_MCU, MCU.BMS_COUNT)
        return {
            "serial":    sn_raw.rstrip(b"\x00").decode("ascii", errors="replace"),
            "mcu_fw":    f"{mcu_ver >> 8}.{mcu_ver & 0xFF}",
            "ble_fw":    f"{ble_ver >> 8}.{ble_ver & 0xFF}",
            "pv_fw":     f"{pv_ver >> 8}.{pv_ver & 0xFF}",
            "bms_count": bms_cnt & 0xFF,
        }

    # ── Output control ────────────────────────────────────────────────────────

    async def _get_fun_bool(self) -> int:
        return await self._read_u16(ADDR_MCU, MCU.FUN_BOOL)

    async def _set_fun_bool(self, value: int) -> None:
        self._require_auth()
        await self._send_enc(
            build_write_nr(ADDR_MCU, MCU.FUN_BOOL, struct.pack("<H", value))
        )

    async def _get_fun_bool2(self) -> int:
        return await self._read_u16(ADDR_MCU, MCU.FUN_BOOL2)

    async def _set_fun_bool2(self, value: int) -> None:
        self._require_auth()
        await self._send_enc(
            build_write_nr(ADDR_MCU, MCU.FUN_BOOL2, struct.pack("<H", value))
        )

    async def _set_fun_bool2_bit(self, mask: int, enable: bool) -> None:
        current = await self._get_fun_bool2()
        new_val = (current | mask) if enable else (current & ~mask)
        await self._set_fun_bool2(new_val)

    async def set_ac_output(self, enable: bool) -> None:
        """Enable or disable the AC outlet."""
        current = await self._get_fun_bool()
        new_val = (current | FUNBOOL_AC_OUTPUT) if enable else (current & ~FUNBOOL_AC_OUTPUT)
        await self._set_fun_bool(new_val)
        logger.info("AC output %s", "enabled" if enable else "disabled")

    async def set_dc_output(self, enable: bool) -> None:
        """Enable or disable the DC 12V port."""
        current = await self._get_fun_bool()
        new_val = (current | FUNBOOL_DC_OUTPUT) if enable else (current & ~FUNBOOL_DC_OUTPUT)
        await self._set_fun_bool(new_val)
        logger.info("DC output %s", "enabled" if enable else "disabled")

    async def set_ups_mode(self, enable: bool) -> None:
        """Enable or disable UPS (uninterruptible power) mode."""
        await self._set_fun_bool2_bit(FUNBOOL2_UPS, enable)
        logger.info("UPS mode %s", "enabled" if enable else "disabled")

    async def set_super_power(self, enable: bool) -> None:
        """Enable or disable super power drive mode."""
        await self._set_fun_bool2_bit(FUNBOOL2_SUPER_PWR, enable)
        logger.info("Super power drive %s", "enabled" if enable else "disabled")

    async def set_key_tone(self, enable: bool) -> None:
        """Enable or disable button press beep."""
        await self._set_fun_bool2_bit(FUNBOOL2_KEY_TONE, enable)
        logger.info("Key tone %s", "enabled" if enable else "disabled")

    async def set_fan_low_startup(self, enable: bool) -> None:
        """Set fan startup mode: True = low speed, False = high speed."""
        await self._set_fun_bool2_bit(FUNBOOL2_FAN_LOW, enable)
        logger.info("Fan low startup %s", "enabled" if enable else "disabled")

    async def set_ac_frequency(self, hz: int) -> None:
        """Set AC output frequency (50 or 60 Hz)."""
        if hz not in (50, 60):
            raise ValueError("Frequency must be 50 or 60 Hz")
        self._require_auth()
        await self._send_enc(
            build_write_nr(ADDR_MCU, MCU.FREQUENCY, struct.pack("<H", hz))
        )

    async def set_ac_input_limit(self, watts: int) -> None:
        """Set AC charging input power limit in watts."""
        self._require_auth()
        await self._send_enc(
            build_write_nr(ADDR_MCU, MCU.AC_INPUT_PWR_LIMIT, struct.pack("<H", watts))
        )

    async def set_ac_standby(self, minutes: int) -> None:
        """Set AC output auto-off idle time in minutes (0 = never)."""
        self._require_auth()
        await self._send_enc(
            build_write_nr(ADDR_MCU, MCU.AC_STANDBY_TIME, struct.pack("<H", minutes))
        )

    async def set_dc_standby(self, minutes: int) -> None:
        """Set DC output auto-off idle time in minutes (0 = never)."""
        self._require_auth()
        await self._send_enc(
            build_write_nr(ADDR_MCU, MCU.DC_STANDBY_TIME, struct.pack("<H", minutes))
        )

    async def set_device_standby(self, minutes: int) -> None:
        """Set device auto-power-off idle time in minutes (0 = never)."""
        self._require_auth()
        await self._send_enc(
            build_write_nr(ADDR_MCU, MCU.DEVICE_STANDBY_TIME, struct.pack("<H", minutes))
        )

    async def set_screen_time(self, minutes: int) -> None:
        """Set screen display timeout in minutes (0 = always on)."""
        self._require_auth()
        await self._send_enc(
            build_write_nr(ADDR_MCU, MCU.SCREEN_DISPLAY_TIME, struct.pack("<H", minutes))
        )

    async def set_unix_time(self, timestamp: int) -> None:
        """Sync device real-time clock to a Unix timestamp (seconds since epoch)."""
        self._require_auth()
        await self._send_enc(
            build_write_nr(ADDR_MCU, MCU.UNIX_TIME, struct.pack("<I", timestamp))
        )

    # ── Diagnostics ───────────────────────────────────────────────────────────

    async def get_errors(self) -> dict:
        """
        Read error and warning code registers.

        Returns:
            error_raw    — raw uint16 bitmask from ERROR_CODE register
            warn_raw     — raw uint16 bitmask from WARN_CODE register
            errors       — list of active error strings
            warnings     — list of active warning strings
        """
        error_raw = await self._read_u16(ADDR_MCU, MCU.ERROR_CODE)
        warn_raw  = await self._read_u16(ADDR_MCU, MCU.WARN_CODE)
        errors   = [msg for bit, msg in ERROR_BITS.items() if error_raw & bit]
        warnings = [msg for bit, msg in WARN_BITS.items() if warn_raw  & bit]
        return {
            "error_raw": error_raw,
            "warn_raw":  warn_raw,
            "errors":    errors,
            "warnings":  warnings,
        }

    async def get_temperatures(self) -> dict:
        """
        Read the temperature array (MCU reg 171, 10 bytes).

        Format: 10 × uint8, each byte is a temperature in °C (signed).
        Confirmed by cross-checking byte 0 against SOC_TEMP register.
        Returns dict of sensor_name → temperature in °C (int).
        """
        raw = await self._read_reg(ADDR_MCU, MCU.TEMP, 10)
        return dict(zip(TEMP_SENSOR_NAMES, struct.unpack("10b", raw)))

    async def get_features(self) -> dict:
        """
        Read MCU FunSupBool to discover which features this device supports.

        Returns dict of feature_name → bool.
        """
        raw = await self._read_u16(ADDR_MCU, MCU.FUN_SUP_BOOL)
        # Determine max AC input limit variant
        ac_bits = raw & (FUNSUP_AC_LIMIT_1250 | FUNSUP_AC_LIMIT_1650)
        if ac_bits == FUNSUP_AC_LIMIT_1650:
            max_ac_limit = 1650
        elif ac_bits == FUNSUP_AC_LIMIT_1250:
            max_ac_limit = 1250
        else:
            max_ac_limit = None
        return {
            "frequency_switch": bool(raw & FUNSUP_FREQUENCY),
            "max_ac_input_w":   max_ac_limit,
            "ac_standby":       bool(raw & FUNSUP_AC_STANDBY),
            "dc_standby":       bool(raw & FUNSUP_DC_STANDBY),
            "device_standby":   bool(raw & FUNSUP_DEV_STANDBY),
            "screen_timeout":   bool(raw & FUNSUP_SCREEN_TIME),
            "raw":              raw,
        }

    # ── BMS extended data ─────────────────────────────────────────────────────

    async def get_bms_info(self, bms_num: int = 1) -> dict:
        """
        Read battery module info (bms_num 1..5).

        NOTE: BMS register layout may vary by hardware revision.
        Raw bytes are included alongside decoded values.
        Use --probe 0x41 (BMS1) to discover actual registers on a device.
        """
        if bms_num < 1 or bms_num > 5:
            raise ValueError("bms_num must be 1-5")
        dst = BMS_ADDRS[bms_num - 1]

        # Battery pack snapshot (reg 49, 12 bytes).
        #   [2:4]  current_ma (LE uint16)
        #   [8:12] cell_temps — 4 × uint8 °C
        info_raw = await self._read_reg(dst, BMS.BATTERY_INFO, 12)
        current    = struct.unpack_from("<H", info_raw, 2)[0]   # mA
        cell_temps = list(info_raw[8:12])  # 4 cell temps in °C

        # Individual cell voltages (reg 64, 32 bytes = 16 × uint16 mV)
        cv_raw  = await self._read_reg(dst, BMS.CELL_VOLTAGE, 32)
        cell_mv = [struct.unpack_from("<H", cv_raw, i * 2)[0] for i in range(16)]
        pack_mv = sum(cell_mv)

        # Full/design capacity (reg 85, uint16, mAh)
        full_cap_mah = await self._read_u16(dst, BMS.FULL_CAP_MAH)

        # Reg 138 (REMAIN_CAP): usable design capacity in Wh (not current remaining)
        remain_cap_wh = await self._read_u16(dst, BMS.REMAIN_CAP)

        # Cycle count (reg 27)
        cycles = await self._read_u16(dst, BMS.CYCLE_COUNT)

        # Deep discharge event count (reg 39)
        deep_dc = await self._read_u16(dst, BMS.DEEP_DISCHARGE)

        # Manufacturing date (reg 32): raw encoding, device-specific format
        mfg_raw = await self._read_u16(dst, BMS.MFG_DATE)

        # Lifetime energy throughput (reg 128, 4 bytes, uint32 Wh)
        energy_raw = await self._read_reg(dst, BMS.ENERGY_THROUGH, 4)
        energy_wh  = struct.unpack_from("<I", energy_raw)[0]

        # Lifetime capacity throughput (reg 130, 4 bytes, uint32 mAh)
        cap_raw = await self._read_reg(dst, BMS.CAP_THROUGH, 4)
        cap_mah = struct.unpack_from("<I", cap_raw)[0]

        # Extreme condition durations (regs 134/136, 4 bytes each, uint32 minutes)
        ext_chg_raw = await self._read_reg(dst, BMS.EXTREME_CHARGE, 4)
        ext_chg_min = struct.unpack_from("<I", ext_chg_raw)[0]

        ext_use_raw = await self._read_reg(dst, BMS.EXTREME_USE, 4)
        ext_use_min = struct.unpack_from("<I", ext_use_raw)[0]

        # Firmware version reported by MCU for this BMS slot
        fw_reg = MCU.BMS1_FW_VER + (bms_num - 1)
        fw_ver = await self._read_u16(ADDR_MCU, fw_reg)

        return {
            "bms_num":            bms_num,
            # Confirmed values
            "pack_voltage_mv":    pack_mv,        # sum of 16 cell voltages in mV
            "cell_voltages_mv":   cell_mv,        # 16 individual cell voltages in mV
            "current_ma":         current,         # current draw in mA
            "remain_cap_wh":      remain_cap_wh,   # design/usable capacity in Wh (not current remaining)
            "full_cap_mah":       full_cap_mah,    # design capacity in mAh
            "cycle_count":        cycles,
            "cell_temps_c":       cell_temps,      # 4 cell temps in °C
            "deep_discharge":     deep_dc,
            "mfg_raw":            f"0x{mfg_raw:04x}",
            "energy_through_wh":  energy_wh,
            "cap_through_mah":    cap_mah,
            "extreme_charge_min": ext_chg_min,
            "extreme_use_min":    ext_use_min,
            "raw_info_hex":       info_raw.hex(),
            "fw_ver":             f"{fw_ver >> 8}.{fw_ver & 0xFF}",
        }

    # ── Module probing ────────────────────────────────────────────────────────

    async def probe_module(
        self,
        dst: int,
        reg_start: int = 0,
        reg_end: int = 60,
        n_bytes: int = 2,
        timeout: float = 2.0,
    ) -> dict:
        """
        Read a range of registers from any module address, skipping timeouts.

        Useful for discovering register layouts on ADDR_PV (0x15),
        ADDR_INVS (0x11), ADDR_INVP (0x16), or unknown modules.

        Returns dict of reg_index → bytes.
        """
        self._require_auth()
        results = {}
        for reg in range(reg_start, reg_end + 1):
            try:
                data = await asyncio.wait_for(
                    self._read_reg(dst, reg, n_bytes), timeout=timeout
                )
                results[reg] = data
            except (PowerCubeError, asyncio.TimeoutError):
                pass
        return results

    # ── Raw access ────────────────────────────────────────────────────────────

    async def send_raw(
        self,
        src: int, dst: int, cmd: int,
        arg: int = 0, payload: bytes = b"",
        timeout: float = 5.0,
    ) -> NinebotFrame:
        """Send an arbitrary Ninebot frame (encrypted) and return the response."""
        self._require_auth()
        inner = build_inner_frame(src, dst, cmd, arg=arg, payload=payload)
        return await self._request(inner, timeout=timeout)


# ── BLE device discovery ──────────────────────────────────────────────────────

async def scan_for_powercube(
    timeout: float = 10.0,
    ble_name: str = "PowerCube",
) -> list[tuple[str | None, str]]:
    """
    Scan for PowerCube devices over BLE.

    Returns a list of (name, address) tuples for each device found that
    advertises the Ninebot UART service (NUS) or whose name contains ble_name.
    Returns an empty list if no devices are found within timeout seconds.
    """
    from bleak import BleakScanner

    found: list[tuple[str | None, str]] = []

    def cb(device, adv):
        uuids = [str(u).lower() for u in (adv.service_uuids or [])]
        name  = device.name or ""
        if ble_name.lower() in name.lower() or any("6e400001" in u for u in uuids):
            found.append((device.name, device.address))

    async with BleakScanner(cb):
        await asyncio.sleep(timeout)

    return found


async def find_device_address(ble_name: str, timeout: float = 10.0) -> Optional[str]:
    """Scan and return the address of the first device matching ble_name."""
    from bleak import BleakScanner

    result: list = []

    def cb(device, adv):
        if device.name and ble_name.lower() in device.name.lower() and not result:
            result.append(device.address)

    try:
        async with asyncio.timeout(timeout):
            async with BleakScanner(cb):
                while not result:
                    await asyncio.sleep(0.1)
    except TimeoutError:
        pass

    return result[0] if result else None


