"""
crypto.py — AES-CCM variant BLE frame encryption for the Segway PowerCube.

Algorithm:
  - SHA1-derived AES-128 key: SHA1(key1[:16] || key2_or_zero[:16])[:16]
  - No-SN mode (counter=0, PRE_COMM): XOR with repeating AES_ECB(zero_key, sha_key)
  - With-SN mode (counter>0): AES-CTR keystream + 4-byte CBC-MAC tag

Wire frame layout (encrypt output):
  [5a a5 len][XOR'd body][trailer]
  trailer (no-SN):   [00 00 ~sum_lo ~sum_hi 00 00]
  trailer (with-SN): [tag4][ctr_plus1_BE2]
"""

import hashlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _aes_ecb_block(key: bytes, block: bytes) -> bytes:
    """AES-128 ECB encrypt a single 16-byte block."""
    c = Cipher(algorithms.AES(key), modes.ECB())
    enc = c.encryptor()
    return enc.update(block) + enc.finalize()


# --- Constants ---

# Fixed 16-byte value used as the default key2 when key2=None,
# and as the AES plaintext block for no-SN keystream generation.
ZERO_KEY = bytes.fromhex("97cfb802844143de56002b3b34780a5d")


# --- Core crypto ---

def _sha1_derive_aes_key(key1: bytes | None, key2: bytes | None) -> bytes:
    """SHA1(key1[:16] || key2_or_zero[:16])[:16]"""
    k1 = (key1 + b"\x00" * 16)[:16] if key1 else ZERO_KEY
    k2 = (key2 + b"\x00" * 16)[:16] if key2 else ZERO_KEY
    return hashlib.sha1(k1 + k2).digest()[:16]


def _cbc_mac(key: bytes, b0: bytes, adata_block: bytes, body: bytes) -> bytes:
    """
    CBC-MAC over B0 || adata_block || body (zero-padded to 16-byte boundary).
    adata_block must already be 16 bytes.
    """
    T = _aes_ecb_block(key, b0)
    T = _aes_ecb_block(key, bytes(x ^ y for x, y in zip(adata_block, T)))
    padded = body + bytes((-len(body)) % 16)
    for i in range(0, len(padded), 16):
        T = _aes_ecb_block(key, bytes(x ^ y for x, y in zip(padded[i:i + 16], T)))
    return T


class FrameEncryption:
    """
    Encrypts and decrypts Segway PowerCube BLE frames.

    The device uses a session-key handshake:
      - PRE_COMM (no-SN, counter=0): key = SHA1(ble_name || ZERO_KEY)
      - AUTH / COMM (with-SN, counter>0): key = SHA1(mKeyPwd || mKeyAuth)

    Usage (PRE_COMM → AUTH handshake):

        enc = FrameEncryption()

        # PRE_COMM (no-SN, counter=0)
        enc.setKey(b"PowerCube", None)
        tx = enc.encrypt_frame(build_inner_frame(ADDR_HOST, ADDR_BLE, CMD_AUTH_PROBE))
        plaintext = enc.decrypt_frame(rx)
        mKeyAuth = plaintext[7:23]

        enc.setAuthParam(mKeyAuth)
        enc.start_sn()          # counter → 1

        # AUTH (with-SN, counter=1)
        enc.setKey(mKeyPwd, mKeyAuth)
        tx = enc.encrypt_frame(build_inner_frame(ADDR_HOST, ADDR_BLE, CMD_AUTH_PAIR,
                                                  payload=serial_bytes))
    """

    def __init__(self) -> None:
        self._key1: bytes | None = None
        self._key2: bytes | None = None
        self._auth_param: bytes = bytes(16)
        self._counter: int = 0

    def setKey(self, key1: bytes, key2: bytes | None) -> None:
        """Set the primary and secondary key material."""
        self._key1 = key1
        self._key2 = key2

    def setAuthParam(self, auth_param: bytes) -> None:
        """Store 16-byte auth parameter (session nonce from device)."""
        self._auth_param = (auth_param + bytes(16))[:16]

    def reset_sn(self) -> None:
        """Reset counter to 0 (no-SN mode)."""
        self._counter = 0

    def start_sn(self) -> None:
        """Activate with-SN mode: counter → 1."""
        self._counter = 1

    # Keep legacy names used by client.py
    crypto_setKey = setKey
    crypto_setAuthParam = setAuthParam
    crypto_reset_sn = reset_sn
    crypto_start_sn = start_sn

    # --- Private helpers ---

    def _aes_key(self) -> bytes:
        return _sha1_derive_aes_key(self._key1, self._key2)

    def _nonce12(self, ctr_plus1: int) -> bytes:
        """12-byte nonce = ctr_plus1_BE(4) || auth_param[0:8]."""
        return struct.pack(">I", ctr_plus1) + self._auth_param[:8]

    def _ctr_block(self, ctr_plus1: int, block_i: int) -> bytes:
        """16-byte AES-CTR block: [0x01][nonce12][0x00 0x00][block_i]."""
        return bytes([0x01]) + self._nonce12(ctr_plus1) + bytes([0x00, 0x00, block_i & 0xFF])

    def _b0_block(self, ctr_plus1: int, body_len: int) -> bytes:
        """16-byte CBC-MAC B0 block: [0x59][nonce12][0x00 0x00][body_len]."""
        return bytes([0x59]) + self._nonce12(ctr_plus1) + bytes([0x00, 0x00, body_len & 0xFF])

    # --- High-level frame encrypt / decrypt ---

    def encrypt_frame(self, plaintext: bytes) -> bytes:
        """
        Encrypt a raw frame and return the encrypted wire bytes.

        plaintext: complete frame [5a a5 len src dst cmd arg [payload]]
        Returns:   [5a a5 len][encrypted_body][6-byte trailer]
        """
        length = len(plaintext)
        if length < 7:
            raise ValueError(f"Frame too short: {length} bytes")

        key = self._aes_key()
        header = plaintext[:3]   # 5a a5 len (not encrypted)
        body   = plaintext[3:]   # src dst cmd arg [payload]
        body_len = len(body)

        if self._counter == 0:
            # No-SN mode: repeating AES_ECB(zero_key, sha_key) keystream
            ks = _aes_ecb_block(key, ZERO_KEY)
            enc_body = bytes(b ^ ks[i % 16] for i, b in enumerate(body))

            s   = sum(body) & 0xFFFF
            chk = (~s) & 0xFFFF
            trailer = b"\x00\x00" + struct.pack("<H", chk) + b"\x00\x00"
        else:
            # With-SN mode: AES-CTR encryption + 4-byte CBC-MAC tag
            ctr_plus1 = self._counter + 1
            self._counter = ctr_plus1

            # Encrypt body: blocks indexed from 1
            enc_body_list = []
            block_i = 1
            offset = 0
            while offset < body_len:
                ks = _aes_ecb_block(key, self._ctr_block(ctr_plus1, block_i))
                chunk = body[offset:offset + 16]
                enc_body_list.append(bytes(b ^ ks[j] for j, b in enumerate(chunk)))
                offset += len(chunk)
                block_i += 1
            enc_body = b"".join(enc_body_list)

            # CBC-MAC over plaintext body
            b0    = self._b0_block(ctr_plus1, body_len)
            adata = header + bytes(13)   # 16-byte Adata block (header zero-padded)
            T     = _cbc_mac(key, b0, adata, body)

            # Encrypt tag with A0 (block_i=0) keystream
            enc_a0   = _aes_ecb_block(key, self._ctr_block(ctr_plus1, 0))
            wire_tag = bytes(t ^ k for t, k in zip(T[:4], enc_a0))

            # Trailer: [tag4][ctr_plus1 big-endian 2 bytes]
            trailer = wire_tag + struct.pack(">H", ctr_plus1 & 0xFFFF)

        return header + enc_body + trailer

    def decrypt_frame(self, ciphertext: bytes) -> bytes | None:
        """
        Decrypt an encrypted wire frame.

        ciphertext: [5a a5 len][encrypted_body][6-byte trailer]
        Returns:    decrypted [5a a5 len][body] on success, None on failure.

        Updates internal counter on success (replay protection).
        """
        if len(ciphertext) < 13:
            return None
        if ciphertext[:2] != b"\x5a\xa5":
            return None

        key      = self._aes_key()
        header   = ciphertext[:3]
        trailer  = ciphertext[-6:]
        enc_body = ciphertext[3:-6]
        body_len = len(enc_body)

        if self._counter == 0:
            # No-SN mode
            ks = _aes_ecb_block(key, ZERO_KEY)
            body = bytes(b ^ ks[i % 16] for i, b in enumerate(enc_body))

            s   = sum(body) & 0xFFFF
            chk = (~s) & 0xFFFF
            stored_chk = struct.unpack_from("<H", trailer, 2)[0]
            if chk != stored_chk:
                return None
            return header + body

        else:
            # With-SN mode: extract counter from trailer[4:6] (big-endian)
            ctr_plus1 = struct.unpack_from(">H", trailer, 4)[0]
            if ctr_plus1 <= self._counter:
                return None   # replay / out-of-order

            # Decrypt body
            body_parts = []
            block_i = 1
            offset = 0
            while offset < body_len:
                ks = _aes_ecb_block(key, self._ctr_block(ctr_plus1, block_i))
                chunk = enc_body[offset:offset + 16]
                body_parts.append(bytes(b ^ ks[j] for j, b in enumerate(chunk)))
                offset += len(chunk)
                block_i += 1
            body = b"".join(body_parts)

            # Decrypt tag: wire_tag XOR AES(A0) → expected T[:4]
            enc_a0     = _aes_ecb_block(key, self._ctr_block(ctr_plus1, 0))
            expected_T = bytes(t ^ k for t, k in zip(trailer[:4], enc_a0))

            # Recompute CBC-MAC over decrypted body
            b0    = self._b0_block(ctr_plus1, body_len)
            adata = header + bytes(13)
            T     = _cbc_mac(key, b0, adata, body)

            if T[:4] != expected_T:
                return None

            self._counter = ctr_plus1
            return header + body
