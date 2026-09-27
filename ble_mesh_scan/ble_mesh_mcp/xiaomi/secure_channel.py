"""FE95/001A AES-CCM framing after Xiaomi Mesh Admin Login.

Only byte transformation and in-memory counters live here. Callers own BLE
I/O and must start a new instance for every successful 0x50/0x51 session.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from .admin_login import MeshSession


class SecureChannelError(ValueError):
    """Invalid authenticated packet or counter progression."""


class MiotBleSecureChannel:
    """Directional session keys with 16-bit sequence and bit15 epoch tracking."""

    def __init__(self, session: MeshSession | bytes) -> None:
        material = session.material if isinstance(session, MeshSession) else bytes(session)
        if len(material) != 64:
            raise ValueError("Admin Login session must be exactly 64 bytes")
        self._device_cipher = AESCCM(material[0:16], tag_length=4)
        self._application_cipher = AESCCM(material[16:32], tag_length=4)
        self._device_iv = material[32:36]
        self._application_iv = material[36:40]
        self._tx_seq = 0
        self._tx_epoch = 0
        self._rx_last_seq: int | None = None
        self._rx_epoch = 0

    def __repr__(self) -> str:
        return "MiotBleSecureChannel(<redacted>)"

    @staticmethod
    def _nonce(iv: bytes, seq: int, epoch: int) -> bytes:
        return iv + b"\x00" * 4 + seq.to_bytes(2, "little") + epoch.to_bytes(2, "little")

    @staticmethod
    def _next_counter(seq: int, epoch: int) -> tuple[int, int]:
        following = (seq + 1) & 0xFFFF
        if (seq ^ following) & 0x8000:
            if epoch == 0xFFFF:
                raise SecureChannelError("secure-channel epoch exhausted")
            epoch += 1
        return following, epoch

    def encrypt(self, plaintext: bytes) -> bytes:
        """Return seq_le16 || ciphertext || 4-byte MIC for FE95/001A."""
        payload = bytes(plaintext)
        if not payload:
            raise ValueError("secure-channel plaintext cannot be empty")
        seq, epoch = self._tx_seq, self._tx_epoch
        # Calculate the successor before encryption so an exhausted epoch can
        # never emit a packet whose nonce would be reused on the next call.
        next_seq, next_epoch = self._next_counter(seq, epoch)
        encrypted = self._application_cipher.encrypt(
            self._nonce(self._application_iv, seq, epoch), payload, None,
        )
        self._tx_seq, self._tx_epoch = next_seq, next_epoch
        return seq.to_bytes(2, "little") + encrypted

    def decrypt(self, wire: bytes) -> bytes:
        """Verify device→client MIC, then advance the receive epoch."""
        raw = bytes(wire)
        if len(raw) < 7:  # sequence, >=1 byte ciphertext, 4-byte MIC
            raise SecureChannelError("secure-channel notification is truncated")
        seq = int.from_bytes(raw[:2], "little")
        epoch = self._rx_epoch
        if self._rx_last_seq is not None:
            delta = (seq - self._rx_last_seq) & 0xFFFF
            if not 0 < delta < 0x8000:
                raise SecureChannelError("duplicate or out-of-order device sequence")
            if (seq ^ self._rx_last_seq) & 0x8000:
                if epoch == 0xFFFF:
                    raise SecureChannelError("secure-channel receive epoch exhausted")
                epoch += 1
        try:
            plaintext = self._device_cipher.decrypt(
                self._nonce(self._device_iv, seq, epoch), raw[2:], None,
            )
        except InvalidTag:
            raise SecureChannelError("secure-channel MIC verification failed") from None
        self._rx_last_seq = seq
        self._rx_epoch = epoch
        return plaintext
