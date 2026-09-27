"""Offline client side of the Xiaomi Mesh 0x50 Admin Login exchange.

This module handles payloads and authentication state only. A caller sends
``start()`` on FE95/0010, then sends ``public_key_payload()`` as RXFER type
ECC_PUBKEY (0x03) on FE95/0016. The device's 64-byte ECC_PUBKEY payload goes
to ``accept_device_public_key()``; its return value is sent as RXFER type
DEV_LOGIN_INFO (0x05). Finally, pass the device's 0010 opcode to ``complete()``.
No BLE connection, cloud request, credential storage, or secret logging occurs.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass
from enum import Enum

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import MeshAuthOpcode


LOGIN_SALT = b"miot-mesh-login-salt"
LOGIN_INFO = b"miot-mesh-login-info"
LOGIN_NONCE = bytes(range(0x10, 0x1C))


class LoginState(str, Enum):
    NEW = "new"
    STARTED = "started"
    PUBLIC_KEY_SENT = "public_key_sent"
    WAIT_RESULT = "wait_result"
    AUTHENTICATED = "authenticated"
    FAILED = "failed"


class MeshLoginError(RuntimeError):
    """Admin Login failed or the device reported a failure opcode."""


@dataclass(frozen=True, repr=False)
class MeshSession:
    """64-byte session_ctx_t: dev_key, app_key, dev_iv, app_iv, reserve."""

    material: bytes

    def __post_init__(self) -> None:
        if len(self.material) != 64:
            raise ValueError("Mesh session material must be 64 bytes")

    def __repr__(self) -> str:
        return "MeshSession(<redacted>)"

    @property
    def device_key(self) -> bytes:
        return self.material[0:16]

    @property
    def application_key(self) -> bytes:
        return self.material[16:32]

    @property
    def device_iv(self) -> int:
        return int.from_bytes(self.material[32:36], "little")

    @property
    def application_iv(self) -> int:
        return int.from_bytes(self.material[36:40], "little")


class MeshAdminLogin:
    """Single-use, transport-independent 0x50 login state machine."""

    def __init__(
        self,
        gatt_ltmk: bytes,
        *,
        private_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> None:
        key = bytes(gatt_ltmk)
        if len(key) != 32:
            raise ValueError("GATT_LTMK must be exactly 32 bytes")
        if private_key is None:
            private_key = ec.generate_private_key(ec.SECP256R1())
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("ephemeral private key must use P-256")
        self._gatt_ltmk = key
        self._private_key: ec.EllipticCurvePrivateKey | None = private_key
        self._public_key = private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )[1:]
        self._session: MeshSession | None = None
        self.state = LoginState.NEW

    def __repr__(self) -> str:
        return f"MeshAdminLogin(state={self.state.value}, secrets=<redacted>)"

    def start(self) -> bytes:
        """Return little-endian 0x50 opcode for FE95/0010."""
        self._require(LoginState.NEW)
        self.state = LoginState.STARTED
        return int(MeshAuthOpcode.MESH_ADMIN_LOGIN_START).to_bytes(4, "little")

    def public_key_payload(self) -> bytes:
        """Return 64-byte X||Y payload for RXFER ECC_PUBKEY (0x03)."""
        self._require(LoginState.STARTED)
        self.state = LoginState.PUBLIC_KEY_SENT
        return self._public_key

    def accept_device_public_key(self, payload: bytes) -> bytes:
        """Derive session and return 4-byte CRC32 ciphertext + 4-byte CCM MIC.

        The returned eight bytes are the RXFER DEV_LOGIN_INFO (0x05) payload.
        They do not include RXFER framing.
        """
        self._require(LoginState.PUBLIC_KEY_SENT)
        device_public = bytes(payload)
        if len(device_public) != 64:
            self._fail()
            raise ValueError("device ECC_PUBKEY payload must be 64 bytes")
        try:
            point = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), b"\x04" + device_public
            )
            if self._private_key is None:
                raise MeshLoginError("ephemeral key is unavailable")
            shared_secret = self._private_key.exchange(ec.ECDH(), point)
            material = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=LOGIN_SALT,
                info=LOGIN_INFO,
            ).derive(shared_secret + self._gatt_ltmk)
            self._session = MeshSession(material)
            crc = zlib.crc32(device_public).to_bytes(4, "little")
            login_payload = AESCCM(self._session.application_key, tag_length=4).encrypt(
                LOGIN_NONCE, crc, None
            )
        except ValueError:
            self._fail()
            raise ValueError("invalid device ECC_PUBKEY payload") from None
        self._private_key = None
        self._gatt_ltmk = b""
        self.state = LoginState.WAIT_RESULT
        return login_payload

    def complete(self, opcode: bytes | bytearray | memoryview | int) -> MeshSession:
        """Accept 0x51 success or raise on 0x52/0x53/other result."""
        self._require(LoginState.WAIT_RESULT)
        if isinstance(opcode, (bytes, bytearray, memoryview)):
            raw_opcode = bytes(opcode)
            if len(raw_opcode) != 4:
                self._fail()
                raise ValueError("Admin Login opcode must be four bytes")
            value = int.from_bytes(raw_opcode, "little")
        else:
            value = int(opcode)
        if value != MeshAuthOpcode.MESH_ADMIN_LOGIN_SUCCESS:
            self._fail()
            if value == MeshAuthOpcode.MESH_ADMIN_INVALID_LTMK:
                raise MeshLoginError("device rejected GATT_LTMK (0x52)")
            if value == MeshAuthOpcode.MESH_ADMIN_LOGIN_FAILED:
                raise MeshLoginError("device rejected Admin Login (0x53)")
            raise MeshLoginError(f"unexpected Admin Login result opcode 0x{value:02X}")
        if self._session is None:
            self._fail()
            raise MeshLoginError("session is unavailable")
        self.state = LoginState.AUTHENTICATED
        return self._session

    @property
    def session(self) -> MeshSession:
        if self.state != LoginState.AUTHENTICATED or self._session is None:
            raise MeshLoginError("Admin Login has not succeeded")
        return self._session

    def _require(self, state: LoginState) -> None:
        if self.state != state:
            raise MeshLoginError(f"Admin Login state is {self.state.value}; expected {state.value}")

    def _fail(self) -> None:
        self.state = LoginState.FAILED
        self._session = None
        self._private_key = None
        self._gatt_ltmk = b""
