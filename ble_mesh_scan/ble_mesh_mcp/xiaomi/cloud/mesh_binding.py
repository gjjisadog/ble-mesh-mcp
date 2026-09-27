"""Provisional credential contract for Xiaomi Mesh registration.

This module contains types only. It does not call Xiaomi services, store
account tokens, or create signing keys. It is not the X08A Miot Gateway RPC
wire contract: that gateway's device_auth response combines cert, pub, sign,
and did in one message.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol


@dataclass(frozen=True)
class MeshRegistrationRequest:
    """Device identity material available from the BLE registration exchange."""

    pid: int
    mac: str
    manufacturer_sn: bytes
    device_certificate_der: bytes
    device_ephemeral_public_key: bytes


@dataclass(frozen=True)
class MeshRegistrationContext:
    """Normalized transaction handle and server certificate for Mesh Auth.

    ``registration_id`` is an opaque provider handle. Its existence and wire
    representation in Xiaomi Cloud have not been confirmed.
    """

    registration_id: str
    server_certificate_der: bytes


class XiaomiMeshCredentialProvider(Protocol):
    """Early logical interface; methods do not correspond 1:1 to OT RPCs."""

    async def begin_registration(
        self, request: MeshRegistrationRequest
    ) -> MeshRegistrationContext:
        """Verify device identity and return the registration certificate."""
        ...

    async def sign_ltmk(self, registration_id: str, ltmk_hash: bytes) -> bytes:
        """Return the 64-byte P-256 SERVER_SIGN over SHA-256(LTMK).

        ``ltmk_hash`` is already hashed; providers must not hash it again.
        """
        ...

    async def verify_device(
        self, registration_id: str, device_signature: bytes
    ) -> None:
        """Submit DEV_SIGNATURE for server-side verification."""
        ...

    async def get_mesh_config(
        self, registration_id: str
    ) -> Mapping[str, object]:
        """Return normalized provisioning data; its wire schema is unknown."""
        ...

    async def finish_registration(
        self, registration_id: str, success: bool
    ) -> None:
        """Report the final registration result to the provider."""
        ...
