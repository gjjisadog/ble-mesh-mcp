"""Strict offline replay of a normalized, captured Mesh registration.

The input is a local analysis format, not a claimed Xiaomi Cloud JSON schema.
Each result is bound to one exact device exchange and LTMK digest. In particular,
a recorded SERVER_SIGN cannot authenticate a fresh ECDH session.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from .mesh_binding import MeshRegistrationContext, MeshRegistrationRequest


def _hex_field(record: Mapping[str, Any], field: str) -> bytes:
    value = record[field]
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a hex string")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field} is not valid hex") from exc


class ReplayCredentialProvider:
    """Validate a local transcript through the credential-provider protocol."""

    def __init__(self, transcript: Mapping[str, Any]) -> None:
        if transcript.get("format") != "xiaomi-mesh-replay-v1":
            raise ValueError("expected normalized xiaomi-mesh-replay-v1 format")
        begin = transcript["begin_registration"]
        sign = transcript["server_signature"]
        verify = transcript["device_verify_result"]
        if not isinstance(begin, Mapping) or not isinstance(sign, Mapping) or not isinstance(verify, Mapping):
            raise ValueError("begin_registration, server_signature and device_verify_result must be objects")
        mesh_config = transcript["mesh_provision"]
        if not isinstance(mesh_config, Mapping):
            raise ValueError("mesh_provision must be an object")

        self._request = MeshRegistrationRequest(
            pid=int(begin["pid"]),
            mac=str(begin["mac"]),
            manufacturer_sn=_hex_field(begin, "manufacturer_sn_hex"),
            device_certificate_der=_hex_field(begin, "device_certificate_der_hex"),
            device_ephemeral_public_key=_hex_field(begin, "device_ephemeral_public_key_hex"),
        )
        self._certificate = _hex_field(transcript, "server_certificate_der_hex")
        self._ltmk_digest = _hex_field(sign, "ltmk_digest_hex")
        self._server_signature = _hex_field(sign, "signature_hex")
        self._device_signature = _hex_field(verify, "signature_hex")
        self._device_accepted = verify["accepted"]
        if not isinstance(self._device_accepted, bool):
            raise ValueError("device_verify_result.accepted must be boolean")
        self._expected_success = transcript.get("registration_success")
        if self._expected_success is not None and not isinstance(self._expected_success, bool):
            raise ValueError("registration_success must be boolean when provided")
        self._mesh_config = deepcopy(dict(mesh_config))
        self._stage = 0
        self._handle = "replay:0"

        if len(self._ltmk_digest) != 32 or len(self._server_signature) != 64:
            raise ValueError("replay requires a 32-byte LTMK digest and 64-byte SERVER_SIGN")
        if len(self._device_signature) != 64:
            raise ValueError("replay requires a 64-byte DEV_SIGNATURE")

    @classmethod
    def from_json_file(cls, path: str | Path) -> ReplayCredentialProvider:
        with Path(path).open("r", encoding="utf-8") as stream:
            return cls(json.load(stream))

    def _require(self, handle: str, stage: int) -> None:
        if handle != self._handle:
            raise ValueError("unknown replay handle")
        if self._stage != stage:
            raise RuntimeError(f"replay stage {self._stage}; expected {stage}")

    async def begin_registration(
        self, request: MeshRegistrationRequest
    ) -> MeshRegistrationContext:
        if self._stage != 0:
            raise RuntimeError("replay already started")
        if request != self._request:
            raise ValueError("device identity differs from recorded registration")
        self._stage = 1
        return MeshRegistrationContext(self._handle, self._certificate)

    async def sign_ltmk(self, registration_id: str, ltmk_hash: bytes) -> bytes:
        self._require(registration_id, 1)
        if bytes(ltmk_hash) != self._ltmk_digest:
            raise ValueError("LTMK digest differs; recorded signature cannot be replayed")
        self._stage = 2
        return self._server_signature

    async def verify_device(
        self, registration_id: str, device_signature: bytes
    ) -> None:
        self._require(registration_id, 2)
        if bytes(device_signature) != self._device_signature:
            raise ValueError("DEV_SIGNATURE differs from recorded registration")
        if not self._device_accepted:
            raise ValueError("recorded device verification failed")
        self._stage = 3

    async def get_mesh_config(self, registration_id: str) -> Mapping[str, object]:
        self._require(registration_id, 3)
        self._stage = 4
        return deepcopy(self._mesh_config)

    async def finish_registration(self, registration_id: str, success: bool) -> None:
        self._require(registration_id, 4)
        if not isinstance(success, bool):
            raise ValueError("success must be boolean")
        if self._expected_success is not None and success != self._expected_success:
            raise ValueError("registration result differs from recorded registration")
        self._stage = 5
