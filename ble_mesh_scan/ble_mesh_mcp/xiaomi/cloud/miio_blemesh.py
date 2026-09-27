"""Thin MiIO HTTP adapter for Xiaomi BLE Mesh account endpoints.

The endpoint names and request fields come from an older Mi Home build. Their
availability for a particular account, region, and device must be checked at
runtime. Mutating methods are invoked only by the explicit registration flow.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol


class MiioRequester(Protocol):
    async def miio_request(self, uri: str, data: dict[str, Any]) -> Any: ...


@dataclass(frozen=True)
class MeshAuthCloudMaterial:
    """The four device-auth fields observed in a successful MiIO response."""

    did: str
    server_certificate_der: bytes
    server_public_key: bytes
    server_signature: bytes


@dataclass(frozen=True)
class MeshControllerInfo:
    iv_index: int
    primary_netkey: bytes = field(repr=False)
    ctl_appkey: bytes = field(repr=False)


@dataclass(frozen=True)
class MeshModelElement:
    number: int
    model_ids: tuple[int, ...]


@dataclass(frozen=True)
class MeshModelInfo:
    pdid: int
    elements: tuple[MeshModelElement, ...]


@dataclass(frozen=True)
class MeshBindResult:
    address: int
    static_oob: bytes = field(repr=False)
    appkey: bytes = field(repr=False)
    appkey_id: str
    bind_id: str


def _hex_key(value: Any, name: str) -> bytes:
    if not isinstance(value, str) or len(value) != 32:
        raise ValueError(f"{name} must be a 16-byte hex key")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} is not hex") from exc


def _hex_integer(value: Any, name: str, bits: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer or hex string")
    try:
        number = int(value, 16) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer or hex string") from exc
    if not 0 <= number < (1 << bits):
        raise ValueError(f"{name} is outside {bits}-bit range")
    return number


def decode_auth_material(result: Mapping[str, Any]) -> MeshAuthCloudMaterial:
    """Decode server material without printing or persisting its raw values."""

    did = result.get("did")
    if not isinstance(did, (str, int)) or not str(did).strip():
        raise ValueError("device_auth result has no DID")

    def decode(name: str) -> bytes:
        value = result.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError(f"device_auth result has no {name}")
        try:
            padded = value + "=" * (-len(value) % 4)
            return base64.b64decode(padded, altchars=b"-_", validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError(f"device_auth result has invalid {name} encoding") from exc

    certificate = decode("server_cert")
    public_key = decode("pub")
    signature = decode("sign")
    if not certificate or len(public_key) != 64 or len(signature) != 64:
        raise ValueError("device_auth result has unexpected material lengths")
    return MeshAuthCloudMaterial(
        did=str(did).strip(),
        server_certificate_der=certificate,
        server_public_key=public_key,
        server_signature=signature,
    )


class XiaomiMiioBleMeshCloud:
    """Call Xiaomi account Mesh endpoints through one authenticated MiIO session."""

    def __init__(self, miio: MiioRequester) -> None:
        self._miio = miio

    async def get_controller_info(self) -> MeshControllerInfo:
        """Read the controller IV index and keys; never log their values."""
        result = await self._miio.miio_request("/v2/blemesh/ctl_info", {})
        if not isinstance(result, dict):
            raise ValueError("ctl_info returned a non-object result")
        netkey = result.get("primary_netkey")
        appkey = result.get("ctl_appkey")
        if not isinstance(netkey, dict) or not isinstance(appkey, dict):
            raise ValueError("ctl_info has no primary_netkey or ctl_appkey object")
        return MeshControllerInfo(
            iv_index=_hex_integer(result.get("iv_index"), "iv_index", 32),
            primary_netkey=_hex_key(netkey.get("key"), "primary_netkey.key"),
            ctl_appkey=_hex_key(appkey.get("key"), "ctl_appkey.key"),
        )

    async def get_model_info(self, pdid: int) -> MeshModelInfo:
        """Read the public element/model map for one product ID."""
        if isinstance(pdid, bool) or not isinstance(pdid, int) or not 0 < pdid <= 0xFFFF:
            raise ValueError("pdid must be a positive 16-bit integer")
        result = await self._miio.miio_request(
            "/v2/blemesh/query_model", {"pdid": pdid}
        )
        if not isinstance(result, dict) or not isinstance(result.get("elements"), list):
            raise ValueError("query_model has no elements array")
        elements = []
        for item in result["elements"]:
            if not isinstance(item, dict) or not isinstance(item.get("model_id"), list):
                raise ValueError("query_model contains an invalid element")
            number = item.get("num")
            if isinstance(number, bool) or not isinstance(number, int) or not 0 <= number <= 255:
                raise ValueError("query_model element num is outside uint8 range")
            model_ids = tuple(
                _hex_integer(value, "model_id", 32) for value in item["model_id"]
            )
            elements.append(MeshModelElement(number=number, model_ids=model_ids))
        return MeshModelInfo(pdid=pdid, elements=tuple(elements))

    async def query_device(self, did: str) -> dict[str, Any]:
        did = str(did).strip()
        if not did:
            raise ValueError("did is required")
        result = await self._miio.miio_request("/v2/blemesh/query_dev", {"did": did})
        if not isinstance(result, dict):
            raise ValueError("query_dev returned a non-object result")
        return result

    async def get_gatt_ltmk(self, did: str) -> bytes:
        result = await self.query_device(did)
        value = result.get("gatt_ltmk")
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError("query_dev did not return a 64-character gatt_ltmk")
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("query_dev returned a non-hex gatt_ltmk") from exc

    async def device_auth(self, params: Mapping[str, Any]) -> dict[str, Any]:
        """Submit one explicit /auth request; never continue to bind.

        `params` is the inner JSON object. MiIOService signs and wraps it in
        the outer `data` form field. No account secret or response is logged.
        """
        required = ("pdid", "dev_mesh_pub", "dev_cert", "manu_cert_id", "dev_info")
        missing = [name for name in required if not params.get(name)]
        if missing:
            raise ValueError("missing auth fields: " + ", ".join(missing))
        result = await self._miio.miio_request("/v2/blemesh/auth", dict(params))
        if not isinstance(result, dict):
            raise ValueError("auth returned a non-object result")
        return result

    async def device_auth_material(
        self, params: Mapping[str, Any]
    ) -> MeshAuthCloudMaterial:
        return decode_auth_material(await self.device_auth(params))

    async def device_bind(
        self, *, pdid: int, mac: str, did: str, device_signature: bytes
    ) -> MeshBindResult:
        """Call /bind once with the signature from the current BLE session.

        The X08A native client and old Mi Home both send token="". Callers
        must journal the attempt first and never automatically retry it.
        """
        if not 0 < pdid <= 0xFFFF or not re.fullmatch(
            r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", mac
        ) or not str(did).isdigit() or len(device_signature) != 64:
            raise ValueError("invalid bind identity or live device signature")
        result = await self._miio.miio_request("/v2/blemesh/bind", {
            "pdid": pdid,
            "mac": mac.upper(),
            "sign": base64.urlsafe_b64encode(device_signature).rstrip(b"=").decode("ascii"),
            "did": str(did),
            "token": "",
        })
        if not isinstance(result, dict):
            raise ValueError("bind returned a non-object result")
        appkey = result.get("appkey")
        if not isinstance(appkey, dict):
            raise ValueError("bind result has no appkey object")
        address = result.get("address")
        if isinstance(address, bool) or not isinstance(address, int) or not 1 <= address <= 0xFFFF:
            raise ValueError("bind result has an invalid unicast address")
        return MeshBindResult(
            address=address,
            static_oob=_hex_key(result.get("static_oob"), "static_oob"),
            appkey=_hex_key(appkey.get("key"), "appkey.key"),
            appkey_id=str(appkey.get("id", appkey.get("appkey_id", ""))),
            bind_id=str(appkey.get("bind_id", "")),
        )

    async def provision_done(self, *, did: str, device_key: bytes, static_oob: bytes) -> None:
        """Report device 0x41 success; do not call before that opcode."""
        if not str(did).isdigit() or len(device_key) != 16 or len(static_oob) != 16:
            raise ValueError("invalid provision_done material")
        await self._miio.miio_request("/v2/blemesh/provision_done", {
            "result": 0,
            "did": str(did),
            "device_key": device_key.hex(),
            "auth": hashlib.sha256(static_oob).digest()[:16].hex(),
        })
        # MiIOService has already required an outer result and outer code=0.
        # Historical clients check that outer code; its inner result is not a
        # documented object and may be a scalar.


def build_auth_params_from_capture(
    frame: bytes,
    device_certificate_der: bytes,
    *,
    pid: int,
    code: str = "123456",
    oob: int | None = None,
    manufacturer_sn_order: str = "legacy",
    base64_mode: str = "legacy",
) -> dict[str, Any]:
    """Build the older Mi Home /auth payload from a captured RXFER ECC frame.

    A saved ephemeral public key is suitable for endpoint compatibility checks.
    It must not be reused for a later live registration transaction.
    """
    if len(frame) != 88 or frame[2:4] != b"\x02\x03":
        raise ValueError("expected an 88-byte SGL_CMD ECC_PUBKEY frame")
    if not 0 < pid <= 0xFFFF:
        raise ValueError("pid must be a 16-bit positive integer")
    if not device_certificate_der:
        raise ValueError("device certificate is required")
    if manufacturer_sn_order not in ("legacy", "wire"):
        raise ValueError("manufacturer_sn_order must be legacy or wire")
    if base64_mode not in ("legacy", "standard"):
        raise ValueError("base64_mode must be legacy or standard")
    manufacturer_sn = frame[16:24]
    # Old Mi Home calls got.O00000Oo(byte[]), which hex-encodes the bytes in
    # reverse order. The X08A gateway analysis indicates wire order instead.
    if manufacturer_sn_order == "legacy":
        manufacturer_sn = manufacturer_sn[::-1]
    def encode(data: bytes) -> str:
        if base64_mode == "legacy":
            # grs.O00000Oo(byte[]) uses flags 24: URL-safe alphabet, no
            # line breaks, and no '=' padding.
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
        return base64.b64encode(data).decode("ascii")
    params: dict[str, Any] = {
        "pdid": pid,
        "dev_mesh_pub": encode(frame[24:88]),
        "dev_cert": encode(device_certificate_der),
        "manu_cert_id": manufacturer_sn.hex(),
        "dev_info": frame[4:16].hex(),
        "code": code,
    }
    if oob is not None:
        params["oob"] = oob
    return params
