"""Offline X08A-style Xiaomi Mesh provisioning payload construction.

The X08A gateway binary analysis documents this DeviceKey derivation and the
four TLVs. The older Mi Home client uses a different DeviceKey construction;
the target plug's final configuration profile remains to be confirmed.
Nothing in this module connects to BLE or Cloud.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from .cloud.miio_blemesh import MeshModelInfo


def _key16(value: bytes, name: str) -> bytes:
    raw = bytes(value)
    if len(raw) != 16:
        raise ValueError(f"{name} must be exactly 16 bytes")
    return raw


def _uint(value: int, bits: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << bits:
        raise ValueError(f"{name} must fit uint{bits}")
    return value


def _tlv(tag: int, value: bytes) -> bytes:
    if len(value) > 255:
        raise ValueError("TLV value is longer than 255 bytes")
    return bytes((tag, len(value))) + value


def derive_device_key_x08a(random16: bytes, static_oob: bytes) -> bytes:
    """X08A: SHA256(random16 || static_oob), XOR mirrored digest ends."""
    random16 = _key16(random16, "random16")
    static_oob = _key16(static_oob, "static_oob")
    digest = hashlib.sha256(random16 + static_oob).digest()
    return bytes(digest[index] ^ digest[31 - index] for index in range(16))


def encode_model_bindings(model_info: MeshModelInfo, appkey_index: int = 0) -> bytes:
    """Encode the observed 8-byte element/model/AppKey binding records."""
    _uint(appkey_index, 16, "appkey_index")
    records = bytearray()
    for element in model_info.elements:
        _uint(element.number, 16, "element number")
        for model_id in element.model_ids:
            _uint(model_id, 32, "model_id")
            records.extend(element.number.to_bytes(2, "little"))
            records.extend((model_id >> 16).to_bytes(2, "little"))
            records.extend((model_id & 0xFFFF).to_bytes(2, "little"))
            records.extend(appkey_index.to_bytes(2, "little"))
    if len(records) > 255:
        raise ValueError("model bind list exceeds the TLV8 length limit")
    return bytes(records)


@dataclass(frozen=True)
class MeshConfigArtifact:
    device_key: bytes = field(repr=False)
    plaintext: bytes = field(repr=False)
    encrypted_payload: bytes = field(repr=False)
    model_bind_count: int


class MeshConfigBuilder:
    """Build only an offline X08A-style TLV/CCM payload."""

    @staticmethod
    def build(
        *,
        random16: bytes,
        static_oob: bytes,
        netkey: bytes,
        netkey_index: int,
        flags: int,
        iv_index: int,
        unicast_address: int,
        appkey: bytes,
        appkey_index: int,
        model_info: MeshModelInfo,
    ) -> MeshConfigArtifact:
        static_oob = _key16(static_oob, "static_oob")
        netkey = _key16(netkey, "netkey")
        appkey = _key16(appkey, "appkey")
        _uint(netkey_index, 16, "netkey_index")
        _uint(flags, 8, "flags")
        _uint(iv_index, 32, "iv_index")
        _uint(unicast_address, 16, "unicast_address")
        _uint(appkey_index, 16, "appkey_index")
        if unicast_address == 0:
            raise ValueError("unicast_address cannot be zero")

        device_key = derive_device_key_x08a(random16, static_oob)
        provision_data = (
            netkey
            + netkey_index.to_bytes(2, "little")
            + bytes((flags,))
            + iv_index.to_bytes(4, "little")
            + unicast_address.to_bytes(2, "little")
        )
        appkey_data = (
            netkey_index.to_bytes(2, "little")
            + appkey_index.to_bytes(2, "little")
            + appkey
        )
        bindings = encode_model_bindings(model_info, appkey_index)
        plaintext = b"".join((
            _tlv(1, device_key),
            _tlv(2, provision_data),
            _tlv(3, appkey_data),
            _tlv(4, bindings),
        ))
        encrypted = AESCCM(static_oob, tag_length=4).encrypt(
            static_oob[:8], plaintext, None
        )
        return MeshConfigArtifact(
            device_key=device_key,
            plaintext=plaintext,
            encrypted_payload=encrypted,
            model_bind_count=len(bindings) // 8,
        )
