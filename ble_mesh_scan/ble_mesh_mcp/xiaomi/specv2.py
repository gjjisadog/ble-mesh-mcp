"""Minimal plaintext MIoT SpecV2 boolean property packets.

The wire encryption and BLE characteristic are handled separately. This
module does not send data to a device.
"""

from __future__ import annotations

from dataclasses import dataclass


SPEC_V2_FLAG = 0x2000
SET_PROPERTY = 0
SET_PROPERTY_RESPONSE = 1


class SpecV2Error(ValueError):
    """Malformed or unexpected SpecV2 packet."""


@dataclass(frozen=True)
class SetPropertyResponse:
    tid: int
    siid: int
    piid: int
    status: int


def _header(payload: bytes, tid: int) -> bytes:
    if not 0 <= tid <= 0xFFFF:
        raise ValueError("tid must fit uint16")
    length = len(payload) + 4
    if length > 0x1FFF:
        raise ValueError("SpecV2 packet exceeds 13-bit length")
    return (SPEC_V2_FLAG | length).to_bytes(2, "little") + tid.to_bytes(2, "little")


def build_set_property(*, tid: int, siid: int, piid: int, value: bool) -> bytes:
    """Encode one boolean SetProperty; e.g. OFF(2,1) is 0C20TTTT0001020100010000."""
    if not isinstance(value, bool):
        raise TypeError("value must be bool")
    if not 0 <= siid <= 0xFF:
        raise ValueError("siid must fit uint8")
    if not 0 <= piid <= 0xFFFF:
        raise ValueError("piid must fit uint16")
    payload = (
        bytes((SET_PROPERTY, 1, siid))
        + piid.to_bytes(2, "little")
        + (1).to_bytes(2, "little")  # type=BOOL (0), length=1
        + bytes((int(value),))
    )
    return _header(payload, tid) + payload


def parse_set_property_response(
    packet: bytes, *, expected_tid: int, expected_siid: int, expected_piid: int,
) -> SetPropertyResponse:
    """Parse a single-property response with a 1-, 2-, or 4-byte signed code.

    The old client's exact response-code width has not yet been observed on
    PID 0x90C0. All surrounding fields must match the pending request. A
    caller must not treat an unrecognized response as success.
    """
    raw = bytes(packet)
    if len(raw) < 10:
        raise SpecV2Error("SetProperty response is truncated")
    framing = int.from_bytes(raw[0:2], "little")
    if framing & 0xE000 != SPEC_V2_FLAG:
        raise SpecV2Error("unexpected SpecV2 framing flag")
    if framing & 0x1FFF != len(raw):
        raise SpecV2Error("SpecV2 length mismatch")
    tid = int.from_bytes(raw[2:4], "little")
    if tid != expected_tid:
        raise SpecV2Error("SetProperty response transaction ID mismatch")
    if raw[4] != SET_PROPERTY_RESPONSE or raw[5] != 1:
        raise SpecV2Error("unexpected SetProperty response opcode/count")
    siid = raw[6]
    piid = int.from_bytes(raw[7:9], "little")
    if (siid, piid) != (expected_siid, expected_piid):
        raise SpecV2Error("SetProperty response property ID mismatch")
    code_bytes = raw[9:]
    if len(code_bytes) not in (1, 2, 4):
        raise SpecV2Error("unsupported SetProperty response code width")
    return SetPropertyResponse(tid, siid, piid,
                               int.from_bytes(code_bytes, "little", signed=True))
