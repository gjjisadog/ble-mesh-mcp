"""Small, pure helpers for Xiaomi RXFER frame parsing and acknowledgements."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from .constants import (
    RXFER_MODE_NAMES,
    RXFER_TYPE_NAMES,
    RxferAck,
    RxferManagement,
    RxferMode,
    RxferType,
)

M_FEATURE_REQUEST = bytes((0, 0, RxferMode.MNG_CMD, RxferManagement.M_FEATURE))
M_FEATURE_RESPONSE = bytes((0, 0, RxferMode.MNG_ACK, RxferManagement.M_FEATURE))
M_LENGTH_REQUEST = bytes((0, 0, RxferMode.MNG_CMD, RxferManagement.M_LENGTH))
M_LENGTH_RESPONSE = bytes((0, 0, RxferMode.MNG_ACK, RxferManagement.M_LENGTH))


@dataclass(frozen=True)
class RxferFrame:
    sequence: int
    mode: int | None = None
    data_type: int | None = None
    body: bytes = b""

    @property
    def is_control(self) -> bool:
        return self.sequence == 0


class RxferError(RuntimeError):
    pass


def parse_frame(data: bytes) -> RxferFrame:
    raw = bytes(data)
    if len(raw) < 2:
        raise ValueError("RXFER frame must contain a two-byte sequence number")
    sequence = int.from_bytes(raw[:2], "little")
    if sequence != 0:
        return RxferFrame(sequence=sequence, body=raw[2:])
    if len(raw) < 4:
        raise ValueError("RXFER control frame must contain mode and type bytes")
    return RxferFrame(
        sequence=0,
        mode=raw[2],
        data_type=raw[3],
        body=raw[4:],
    )


def parse_segment_command_count(data: bytes, expected_type: RxferType) -> int | None:
    """Return the count from a SEG_CMD for the requested RXFER data type."""
    try:
        frame = parse_frame(data)
    except ValueError:
        return None
    if (
        not frame.is_control
        or frame.mode != RxferMode.SEG_CMD
        or frame.data_type != expected_type
        or len(frame.body) != 2
    ):
        return None
    return int.from_bytes(frame.body, "little")


def control_fields(characteristic: str, data: bytes) -> dict[str, object]:
    if characteristic != "0016":
        return {}
    try:
        frame = parse_frame(data)
    except ValueError:
        return {}
    if not frame.is_control:
        return {
            "rxfer_segment": {
                "sequence": frame.sequence,
                "payload_length": len(frame.body),
            }
        }

    mode = int(frame.mode)
    data_type = int(frame.data_type)
    if mode in (RxferMode.SEG_ACK, RxferMode.SGL_ACK):
        type_name = RxferAck(data_type).name if data_type in RxferAck._value2member_map_ else "UNKNOWN_ACK"
    elif mode in (RxferMode.MNG_CMD, RxferMode.MNG_ACK):
        type_name = (
            RxferManagement(data_type).name
            if data_type in RxferManagement._value2member_map_ else "UNKNOWN_MANAGEMENT"
        )
    else:
        type_name = RXFER_TYPE_NAMES.get(data_type, "UNKNOWN")
    result: dict[str, object] = {
        "mode": mode,
        "mode_name": RXFER_MODE_NAMES.get(mode, "UNKNOWN"),
        "type": data_type,
        "type_name": type_name,
    }
    if mode == RxferMode.SEG_CMD and len(frame.body) == 2:
        result["segment_count"] = int.from_bytes(frame.body, "little")
    return {"rxfer_control": result}


def encode_management_ack(request: bytes) -> bytes:
    frame = parse_frame(request)
    if not frame.is_control or frame.mode != RxferMode.MNG_CMD:
        raise ValueError("Expected an RXFER MNG_CMD request")
    if frame.data_type == RxferManagement.M_FEATURE:
        if len(frame.body) != 2:
            raise ValueError("M_FEATURE request must contain two feature bytes")
    elif frame.data_type == RxferManagement.M_LENGTH:
        if len(frame.body) < 1:
            raise ValueError("M_LENGTH request must contain a length payload")
    else:
        raise ValueError(f"Unsupported RXFER management command: {frame.data_type}")
    return bytes((0, 0, RxferMode.MNG_ACK, frame.data_type)) + frame.body


def encode_segment_ack(ack: RxferAck, missing_sequences: tuple[int, ...] = ()) -> bytes:
    ack = RxferAck(ack)
    if ack == RxferAck.A_LOST:
        if not missing_sequences:
            raise ValueError("A_LOST requires at least one missing sequence number")
        if len(missing_sequences) > 6:
            raise ValueError("A_LOST supports at most six missing sequence numbers")
        body = b"".join(int(number).to_bytes(2, "little") for number in missing_sequences)
    else:
        if missing_sequences:
            raise ValueError("Missing sequence numbers are valid only with A_LOST")
        body = b""
    return bytes((0, 0, RxferMode.SEG_ACK, ack)) + body


def encode_single_ack(ack: RxferAck) -> bytes:
    ack = RxferAck(ack)
    if ack not in (RxferAck.A_SUCCESS, RxferAck.A_BUSY, RxferAck.A_CANCEL):
        raise ValueError("unsupported RXFER single-frame acknowledgement")
    return bytes((0, 0, RxferMode.SGL_ACK, ack))


def reassemble_segments(segments: dict[int, bytes], segment_count: int) -> bytes:
    expected = set(range(1, segment_count + 1))
    actual = set(segments)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"RXFER segments incomplete (missing={missing}, extra={extra})")
    return b"".join(bytes(segments[number]) for number in range(1, segment_count + 1))


def encode_single_command(data_type: RxferType, payload: bytes) -> bytes:
    if not payload:
        raise ValueError("RXFER single command payload must not be empty")
    return bytes((0, 0, RxferMode.SGL_CMD, RxferType(data_type))) + bytes(payload)


def encode_segment_command(data_type: RxferType, segment_count: int) -> bytes:
    if not 1 <= segment_count <= 0xFFFF:
        raise ValueError("RXFER segment count must fit uint16")
    return (
        bytes((0, 0, RxferMode.SEG_CMD, RxferType(data_type)))
        + segment_count.to_bytes(2, "little")
    )


async def send_rxfer_data(
    notification_queue: asyncio.Queue[tuple[str, bytes]],
    data_type: RxferType,
    payload: bytes,
    dmtu: int,
    simultaneous_retransmissions: int,
    write_frame: Callable[[bytes], Awaitable[None]],
    *,
    max_write_size: int,
    deadline: float,
    max_retransmissions: int = 3,
) -> None:
    """Send one RXFER payload using the device's SGL/SEG ACK handshake.

    The callback and exceptions deliberately omit payload bytes because callers
    may send authentication material. The caller owns negotiation and logging.
    """
    data_type = RxferType(data_type)
    data = bytes(payload)
    if not data or not 3 <= dmtu <= 255 or simultaneous_retransmissions < 1:
        raise ValueError("invalid RXFER payload, DMTU or retransmission capability")
    if max_retransmissions < 0:
        raise ValueError("max_retransmissions must not be negative")
    if max_write_size < 4:
        raise RxferError("BLE characteristic cannot carry RXFER control frames")

    loop = asyncio.get_running_loop()

    async def write(value: bytes) -> None:
        if len(value) > max_write_size:
            raise RxferError("BLE write limit is smaller than the RXFER frame")
        if deadline <= loop.time():
            raise RxferError("RXFER send deadline expired")
        await write_frame(value)

    async def next_ack(expected_mode: RxferMode) -> RxferFrame:
        deferred: list[tuple[str, bytes]] = []
        try:
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise RxferError("RXFER acknowledgement timed out")
                try:
                    item = await asyncio.wait_for(notification_queue.get(), remaining)
                except asyncio.TimeoutError as exc:
                    raise RxferError("RXFER acknowledgement timed out") from exc
                sid, raw = item
                if sid == "0016":
                    try:
                        frame = parse_frame(raw)
                    except ValueError:
                        pass
                    else:
                        if frame.is_control and frame.mode == expected_mode:
                            return frame
                deferred.append(item)
        finally:
            for item in deferred:
                notification_queue.put_nowait(item)

    if simultaneous_retransmissions > 1 and len(data) <= dmtu - 2:
        if max_write_size < len(data) + 4:
            raise RxferError("BLE write limit is smaller than the RXFER single frame")
        await write(encode_single_command(data_type, data))
        ack = await next_ack(RxferMode.SGL_ACK)
        if ack.data_type != RxferAck.A_SUCCESS or ack.body:
            raise RxferError(f"RXFER single command rejected with ACK {ack.data_type}")
        return

    chunks = tuple(data[offset:offset + dmtu] for offset in range(0, len(data), dmtu))
    if max_write_size < len(chunks[0]) + 2:
        raise RxferError("BLE write limit is smaller than the RXFER data frame")
    await write(encode_segment_command(data_type, len(chunks)))
    ready = await next_ack(RxferMode.SEG_ACK)
    if ready.data_type != RxferAck.A_READY or ready.body:
        raise RxferError(f"RXFER segmented command rejected with ACK {ready.data_type}")
    for sequence, chunk in enumerate(chunks, 1):
        await write(sequence.to_bytes(2, "little") + chunk)

    for attempt in range(max_retransmissions + 1):
        ack = await next_ack(RxferMode.SEG_ACK)
        if ack.data_type == RxferAck.A_SUCCESS and not ack.body:
            return
        if ack.data_type != RxferAck.A_LOST or not ack.body or len(ack.body) % 2:
            raise RxferError(f"RXFER segmented transfer rejected with ACK {ack.data_type}")
        if attempt >= max_retransmissions:
            raise RxferError("RXFER segmented transfer exceeded retransmission limit")
        missing = tuple(
            int.from_bytes(ack.body[index:index + 2], "little")
            for index in range(0, len(ack.body), 2)
        )
        if not all(1 <= sequence <= len(chunks) for sequence in missing):
            raise RxferError("RXFER requested an invalid segment retransmission")
        for sequence in missing:
            await write(sequence.to_bytes(2, "little") + chunks[sequence - 1])


async def receive_segmented_data(
    notification_queue: asyncio.Queue[tuple[str, bytes]],
    segment_count: int,
    dmtu: int,
    write_frame: Callable[[bytes], Awaitable[None]],
    record: Callable[[dict[str, Any]], None],
    deadline: float,
    address: str,
    data_type: str,
    max_retransmissions: int = 3,
) -> tuple[bytes, int]:
    """Receive one SEG_CMD body, acknowledge it and request missing segments."""
    if segment_count < 1 or dmtu < 1:
        raise RxferError("segment_count and DMTU must be positive")

    acknowledgements_sent = 0
    ready_ack = encode_segment_ack(RxferAck.A_READY)
    await write_frame(ready_ack)
    acknowledgements_sent += 1
    record({
        "event": "write_rxfer_segment_ready_sent",
        "address": address,
        "characteristic": "0016",
        "ack": RxferAck.A_READY.name,
        "hex": ready_ack.hex(" ").upper(),
        "raw_bytes": list(ready_ack),
    })

    loop = asyncio.get_running_loop()
    segments: dict[int, bytes] = {}
    for attempt in range(max_retransmissions + 1):
        while len(segments) < segment_count:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise RxferError(
                    f"Timed out receiving {data_type} segments; received {sorted(segments)} of {segment_count}"
                )
            try:
                characteristic, frame = await asyncio.wait_for(
                    notification_queue.get(), min(0.5, remaining)
                )
            except asyncio.TimeoutError:
                break

            if characteristic != "0016" or len(frame) < 3:
                continue
            try:
                segment = parse_frame(frame)
            except ValueError:
                continue
            sequence = segment.sequence
            if not 1 <= sequence <= segment_count:
                continue
            payload = segment.body
            if sequence < segment_count and len(payload) != dmtu:
                record({
                    "event": "rxfer_segment_rejected",
                    "address": address,
                    "sequence": sequence,
                    "expected_payload_length": dmtu,
                    "actual_payload_length": len(payload),
                    "hex": frame.hex(" ").upper(),
                    "raw_bytes": list(frame),
                })
                continue
            if not 1 <= len(payload) <= dmtu:
                record({
                    "event": "rxfer_segment_rejected",
                    "address": address,
                    "sequence": sequence,
                    "expected_payload_length_range": [1, dmtu],
                    "actual_payload_length": len(payload),
                    "hex": frame.hex(" ").upper(),
                    "raw_bytes": list(frame),
                })
                continue

            previous = segments.get(sequence)
            if previous is not None:
                if previous != payload:
                    raise RxferError(f"Conflicting RXFER retransmission for sequence {sequence}")
                record({
                    "event": "rxfer_segment_duplicate",
                    "address": address,
                    "sequence": sequence,
                    "payload_length": len(payload),
                })
            else:
                segments[sequence] = payload
                record({
                    "event": "rxfer_segment_received",
                    "address": address,
                    "data_type": data_type,
                    "sequence": sequence,
                    "segment_count": segment_count,
                    "payload_length": len(payload),
                    "hex": frame.hex(" ").upper(),
                    "raw_bytes": list(frame),
                })

        missing = [sequence for sequence in range(1, segment_count + 1) if sequence not in segments]
        if not missing:
            break
        if attempt >= max_retransmissions:
            raise RxferError(f"{data_type} still missing RXFER segments after retries: {missing}")

        try:
            lost_ack = encode_segment_ack(RxferAck.A_LOST, tuple(missing))
        except ValueError as exc:
            raise RxferError(str(exc)) from exc
        await write_frame(lost_ack)
        acknowledgements_sent += 1
        record({
            "event": "write_rxfer_lost_segments_ack_sent",
            "address": address,
            "characteristic": "0016",
            "ack": RxferAck.A_LOST.name,
            "missing_sequences": missing,
            "hex": lost_ack.hex(" ").upper(),
            "raw_bytes": list(lost_ack),
        })

    payload = reassemble_segments(segments, segment_count)
    success_ack = encode_segment_ack(RxferAck.A_SUCCESS)
    await write_frame(success_ack)
    acknowledgements_sent += 1
    record({
        "event": "write_rxfer_segment_success_sent",
        "address": address,
        "characteristic": "0016",
        "ack": RxferAck.A_SUCCESS.name,
        "hex": success_ack.hex(" ").upper(),
        "raw_bytes": list(success_ack),
    })
    return payload, acknowledgements_sent
