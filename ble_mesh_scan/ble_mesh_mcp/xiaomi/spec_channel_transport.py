"""RXFER framing used by the old Mi Home SpecV2 writer on FE95/001A.

This layer transports an already encrypted secure-channel packet. It does not
choose an MIoT property or create a control command.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from .constants import RxferAck, RxferMode, RxferType
from .rxfer import encode_segment_ack, encode_single_ack, parse_frame


class SpecTransportError(RuntimeError):
    def __init__(self, message: str, *, transport_accepted: bool = False) -> None:
        super().__init__(message)
        self.transport_accepted = transport_accepted


def encode_write_start(packet_length: int, dmtu: int) -> bytes:
    """Old SpecWriteChannelManager calls ChannelWriter.write(..., type=0).

    That call uses RXFER SEG_CMD even when there is only one data segment.
    """
    if not 1 <= packet_length <= dmtu or not 1 <= dmtu <= 255:
        raise ValueError("one encrypted packet must fit the negotiated DMTU")
    return bytes((0, 0, RxferMode.SEG_CMD, RxferType.PASS_THROUGH, 1, 0))


async def exchange(
    encrypted_packet: bytes,
    *,
    dmtu: int,
    incoming: asyncio.Queue[bytes],
    write: Callable[[bytes], Awaitable[None]],
    record: Callable[[str, bytes], None],
    response_incoming: asyncio.Queue[bytes] | None = None,
    write_response_ack: Callable[[bytes], Awaitable[None]] | None = None,
    on_transport_acked: Callable[[], None] | None = None,
    timeout: float = 12.0,
) -> bytes:
    """Send one 001A packet without retry and receive one framed response."""
    packet = bytes(encrypted_packet)
    start = encode_write_start(len(packet), dmtu)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    accepted = False
    response_queue = response_incoming if response_incoming is not None else incoming
    response_writer = write_response_ack if write_response_ack is not None else write

    async def read(queue: asyncio.Queue[bytes], channel: str) -> bytes:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise SpecTransportError(f"{channel} RXFER response timed out",
                                     transport_accepted=accepted)
        try:
            raw = await asyncio.wait_for(queue.get(), remaining)
        except asyncio.TimeoutError:
            raise SpecTransportError(f"{channel} RXFER response timed out",
                                     transport_accepted=accepted) from None
        record(f"{channel}:rx", raw)
        return raw

    async def send(raw: bytes, channel: str, writer: Callable[[bytes], Awaitable[None]]) -> None:
        record(f"{channel}:tx", raw)
        await writer(raw)

    await send(start, "001A", write)
    while True:
        frame = parse_frame(await read(incoming, "001A"))
        if frame.is_control and frame.mode == RxferMode.SEG_ACK:
            if frame.data_type != RxferAck.A_READY or frame.body:
                raise SpecTransportError(f"001A RXFER start rejected: {frame.data_type}")
            break
    await send(b"\x01\x00" + packet, "001A", write)
    while True:
        frame = parse_frame(await read(incoming, "001A"))
        if frame.is_control and frame.mode == RxferMode.SEG_ACK:
            if frame.data_type != RxferAck.A_SUCCESS or frame.body:
                raise SpecTransportError(f"001A RXFER data rejected: {frame.data_type}")
            accepted = True
            if on_transport_acked is not None:
                on_transport_acked()
            break

    return await receive_packet(
        incoming=response_queue, write_ack=response_writer, record=record,
        timeout=max(0.0, deadline - loop.time()),
    )


async def receive_packet(
    *,
    incoming: asyncio.Queue[bytes],
    write_ack: Callable[[bytes], Awaitable[None]],
    record: Callable[[str, bytes], None],
    timeout: float,
) -> bytes:
    """Receive and ACK one encrypted 001B RXFER packet without writing a request."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout

    async def read() -> bytes:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise SpecTransportError("001B RXFER response timed out", transport_accepted=True)
        try:
            raw = await asyncio.wait_for(incoming.get(), remaining)
        except asyncio.TimeoutError:
            raise SpecTransportError("001B RXFER response timed out",
                                     transport_accepted=True) from None
        record("001B:rx", raw)
        return raw

    async def send(raw: bytes) -> None:
        record("001B:tx", raw)
        await write_ack(raw)

    while True:
        frame = parse_frame(await read())
        if not frame.is_control or frame.data_type != RxferType.PASS_THROUGH:
            continue
        if frame.mode == RxferMode.SGL_CMD:
            if not frame.body:
                raise SpecTransportError("001B single response has no body",
                                         transport_accepted=True)
            await send(encode_single_ack(RxferAck.A_SUCCESS))
            return frame.body
        if frame.mode != RxferMode.SEG_CMD or len(frame.body) != 2:
            continue
        count = int.from_bytes(frame.body, "little")
        if not 1 <= count <= 64:
            raise SpecTransportError("001B invalid response segment count",
                                     transport_accepted=True)
        await send(encode_segment_ack(RxferAck.A_READY))
        chunks: dict[int, bytes] = {}
        while len(chunks) < count:
            part = parse_frame(await read())
            if not 1 <= part.sequence <= count or not part.body:
                continue
            previous = chunks.get(part.sequence)
            if previous is not None and previous != part.body:
                raise SpecTransportError("001B conflicting response segment",
                                         transport_accepted=True)
            chunks[part.sequence] = part.body
        await send(encode_segment_ack(RxferAck.A_SUCCESS))
        return b"".join(chunks[i] for i in range(1, count + 1))
