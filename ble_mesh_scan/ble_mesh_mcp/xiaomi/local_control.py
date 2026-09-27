"""ON/OFF control for the registered PID 0x90C0 lab plug."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from collections.abc import Callable

from ..transport.bleak_transport import BleakTransport
from .admin_login import MeshSession
from .live_admin_login import verify_admin_login
from .secure_channel import MiotBleSecureChannel
from .spec_channel_transport import SpecTransportError, exchange, receive_packet
from .specv2 import SpecV2Error, build_set_property, parse_set_property_response
from .constants import RxferAck, RxferMode
from .rxfer import parse_frame
from .device_config import load_device_config


@dataclass(frozen=True)
class PowerResult:
    requested_on: bool
    transport_acked: bool
    property_status: int
    protocol_verified: bool


@dataclass(frozen=True)
class PowerCycleResult:
    off: PowerResult
    on: PowerResult
    off_hold_seconds: float

    @property
    def protocol_verified(self) -> bool:
        return self.off.protocol_verified and self.on.protocol_verified


async def send_property_in_session(
    transport: BleakTransport,
    channel: MiotBleSecureChannel,
    write_replies: asyncio.Queue[bytes],
    read_replies: asyncio.Queue[bytes],
    *,
    value: bool,
    tid: int,
    timeout: float = 8.0,
    on_transport_acked: Callable[[], None] | None = None,
    on_unrelated_packet: Callable[[str, int], None] | None = None,
) -> PowerResult:
    """Send one property request, ignoring unrelated authenticated 001B notices."""
    if transport.negotiated_dmtu is None:
        raise RuntimeError("FE95 data transfer size was not negotiated")
    request = build_set_property(tid=tid, siid=2, piid=1, value=value)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    transport_acked = False

    def mark_acked() -> None:
        nonlocal transport_acked
        transport_acked = True
        if on_transport_acked is not None:
            on_transport_acked()

    write_response_ack = lambda frame: transport.write("001B", frame, response=False)
    response_wire = await exchange(
        channel.encrypt(request),
        dmtu=transport.negotiated_dmtu,
        incoming=write_replies,
        write=lambda frame: transport.write("001A", frame, response=False),
        response_incoming=read_replies,
        write_response_ack=write_response_ack,
        on_transport_acked=mark_acked,
        record=lambda _direction, _frame: None,
        timeout=timeout,
    )
    for _ in range(8):
        plaintext = channel.decrypt(response_wire)
        try:
            response = parse_set_property_response(
                plaintext, expected_tid=tid, expected_siid=2, expected_piid=1,
            )
        except SpecV2Error as exc:
            if on_unrelated_packet is not None:
                on_unrelated_packet(str(exc), len(plaintext))
            response_wire = await receive_packet(
                incoming=read_replies, write_ack=write_response_ack,
                record=lambda _direction, _frame: None,
                timeout=max(0.0, deadline - loop.time()),
            )
            continue
        return PowerResult(
            requested_on=value,
            transport_acked=transport_acked,
            property_status=response.status,
            protocol_verified=transport_acked and response.status == 0,
        )
    raise RuntimeError("too many unrelated 001B notifications")


async def _set_power(
    gatt_ltmk: bytes, *, value: bool, address: str | None = None,
) -> PowerResult:
    """Log in, send exactly one SetProperty, and verify the 001B reply.

    Physical power is not sensed by this function. Failure never triggers a
    second property write. The credential and session key stay in memory.
    """
    if len(gatt_ltmk) != 32:
        raise ValueError("GATT_LTMK must be exactly 32 bytes")
    write_replies: asyncio.Queue[bytes] = asyncio.Queue()
    read_replies: asyncio.Queue[bytes] = asyncio.Queue()
    result: PowerResult | None = None

    def on_write(_characteristic, value: bytearray) -> None:
        write_replies.put_nowait(bytes(value))

    def on_read(_characteristic, value: bytearray) -> None:
        read_replies.put_nowait(bytes(value))

    async def send_property(
        transport: BleakTransport, mesh_session: MeshSession,
        _login_queue: asyncio.Queue[tuple[str, bytes]],
    ) -> None:
        nonlocal result
        for sid in ("001A", "001B"):
            char = transport.characteristics.get(sid)
            if char is None or not {"write-without-response", "notify"}.issubset(char.properties):
                raise RuntimeError(f"FE95/{sid} write/notify is unavailable")
        channel = MiotBleSecureChannel(mesh_session)
        for queue in (write_replies, read_replies):
            while not queue.empty():
                queue.get_nowait()
        result = await send_property_in_session(
            transport, channel, write_replies, read_replies, value=value, tid=1,
        )

    await verify_admin_login(
        address or load_device_config().address, gatt_ltmk,
        on_authenticated=send_property,
        prelogin_notifications={"001A": on_write, "001B": on_read},
    )
    if result is None:
        raise RuntimeError("power request did not produce a property response")
    return result


async def power_on(gatt_ltmk: bytes) -> PowerResult:
    """Set the lab plug's siid=2/piid=1 property to true once."""
    return await _set_power(gatt_ltmk, value=True)


async def power_off(gatt_ltmk: bytes) -> PowerResult:
    """Set the lab plug's siid=2/piid=1 property to false once."""
    return await _set_power(gatt_ltmk, value=False)


async def power_cycle(gatt_ltmk: bytes, *, off_seconds: float = 5.0) -> PowerCycleResult:
    """Turn OFF, hold for at least off_seconds, then restore ON in one login.

    After an OFF attempt, an ON attempt is made even if OFF confirmation or the
    hold is interrupted. Neither property write is retried. Physical power is
    not independently sensed.
    """
    if len(gatt_ltmk) != 32:
        raise ValueError("GATT_LTMK must be exactly 32 bytes")
    if not 1.0 <= off_seconds <= 60.0:
        raise ValueError("off_seconds must be between 1 and 60")

    write_replies: asyncio.Queue[bytes] = asyncio.Queue()
    read_replies: asyncio.Queue[bytes] = asyncio.Queue()
    cycle: PowerCycleResult | None = None

    def on_write(_characteristic, value: bytearray) -> None:
        write_replies.put_nowait(bytes(value))

    def on_read(_characteristic, value: bytearray) -> None:
        read_replies.put_nowait(bytes(value))

    async def run_cycle(
        transport: BleakTransport, mesh_session: MeshSession,
        _login_queue: asyncio.Queue[tuple[str, bytes]],
    ) -> None:
        nonlocal cycle
        for sid in ("001A", "001B"):
            char = transport.characteristics.get(sid)
            if char is None or not {"write-without-response", "notify"}.issubset(char.properties):
                raise RuntimeError(f"FE95/{sid} write/notify is unavailable")
        channel = MiotBleSecureChannel(mesh_session)
        for queue in (write_replies, read_replies):
            while not queue.empty():
                queue.get_nowait()

        async def drain_idle_notifications() -> None:
            # Status notifications can arrive after the matching property reply.
            # ACK and authenticate them before starting a new RXFER exchange.
            for _ in range(32):
                while not write_replies.empty():
                    frame = parse_frame(write_replies.get_nowait())
                    if not (frame.is_control and frame.mode == RxferMode.SEG_ACK
                            and frame.data_type == RxferAck.A_SUCCESS):
                        raise RuntimeError("unexpected FE95/001A notification between commands")
                if read_replies.empty():
                    return
                try:
                    packet = await receive_packet(
                        incoming=read_replies,
                        write_ack=lambda frame: transport.write("001B", frame, response=False),
                        record=lambda _direction, _frame: None,
                        timeout=1.5,
                    )
                except SpecTransportError as exc:
                    if "timed out" in str(exc) and read_replies.empty():
                        return
                    raise
                channel.decrypt(packet)
            raise RuntimeError("too many pending FE95/001B notifications")

        off_attempted = False
        off: PowerResult | None = None
        on: PowerResult | None = None
        held = 0.0
        try:
            off_attempted = True
            off = await send_property_in_session(
                transport, channel, write_replies, read_replies,
                value=False, tid=1,
            )
            if not off.protocol_verified:
                raise RuntimeError(f"OFF property was not confirmed: status={off.property_status}")
            loop = asyncio.get_running_loop()
            off_confirmed_at = loop.time()
            await asyncio.sleep(off_seconds)
            await drain_idle_notifications()
            held = loop.time() - off_confirmed_at
        finally:
            if off_attempted:
                # Keep the connection alive through the recovery write even if
                # the caller cancels while the plug is intentionally OFF.
                restore = asyncio.create_task(send_property_in_session(
                    transport, channel, write_replies, read_replies,
                    value=True, tid=2,
                ))
                try:
                    on = await asyncio.shield(restore)
                except asyncio.CancelledError:
                    await restore
                    raise
                except Exception as exc:
                    raise RuntimeError(
                        "ON restoration failed; the plug may remain OFF"
                    ) from exc
                if not on.protocol_verified:
                    raise RuntimeError(f"ON restoration was not confirmed: status={on.property_status}")
        if off is None or on is None:
            raise RuntimeError("power cycle did not complete")
        cycle = PowerCycleResult(off=off, on=on, off_hold_seconds=held)

    await verify_admin_login(
        load_device_config().address, gatt_ltmk, on_authenticated=run_cycle,
        prelogin_notifications={"001A": on_write, "001B": on_read},
    )
    if cycle is None:
        raise RuntimeError("power cycle did not produce both property responses")
    return cycle
