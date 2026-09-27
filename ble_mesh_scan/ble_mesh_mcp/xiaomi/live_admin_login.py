"""Fresh FE95/Bleak Admin Login after a completed registration."""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

from ..transport.bleak_transport import BleakTransport, short_uuid
from ..tools.mesh_reg_probe import ProbeError, wait_for_notification
from .admin_login import MeshAdminLogin, MeshSession
from .constants import RxferAck, RxferMode, RxferType
from .rxfer import (
    M_FEATURE_REQUEST, M_LENGTH_REQUEST, encode_management_ack,
    encode_single_ack, parse_frame, send_rxfer_data,
)


async def verify_admin_login(
    address: str, gatt_ltmk: bytes, *, scan_timeout: float = 20.0,
    progress: Callable[[str], None] | None = None,
    after_pub_ack_delay: float = 0.3,
    on_authenticated: Callable[[BleakTransport, MeshSession, asyncio.Queue[tuple[str, bytes]]], Awaitable[None]] | None = None,
    prelogin_notifications: dict[str, Callable[[Any, bytearray], None]] | None = None,
) -> bool:
    """Return True only after the target returns opcode 0x51.

    No session material or credential is logged or persisted.
    """
    login = MeshAdminLogin(gatt_ltmk)
    def mark(stage: str) -> None:
        if progress is not None:
            progress(stage)
    queue: asyncio.Queue[tuple[str, bytes]] = asyncio.Queue()
    mark("resolving_device")
    async with BleakTransport(address, scan_timeout) as transport:
        mark("connected")
        for sid in ("0010", "0016"):
            if sid not in transport.characteristics:
                raise ProbeError(f"FE95 {sid} is absent on the login connection")

        def on_notify(characteristic: Any, value: bytearray) -> None:
            sid = short_uuid(characteristic.uuid)
            raw = bytes(value)
            queue.put_nowait((sid, raw))
            if sid == "0010" and len(raw) == 4:
                mark(f"auth_opcode_0x{raw[0]:02x}")
            elif sid == "0016":
                try:
                    frame = parse_frame(raw)
                except ValueError:
                    return
                if frame.is_control:
                    mark(f"rxfer_mode_{frame.mode}_type_{frame.data_type}")

        await transport.start_notify("0010", on_notify)
        await transport.start_notify("0016", on_notify)
        for sid, callback in (prelogin_notifications or {}).items():
            if sid in ("0010", "0016"):
                raise ValueError("login notification subscriptions are managed internally")
            await transport.start_notify(sid, callback)
        await asyncio.sleep(0.2)
        await transport.write("0010", b"\xA4")
        mark("a4_sent")
        _, feature = await wait_for_notification(
            queue,
            lambda sid, raw: sid == "0016" and len(raw) == 6 and raw[:4] == M_FEATURE_REQUEST,
            5.0, "Admin Login RXFER feature request",
        )
        simultaneous, dmtu = feature[4:6]
        if simultaneous < 1 or dmtu < 3:
            raise ProbeError("Admin Login RXFER negotiation returned invalid parameters")
        transport.negotiated_dmtu = dmtu
        await transport.write("0016", encode_management_ack(feature))
        expected = bytes([dmtu]) * (dmtu - 2)
        _, length_request = await wait_for_notification(
            queue,
            lambda sid, raw: sid == "0016" and raw == M_LENGTH_REQUEST + expected,
            5.0, "Admin Login RXFER length request",
        )
        length_ack = encode_management_ack(length_request)
        secure = transport.characteristic("0016")
        loop = asyncio.get_running_loop()
        wait_until = loop.time() + 4.0
        while secure.max_write_without_response_size < len(length_ack) and loop.time() < wait_until:
            await asyncio.sleep(0.2)
        if secure.max_write_without_response_size < len(length_ack):
            raise ProbeError("BLE write limit is too small for Admin Login negotiation")
        await transport.write("0016", length_ack)
        mark("rxfer_negotiated")
        await asyncio.sleep(0.1)
        await transport.write("0010", login.start())
        mark("login_start_sent")
        deadline = loop.time() + 14.0

        async def write_frame(frame: bytes) -> None:
            await transport.write("0016", frame)

        async def send(data_type: RxferType, payload: bytes) -> None:
            await send_rxfer_data(
                notification_queue=queue, data_type=data_type, payload=payload,
                dmtu=dmtu, simultaneous_retransmissions=simultaneous,
                write_frame=write_frame,
                max_write_size=secure.max_write_without_response_size,
                deadline=deadline,
            )

        mark("client_pub_sending")
        await send(RxferType.ECC_PUBKEY, login.public_key_payload())
        mark("client_pub_acknowledged")

        def is_device_pub(sid: str, raw: bytes) -> bool:
            if sid != "0016":
                return False
            try:
                frame = parse_frame(raw)
            except ValueError:
                return False
            return frame.is_control and frame.mode == RxferMode.SGL_CMD and frame.data_type == RxferType.ECC_PUBKEY and len(frame.body) == 64

        _, raw_device_pub = await wait_for_notification(
            queue, is_device_pub, max(0.1, deadline - loop.time()), "device Admin Login ECC_PUBKEY"
        )
        device_pub = parse_frame(raw_device_pub).body
        await write_frame(encode_single_ack(RxferAck.A_SUCCESS))
        mark("device_pub_acknowledged")
        # The device-side RXFER task still has to leave its TX state and arm
        # the next RX buffer after consuming our ACK. An immediate next GATT
        # write can arrive before that scheduler transition.
        await asyncio.sleep(after_pub_ack_delay)
        mark("login_info_sending")
        await send(RxferType.DEV_LOGIN_INFO, login.accept_device_public_key(device_pub))
        mark("login_info_acknowledged")

        def login_result(sid: str, raw: bytes) -> bool:
            return sid == "0010" and len(raw) == 4 and raw[0] in (0x51, 0x52, 0x53) and raw[1:] == b"\0\0\0"

        _, status = await wait_for_notification(
            queue, login_result, max(0.1, deadline - loop.time()), "Admin Login result"
        )
        mesh_session = login.complete(status)
        mark("admin_login_0x51_verified")
        if on_authenticated is not None:
            await on_authenticated(transport, mesh_session, queue)
        return True
