"""Bounded CLI orchestration for the known FE95 Mesh Auth capture."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from ..transport.bleak_transport import BleakTransport, short_uuid
from ..xiaomi.constants import (
    UUID_CTRL,
    UUID_SECURE,
    RxferAck,
    RxferType,
)
from ..xiaomi.mesh_auth import MESH_REG_START, parse_mesh_ecc_frame
from ..xiaomi.rxfer import (
    M_FEATURE_REQUEST,
    M_LENGTH_REQUEST,
    RxferError,
    control_fields as rxfer_control_fields,
    encode_management_ack,
    encode_segment_ack,
    encode_single_ack,
    parse_segment_command_count,
    receive_segmented_data,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = PROJECT_ROOT / "logs"


class ProbeError(RuntimeError):
    pass


@dataclass
class LiveRegistrationSession:
    transport: BleakTransport
    notification_queue: asyncio.Queue[tuple[str, bytes]]
    dmtu: int
    retransmit_count: int
    deadline: float
    record: Callable[[dict[str, Any]], None]
    address: str
    device_signature: bytes | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def byte_fields(value: bytes) -> dict[str, Any]:
    data = bytes(value)
    return {
        "raw_bytes": list(data),
        "hex": data.hex(" ").upper(),
        "ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in data),
    }


async def wait_for_notification(
    queue: asyncio.Queue[tuple[str, bytes]],
    predicate: Callable[[str, bytes], bool],
    timeout: float,
    description: str,
) -> tuple[str, bytes]:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise ProbeError(f"Timed out waiting for {description}")
        try:
            characteristic, data = await asyncio.wait_for(queue.get(), remaining)
        except TimeoutError as exc:
            raise ProbeError(f"Timed out waiting for {description}") from exc
        if predicate(characteristic, data):
            return characteristic, data


async def receive_dev_cert(
    transport: BleakTransport,
    notification_queue: asyncio.Queue[tuple[str, bytes]],
    address: str,
    record: Callable[[dict[str, Any]], None],
    deadline: float,
    dmtu: int,
    save_certificate: bool = True,
) -> tuple[bytes, int, int]:
    """Receive only the device certificate RXFER message and acknowledge transport."""
    loop = asyncio.get_running_loop()
    remaining = deadline - loop.time()
    if remaining <= 0:
        raise ProbeError("Capture deadline expired before DEV_CERT header arrived")

    _, command = await wait_for_notification(
        notification_queue,
        lambda sid, data: sid == "0016"
        and parse_segment_command_count(data, RxferType.DEV_CERT) is not None,
        timeout=min(5.0, remaining),
        description="RXFER DEV_CERT segmented command",
    )
    segment_count = parse_segment_command_count(command, RxferType.DEV_CERT)
    if segment_count is None:
        raise ProbeError("Malformed RXFER DEV_CERT segmented command")
    if not 1 <= segment_count <= 32:
        raise ProbeError(f"DEV_CERT segment count outside safe capture bound: {segment_count}")
    record(
        {
            "event": "rxfer_dev_cert_transfer_started",
            "address": address,
            "segment_count": segment_count,
            "rxfer_dmtu": dmtu,
            **byte_fields(command),
        }
    )

    ready_ack = encode_segment_ack(RxferAck.A_READY)
    secure = transport.characteristic("0016")
    if secure.max_write_without_response_size < len(ready_ack):
        raise ProbeError("Windows/Bleak write limit is too small for RXFER segment acknowledgement")

    async def write_rxfer_frame(value: bytes) -> None:
        await transport.write("0016", value)

    try:
        certificate, acknowledgements_sent = await receive_segmented_data(
            notification_queue=notification_queue,
            segment_count=segment_count,
            dmtu=dmtu,
            write_frame=write_rxfer_frame,
            record=record,
            deadline=deadline,
            address=address,
            data_type="DEV_CERT",
        )
    except RxferError as exc:
        raise ProbeError(str(exc)) from exc

    certificate_event: dict[str, Any] = {
        "event": "dev_cert_reassembled",
        "address": address,
        "data_type": "DEV_CERT",
        "segment_count": segment_count,
        "payload_length": len(certificate),
        "sha256": hashlib.sha256(certificate).hexdigest(),
    }
    if save_certificate:
        certificate_path = LOG_DIR / f"dev_cert_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.bin"
        certificate_path.write_bytes(certificate)
        certificate_event["binary_file"] = str(certificate_path)
        certificate_event.update(byte_fields(certificate))
    record(certificate_event)
    return certificate, segment_count, acknowledgements_sent


async def run_probe(
    address: str,
    timeout: float,
    duration: float,
    capture_device_certificate: bool,
    on_ecc_pubkey: Callable[
        [bytes, bytes, LiveRegistrationSession], Awaitable[dict[str, Any]]
    ] | None = None,
    redact_capture: bool = False,
    send_server_material: bool = False,
    complete_registration: bool = False,
) -> Path:
    if on_ecc_pubkey is not None and not capture_device_certificate:
        raise ValueError("cloud auth callback requires certificate capture")
    if send_server_material and on_ecc_pubkey is None:
        raise ValueError("server material requires a cloud auth callback")
    if complete_registration and not send_server_material:
        raise ValueError("complete registration requires server materials")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / f"mesh_reg_probe_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    log_file = log_path.open("a", encoding="utf-8", newline="\n")
    notification_queue: asyncio.Queue[tuple[str, bytes]] = asyncio.Queue()

    def record(event: dict[str, Any]) -> None:
        event = dict(event)
        if redact_capture:
            for field in ("raw_bytes", "hex", "ascii"):
                event.pop(field, None)
            parsed = event.get("mesh_ecc_pubkey_parsed")
            if isinstance(parsed, dict):
                parsed = dict(parsed)
                for field in ("public_key_x_hex", "public_key_y_hex", "public_key_sec1_hex"):
                    parsed.pop(field, None)
                event["mesh_ecc_pubkey_parsed"] = parsed
        event.setdefault("timestamp_utc", utc_now())
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        log_file.write(line + "\n")
        log_file.flush()
        print(line, flush=True)

    record(
        {
            "event": "session_start",
            "address": address,
            "probe": (
                "mesh_reg_complete_transaction" if complete_registration
                else "mesh_reg_to_dev_signature" if send_server_material
                else "rxfer_negotiation_mesh_reg_start_and_dev_cert_capture"
            ),
            "post_start_policy": (
                (
                    "cloud_auth_then_bind_config_commit_and_login"
                    if complete_registration else
                    "cloud_auth_then_server_material_and_dev_signature_only"
                    if send_server_material
                    else "rxfer_transport_acks_for_dev_cert_and_ecc_then_cloud_auth"
                )
                if on_ecc_pubkey is not None
                else (
                    "rxfer_transport_acks_only_for_dev_cert"
                    if capture_device_certificate
                    else "passive_only_no_rxfer_ack_or_registration_payload"
                )
            ),
            "duration_seconds_after_start": duration,
        }
    )

    try:
        print(f"Resolving {address} from a fresh BLE scan...", flush=True)
        async with BleakTransport(address, timeout) as transport:
            record(
                {
                    "event": "connected",
                    "address": address,
                    "connected": transport.is_connected,
                    "mtu_size": transport.mtu_size,
                }
            )

            for service in transport.services:
                record(
                    {
                        "event": "service",
                        "address": address,
                        "uuid": service.uuid,
                        "description": service.description,
                    }
                )
            characteristics = transport.characteristics
            for sid, char in characteristics.items():
                record(
                    {
                        "event": "characteristic",
                        "address": address,
                        "characteristic": sid,
                        "uuid": char.uuid,
                        "handle": char.handle,
                        "properties": char.properties,
                        "description": char.description,
                        "max_write_without_response_size": getattr(
                            char, "max_write_without_response_size", None
                        ),
                    }
                )

            control = characteristics.get("0010")
            secure = characteristics.get("0016")
            if (
                control is None
                or secure is None
                or control.uuid.lower() != UUID_CTRL
                or secure.uuid.lower() != UUID_SECURE
            ):
                raise ProbeError("FE95 0010 and 0016 are both required for this probe")
            if "write-without-response" not in control.properties:
                raise ProbeError("FE95 0010 does not advertise write-without-response")
            if "write-without-response" not in secure.properties:
                raise ProbeError("FE95 0016 does not advertise write-without-response")
            if "notify" not in secure.properties and "indicate" not in secure.properties:
                raise ProbeError("FE95 0016 has no notify/indicate property")

            def on_notification(characteristic: Any, value: bytearray) -> None:
                sid = short_uuid(characteristic.uuid)
                data = bytes(value)
                notification_queue.put_nowait((sid, data))
                event = {
                    "event": "notification",
                    "address": address,
                    "characteristic": sid,
                    "uuid": characteristic.uuid,
                    "handle": characteristic.handle,
                    "payload_length": len(data),
                    **byte_fields(data),
                    **rxfer_control_fields(sid, data),
                }
                parsed_ecc = parse_mesh_ecc_frame(sid, data)
                if parsed_ecc is not None:
                    event["mesh_ecc_pubkey_parsed"] = parsed_ecc
                if sid == "0010" and data:
                    event["auth_opcode"] = data[0]
                record(event)

            await transport.start_notify("0010", on_notification)
            await transport.start_notify("0016", on_notification)
            record(
                {
                    "event": "notify_started",
                    "address": address,
                    "characteristics": ["0010", "0016"],
                }
            )
            await asyncio.sleep(0.3)

            await transport.write("0010", b"\xA4")
            record(
                {
                    "event": "write_transport_init_sent",
                    "address": address,
                    "characteristic": "0010",
                    **byte_fields(b"\xA4"),
                }
            )

            _, feature = await wait_for_notification(
                notification_queue,
                lambda sid, data: sid == "0016"
                and len(data) == 6
                and data[:4] == M_FEATURE_REQUEST,
                timeout=5.0,
                description="RXFER M_FEATURE request on 0016",
            )
            retransmit_count, dmtu = feature[4], feature[5]
            if dmtu < 3:
                raise ProbeError(f"Invalid RXFER DMTU {dmtu}")
            feature_ack = encode_management_ack(feature)
            await transport.write("0016", feature_ack)
            record(
                {
                    "event": "write_rxfer_feature_ack_sent",
                    "address": address,
                    "characteristic": "0016",
                    "retransmit_count": retransmit_count,
                    "rxfer_dmtu": dmtu,
                    **byte_fields(feature_ack),
                }
            )

            expected_length_data = bytes([dmtu]) * (dmtu - 2)
            _, length_request = await wait_for_notification(
                notification_queue,
                lambda sid, data: sid == "0016"
                and len(data) == 4 + len(expected_length_data)
                and data[:4] == M_LENGTH_REQUEST
                and data[4:] == expected_length_data,
                timeout=5.0,
                description=f"RXFER M_LENGTH request for DMTU {dmtu}",
            )
            length_ack = encode_management_ack(length_request)

            write_limit = secure.max_write_without_response_size
            limit_deadline = asyncio.get_running_loop().time() + 4.0
            while write_limit < len(length_ack) and asyncio.get_running_loop().time() < limit_deadline:
                await asyncio.sleep(0.25)
                write_limit = secure.max_write_without_response_size
            record(
                {
                    "event": "rxfer_length_ack_preflight",
                    "address": address,
                    "characteristic": "0016",
                    "required_write_size": len(length_ack),
                    "max_write_without_response_size": write_limit,
                }
            )
            if write_limit < len(length_ack):
                raise ProbeError(
                    "Windows/Bleak write limit is too small for the complete RXFER M_LENGTH acknowledgement; 0x40 was not sent"
                )

            await transport.write("0016", length_ack)
            record(
                {
                    "event": "write_rxfer_length_ack_sent",
                    "address": address,
                    "characteristic": "0016",
                    "rxfer_dmtu": dmtu,
                    **byte_fields(length_ack),
                }
            )

            await asyncio.sleep(0.1)
            await transport.write("0010", MESH_REG_START)
            record(
                {
                    "event": "write_mesh_reg_start_sent",
                    "address": address,
                    "characteristic": "0010",
                    "registration_opcode": "MESH_REG_START",
                    "post_start_writes": (
                        "cloud_server_material_after_auth"
                        if send_server_material else "transport_acks_only"
                    ),
                    **byte_fields(MESH_REG_START),
                }
            )

            loop = asyncio.get_running_loop()
            capture_started = loop.time()
            deadline = capture_started + duration
            rxfer_data_acknowledgements_sent = 0
            received_segment_count = None
            certificate = None
            cloud_auth_completed = False
            if capture_device_certificate:
                certificate, received_segment_count, rxfer_data_acknowledgements_sent = await receive_dev_cert(
                    transport,
                    notification_queue,
                    address,
                    record,
                    deadline,
                    dmtu,
                    save_certificate=not redact_capture,
                )
            if on_ecc_pubkey is not None:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise ProbeError("Capture deadline expired before ECC_PUBKEY arrived")
                _, ecc_frame = await wait_for_notification(
                    notification_queue,
                    lambda sid, data: parse_mesh_ecc_frame(sid, data) is not None,
                    timeout=remaining,
                    description="RXFER ECC_PUBKEY from current registration",
                )
                if certificate is None:
                    raise ProbeError("Certificate was not captured before ECC_PUBKEY")
                ecc_ack = encode_single_ack(RxferAck.A_SUCCESS)
                if secure.max_write_without_response_size < len(ecc_ack):
                    raise ProbeError("BLE write limit is too small for ECC_PUBKEY acknowledgement")
                await transport.write("0016", ecc_ack)
                rxfer_data_acknowledgements_sent += 1
                record({
                    "event": "write_rxfer_ecc_success_ack_sent",
                    "address": address,
                    "characteristic": "0016",
                    **byte_fields(ecc_ack),
                })
                record({
                    "event": "live_registration_material_ready",
                    "address": address,
                    "device_certificate_bytes": len(certificate),
                    "device_ecc_frame_bytes": len(ecc_frame),
                    "device_ecc_public_key_sha256": hashlib.sha256(ecc_frame[24:88]).hexdigest(),
                })
                session = LiveRegistrationSession(
                    transport=transport,
                    notification_queue=notification_queue,
                    dmtu=dmtu,
                    retransmit_count=retransmit_count,
                    deadline=deadline,
                    record=record,
                    address=address,
                )
                cloud_summary = await on_ecc_pubkey(certificate, ecc_frame, session)
                record({"event": "cloud_auth_complete", "address": address, **cloud_summary})
                cloud_auth_completed = True
            while on_ecc_pubkey is None and loop.time() < deadline and transport.is_connected:
                await asyncio.sleep(min(0.2, deadline - loop.time()))
            elapsed = loop.time() - capture_started
            record(
                {
                    "event": "capture_end",
                    "address": address,
                    "elapsed_seconds": round(elapsed, 3),
                    "connected_at_end": transport.is_connected,
                    "post_start_writes": rxfer_data_acknowledgements_sent + (
                        cloud_summary.get("registration_payloads_sent", 0)
                        + cloud_summary.get("additional_control_writes", 0)
                        if on_ecc_pubkey is not None else 0
                    ),
                    "rxfer_data_acknowledgements_sent": rxfer_data_acknowledgements_sent,
                    "dev_cert_segment_count": received_segment_count,
                    "registration_payloads_sent": (
                        cloud_summary.get("registration_payloads_sent", 0)
                        if on_ecc_pubkey is not None else 0
                    ),
                    "cloud_auth_completed": cloud_auth_completed,
                    "capture_complete": (
                        cloud_summary.get("registered", False) if complete_registration
                        else cloud_summary.get("device_signature_received", False)
                        if send_server_material
                        else cloud_auth_completed if on_ecc_pubkey is not None
                        else elapsed >= duration
                    ),
                }
            )
    except ProbeError as exc:
        record({"event": "probe_aborted", "address": address, "reason": str(exc)})
        raise
    except Exception as exc:
        record(
            {
                "event": "probe_error",
                "address": address,
                "error": (
                    type(exc).__name__ if redact_capture else f"{type(exc).__name__}: {exc}"
                ),
            }
        )
        raise
    finally:
        record({"event": "session_end", "address": address, "log_file": str(log_path)})
        log_file.close()
        print(f"Capture log: {log_path}", flush=True)

    return log_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Complete the observed RXFER negotiation, send MESH_REG_START once, "
            "then optionally acknowledge and capture only DEV_CERT RXFER segments."
        )
    )
    parser.add_argument("address", nargs="?", help="target BLE address")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument(
        "--duration",
        type=float,
        default=8.0,
        help="passive listen duration after MESH_REG_START, seconds",
    )
    parser.add_argument(
        "--receive-dev-cert",
        action="store_true",
        help="send RXFER transport ACKs needed to receive and reassemble DEV_CERT",
    )
    args = parser.parse_args()
    if args.address is None:
        parser.error("address is required")
    if args.timeout <= 0 or args.duration <= 0:
        parser.error("--timeout and --duration must be greater than zero")
    try:
        asyncio.run(
            run_probe(args.address, args.timeout, args.duration, args.receive_dev_cert)
        )
    except KeyboardInterrupt:
        print("Capture interrupted.", flush=True)
        return 130
    except Exception as exc:
        print(f"Mesh registration probe failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
