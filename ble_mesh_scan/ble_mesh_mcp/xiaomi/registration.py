"""One live post-signature Xiaomi Mesh registration transaction.

The caller already owns a fresh 0x40 BLE session and its 64-byte device
signature. This module never retries /bind or /provision_done. Its journal
contains stage metadata only; keys, OOB and signatures stay in memory.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
from typing import Any

from ..tools.mesh_reg_probe import LiveRegistrationSession, ProbeError, wait_for_notification
from .cloud.miio_blemesh import MeshControllerInfo, MeshModelInfo, XiaomiMiioBleMeshCloud
from .constants import MeshAuthOpcode, RxferType
from .mesh_config import MeshConfigBuilder
from .registration_state import RegistrationProgress, RegistrationStage
from .rxfer import send_rxfer_data


def _cloud_code(exc: Exception) -> str:
    match = re.search(r"['\"]code['\"]\s*:\s*(-?\d+)", str(exc))
    return match.group(1) if match else "unknown"


async def complete_registration(
    *,
    cloud: XiaomiMiioBleMeshCloud,
    session: LiveRegistrationSession,
    pdid: int,
    did: str,
    controller: MeshControllerInfo,
    models: MeshModelInfo,
) -> tuple[dict[str, Any], bytes]:
    """Advance from fresh DEV_SIGNATURE to cloud commit and GATT_LTMK.

    A returned credential is 32 bytes and must never be printed or persisted.
    Any exception after bind_request_started requires state inspection before
    another registration attempt, even if the request outcome is unknown.
    """
    signature = session.device_signature
    if signature is None or len(signature) != 64 or models.pdid != pdid:
        raise ProbeError("registration prerequisites are incomplete")
    if not session.transport.is_connected:
        raise ProbeError("BLE disconnected before cloud bind")

    record = session.record
    progress = RegistrationProgress().advance(
        RegistrationStage.CLOUD_AUTH_RESPONSE_RECEIVED
    ).advance(RegistrationStage.DEVICE_SIGNATURE_RECEIVED)
    record({
        "event": "bind_request_started",
        "did": did,
        "pdid": pdid,
        "mac": session.address.upper(),
        "token_kind": "constant_empty_string",
        "device_signature_sha256": hashlib.sha256(signature).hexdigest(),
        "registration_stage": progress.stage.name,
        "retry_policy": "manual_state_inspection_required",
    })
    try:
        bound = await cloud.device_bind(
            pdid=pdid,
            mac=session.address,
            did=did,
            device_signature=signature,
        )
    except Exception as exc:
        record({
            "event": "bind_outcome_unknown",
            "did": did,
            "error_type": type(exc).__name__,
            "cloud_code": _cloud_code(exc),
            "retry_policy": "do_not_retry_bind_automatically",
        })
        raise ProbeError("bind request failed or its outcome is unknown; inspect cloud and device state") from None
    finally:
        session.device_signature = None

    progress = progress.advance(RegistrationStage.CLOUD_BOUND)
    record({
        "event": "cloud_bound",
        "did": did,
        "address": bound.address,
        "appkey_id": bound.appkey_id,
        "bind_id": bound.bind_id,
        "static_oob_bytes": len(bound.static_oob),
        "appkey_bytes": len(bound.appkey),
        "registration_stage": progress.stage.name,
    })

    # Build locally before notifying the device. No cloud request occurs here.
    config = MeshConfigBuilder.build(
        random16=secrets.token_bytes(16),
        static_oob=bound.static_oob,
        netkey=controller.primary_netkey,
        netkey_index=0,
        flags=0,
        iv_index=controller.iv_index,
        unicast_address=bound.address,
        appkey=bound.appkey,
        appkey_index=0,
        model_info=models,
    )
    await session.transport.write(
        "0010", int(MeshAuthOpcode.MESH_REG_VERIFY_SUCCESS).to_bytes(4, "little")
    )
    record({"event": "mesh_reg_verify_success_sent", "did": did, "opcode": "0x43"})

    async def write_frame(frame: bytes) -> None:
        await session.transport.write("0016", frame)

    await send_rxfer_data(
        notification_queue=session.notification_queue,
        data_type=RxferType.MESH_CONFIG,
        payload=config.encrypted_payload,
        dmtu=session.dmtu,
        simultaneous_retransmissions=session.retransmit_count,
        write_frame=write_frame,
        max_write_size=session.transport.characteristic("0016").max_write_without_response_size,
        deadline=session.deadline,
    )
    progress = progress.advance(RegistrationStage.CONFIG_SENT)
    record({
        "event": "mesh_config_acknowledged",
        "did": did,
        "payload_length": len(config.encrypted_payload),
        "payload_sha256": hashlib.sha256(config.encrypted_payload).hexdigest(),
        "element_count": len(models.elements),
        "model_bind_count": config.model_bind_count,
        "iv_index": controller.iv_index,
        "registration_stage": progress.stage.name,
    })

    def registration_result(sid: str, raw: bytes) -> bool:
        return sid == "0010" and len(raw) == 4 and raw[0] in (0x41, 0x42) and raw[1:] == b"\0\0\0"

    remaining = session.deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise ProbeError("device result deadline expired after MESH_CONFIG")
    _, status = await wait_for_notification(
        session.notification_queue,
        registration_result,
        timeout=remaining,
        description="MESH_REG_SUCCESS or MESH_REG_FAILED",
    )
    if status[0] != MeshAuthOpcode.MESH_REG_SUCCESS:
        record({"event": "device_registration_failed", "did": did, "opcode": "0x42"})
        raise ProbeError("device returned MESH_REG_FAILED 0x42")
    progress = progress.advance(RegistrationStage.DEVICE_REGISTERED)
    record({"event": "device_registered", "did": did, "opcode": "0x41", "registration_stage": progress.stage.name})

    record({"event": "provision_done_request_started", "did": did, "retry_policy": "manual_state_inspection_required"})
    try:
        await cloud.provision_done(
            did=did, device_key=config.device_key, static_oob=bound.static_oob
        )
    except Exception as exc:
        record({"event": "provision_done_outcome_unknown", "did": did, "error_type": type(exc).__name__, "cloud_code": _cloud_code(exc)})
        raise ProbeError("device registered but cloud provision_done is unconfirmed") from None
    progress = progress.advance(RegistrationStage.CLOUD_COMMITTED)
    record({"event": "cloud_committed", "did": did, "registration_stage": progress.stage.name})

    try:
        gatt_ltmk = await cloud.get_gatt_ltmk(did)
    except Exception as exc:
        record({"event": "gatt_ltmk_query_failed", "did": did, "error_type": type(exc).__name__, "cloud_code": _cloud_code(exc)})
        raise ProbeError("cloud committed, but 32-byte GATT_LTMK was not retrieved") from None
    record({"event": "gatt_ltmk_retrieved", "did": did, "credential_length": len(gatt_ltmk)})
    return ({
        "did": did,
        "device_opcode": "0x41",
        "provision_done_success": True,
        "gatt_ltmk_length": len(gatt_ltmk),
        "registration_stage": progress.stage.name,
        "registered": True,
    }, gatt_ltmk)
