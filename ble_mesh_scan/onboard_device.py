"""Add an already-bound Xiaomi plug of the supported model by local name.

The Xiaomi account and Mesh key stay out of the project directory. Onboarding
checks BLE Admin Login but never sends a power command.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import tempfile
from pathlib import Path

import aiohttp

from ble_mesh_mcp.xiaomi.cloud.miio_blemesh import XiaomiMiioBleMeshCloud
from ble_mesh_mcp.xiaomi.cloud.qr_login import login_via_qr
from ble_mesh_mcp.xiaomi.credentials import credential_path, save_gatt_ltmk
from ble_mesh_mcp.xiaomi.device_config import (
    MODEL_NAME, PRODUCT_ID, DeviceConfig, list_device_configs,
    normalize_address, save_device_config, validate_name,
)
from ble_mesh_mcp.xiaomi.live_admin_login import verify_admin_login


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="show locally configured devices")
    add = commands.add_parser("add", help="add one already-bound plug")
    add.add_argument("name", help="local name, e.g. board_2")
    add.add_argument("--did", help="select a Xiaomi DID when the account has multiple plugs")
    add.add_argument("--address", help="BLE address if the account does not return a MAC")
    return parser.parse_args()


def _print_local_devices() -> None:
    devices = list_device_configs()
    print(json.dumps({"devices": [
        {"name": name, "model": device.model,
         "credential_ready": credential_path(name).is_file()}
        for name, device in sorted(devices.items())
    ]}, ensure_ascii=False, indent=2))


def _select_device(items: object, did: str | None, registered_dids: set[str]) -> dict:
    if not isinstance(items, list):
        raise ValueError("Xiaomi device list is not an array")
    candidates = [item for item in items if isinstance(item, dict)
                  and item.get("model") == MODEL_NAME
                  and str(item.get("did", "")).isdigit()]
    if did is not None:
        candidates = [item for item in candidates if str(item["did"]) == did]
    else:
        candidates = [item for item in candidates if str(item["did"]) not in registered_dids]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise ValueError(f"no new bound {MODEL_NAME} plug matched this account and DID")
    summary = [{"name": item.get("name"), "did": str(item["did"])}
               for item in candidates]
    raise ValueError("multiple matching plugs; rerun with --did from "
                     + json.dumps(summary, ensure_ascii=False))


def _key_from_query(result: dict) -> bytes:
    value = result.get("gatt_ltmk")
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("query_dev did not return a 32-byte GATT_LTMK")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("query_dev returned a non-hex GATT_LTMK") from exc


def _check_product_id(result: dict) -> None:
    value = result.get("pdid")
    if value is None:
        return
    try:
        if isinstance(value, str):
            product_id = int(value, 10) if value.isdigit() else int(value, 16)
        else:
            product_id = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("query_dev returned an invalid product ID") from exc
    if product_id != PRODUCT_ID:
        raise ValueError(f"query_dev product ID {product_id} is not the supported model")


async def _login(session: aiohttp.ClientSession):
    qr_path = Path(tempfile.gettempdir()) / f"ble_mesh_onboard_{secrets.token_hex(8)}.png"
    ready = asyncio.Event()
    task = asyncio.create_task(login_via_qr(session, qr_path, ready=ready))
    ready_task = asyncio.create_task(ready.wait())
    try:
        done, _ = await asyncio.wait((task, ready_task), return_when=asyncio.FIRST_COMPLETED)
        if task not in done:
            print(f"QR_READY {qr_path.resolve()}", flush=True)
            if os.name == "nt":
                os.startfile(qr_path)
        return await task
    finally:
        ready_task.cancel()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        qr_path.unlink(missing_ok=True)


async def _add(name: str, did: str | None, address: str | None) -> None:
    validate_name(name)
    if did is not None and not did.isdigit():
        raise ValueError("--did must be a decimal Xiaomi DID")
    configured = list_device_configs()
    if name in configured:
        raise ValueError(f"device name {name!r} already exists locally")
    if did is not None and did in {device.did for device in configured.values()}:
        raise ValueError("this DID is already registered locally")
    if credential_path(name).exists():
        raise ValueError(f"credential path for {name!r} already exists")
    if address is not None:
        address = normalize_address(address)

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=75)) as session:
        service = await _login(session)
        selected = _select_device(
            await service.device_list(name="full"), did,
            {device.did for device in configured.values()},
        )
        selected_did = str(selected["did"])
        result = await XiaomiMiioBleMeshCloud(service).query_device(selected_did)
        _check_product_id(result)
        key = _key_from_query(result)
        cloud_mac = result.get("mac") or selected.get("mac")
        if address is None:
            if not cloud_mac:
                raise ValueError("account did not return a BLE MAC; specify --address")
            address = normalize_address(cloud_mac)
        device = DeviceConfig(name=name, address=address, did=selected_did)

        # Prove the address and key belong together without changing power.
        if not await verify_admin_login(address, key):
            raise RuntimeError("BLE Admin Login was not confirmed")

    path = save_gatt_ltmk(key, name)
    try:
        save_device_config(device)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    print(json.dumps({"status": "onboarded", "name": name, "model": MODEL_NAME,
                      "credential_ready": True, "admin_login_verified": True},
                     ensure_ascii=False))


if __name__ == "__main__":
    args = _parse_args()
    try:
        if args.command == "list":
            _print_local_devices()
        else:
            asyncio.run(_add(args.name, args.did, args.address))
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except Exception as exc:
        print(f"ONBOARD_FAILED {type(exc).__name__}: {exc}", flush=True)
        raise SystemExit(1) from None
