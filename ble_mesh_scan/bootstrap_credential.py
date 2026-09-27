"""One-time QR login and Windows DPAPI storage for the lab plug credential."""

from __future__ import annotations

import asyncio
import os
import secrets
import tempfile
from pathlib import Path

import aiohttp

from ble_mesh_mcp.xiaomi.cloud.miio_blemesh import XiaomiMiioBleMeshCloud
from ble_mesh_mcp.xiaomi.cloud.qr_login import login_via_qr
from ble_mesh_mcp.xiaomi.credentials import save_gatt_ltmk
from ble_mesh_mcp.xiaomi.device_config import load_device_config


async def main() -> None:
    qr_path = Path(tempfile.gettempdir()) / f"ble_mesh_credential_{secrets.token_hex(8)}.png"
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=75)) as session:
        ready = asyncio.Event()
        task = asyncio.create_task(login_via_qr(session, qr_path, ready=ready))
        ready_task = asyncio.create_task(ready.wait())
        done, _ = await asyncio.wait((task, ready_task), return_when=asyncio.FIRST_COMPLETED)
        if task not in done:
            print(f"QR_READY {qr_path.resolve()}", flush=True)
            if os.name == "nt":
                os.startfile(qr_path)
        ready_task.cancel()
        service = await task
        key = await XiaomiMiioBleMeshCloud(service).get_gatt_ltmk(load_device_config().did)
        path = save_gatt_ltmk(key)
    print(f"CREDENTIAL_SAVED_DPAPI {path.resolve()}", flush=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except Exception as exc:
        print(f"CREDENTIAL_BOOTSTRAP_FAILED {type(exc).__name__}: {exc}", flush=True)
        raise SystemExit(1) from None
