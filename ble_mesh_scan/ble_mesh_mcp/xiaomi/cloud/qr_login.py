"""One-shot Xiaomi account QR login for a MiIOService session.

The QR image is temporary. Account tokens remain in memory and are never
written to the project's logs. The caller owns the aiohttp session.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse

import aiohttp
from miservice import MiAccount, MiIOService


_ACCOUNT = "https://account.xiaomi.com"
_SID = "xiaomiio"
_USER_AGENT = "APP/com.xiaomi.mihome APPV/6.0.103 iosPassportSDK/3.9.0 iOS/14.4 miHSTS"


def _parse_json(raw: str) -> dict:
    if raw.startswith("&&&START&&&"):
        raw = raw[len("&&&START&&&"):]
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("Xiaomi account returned a non-object response")
    return result


def _require_https(url: str, allowed_host: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.scheme != "https" or not (
        host == allowed_host or host.endswith("." + allowed_host)
    ):
        raise ValueError(f"unexpected Xiaomi login host: {parsed.hostname}")
    return url


async def login_via_qr(
    session: aiohttp.ClientSession,
    qr_path: Path,
    *,
    ready: asyncio.Event | None = None,
    start_poll: asyncio.Event | None = None,
    progress: Callable[[str], None] | None = None,
) -> MiIOService:
    """Save a temporary QR image and wait for account confirmation.

    The caller can wait for `ready` to display `qr_path`. The image is removed
    as soon as login completes or fails.
    """
    device_id = secrets.token_hex(8).upper()
    query = urlencode({
        "_qrsize": "480",
        "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
        "callback": "https://sts.api.io.mi.com/sts",
        "_hasLogo": "false",
        "sid": _SID,
        "serviceParam": "",
        "_locale": "zh_CN",
        "_dc": str(int(time.time() * 1000)),
    }, quote_via=quote)
    headers = {"User-Agent": _USER_AGENT}
    async with session.get(
        f"{_ACCOUNT}/longPolling/loginUrl?{query}",
        headers=headers,
        cookies={"sdkVersion": "accountsdk-18.8.15", "deviceId": device_id},
    ) as response:
        response.raise_for_status()
        info = _parse_json(await response.text())
    qr_url = _require_https(info["qr"], "account.xiaomi.com")
    polling_url = _require_https(info["lp"], "account.xiaomi.com")
    expires = min(max(int(info.get("timeout", 300)), 1), 600)
    async with session.get(qr_url) as response:
        response.raise_for_status()
        image = await response.read()
    if not image.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Xiaomi account did not return a PNG QR image")
    qr_path.parent.mkdir(parents=True, exist_ok=True)
    qr_path.write_bytes(image)
    if ready is not None:
        ready.set()
    try:
        deadline = time.monotonic() + expires
        if start_poll is not None:
            await asyncio.wait_for(start_poll.wait(), timeout=expires)
        login = None
        last_status = None
        while time.monotonic() < deadline:
            try:
                async with session.get(polling_url, headers=headers) as response:
                    if response.status != 200:
                        status = f"http={response.status}"
                        if progress is not None and status != last_status:
                            progress(status)
                        last_status = status
                        await asyncio.sleep(1)
                        continue
                    candidate = _parse_json(await response.text())
                status = (
                    f"code={candidate.get('code')} status={candidate.get('status')} "
                    f"fields={','.join(sorted(candidate))}"
                )
                if progress is not None and status != last_status:
                    progress(status)
                last_status = status
                if candidate.get("passToken"):
                    login = candidate
                    break
                polling_url = _require_https(candidate.get("lp") or polling_url, "account.xiaomi.com")
            except (asyncio.TimeoutError, aiohttp.ClientError, json.JSONDecodeError):
                await asyncio.sleep(1)
        if login is None:
            raise TimeoutError("Xiaomi QR login expired")
        sign = base64.b64encode(
            hashlib.sha1(f"nonce={login['nonce']}&{login['ssecurity']}".encode()).digest()
        ).decode()
        location = _require_https(login["location"], "sts.api.io.mi.com")
        separator = "&" if "?" in location else "?"
        async with session.get(
            f"{location}{separator}clientSign={quote(sign)}",
            headers={"User-Agent": "APP/com.xiaomi.mihome"},
        ) as response:
            response.raise_for_status()
            cookie = response.cookies.get("serviceToken")
            if cookie is None:
                raise RuntimeError("Xiaomi account did not issue a serviceToken")
        account = MiAccount(session, "", "", token_store=None)
        account.token = {
            "deviceId": device_id,
            "userId": str(login["userId"]),
            "passToken": login["passToken"],
            _SID: (login["ssecurity"], cookie.value),
        }
        return MiIOService(account=account, region="cn")
    finally:
        qr_path.unlink(missing_ok=True)
