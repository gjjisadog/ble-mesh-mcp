"""Scan nearby BLE advertisements and save changed observations as JSONL."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bleak import BleakScanner


HERE = Path(__file__).resolve().parent
LOG_DIR = HERE / "logs"

XIAOMI_COMPANY_ID = 0x038F
XIAOMI_SERVICE_UUIDS = {
    "FCC0": "Xiaomi Inc.",
    "FDAA": "Xiaomi Inc.",
    "FE95": "Xiaomi Inc. (MiBeacon-associated)",
}
MESH_SERVICE_UUIDS = {
    "1827": "Mesh Provisioning Service",
    "1828": "Mesh Proxy Service",
    "1859": "Mesh Proxy Solicitation Service",
}
XIAOMI_NAME_HINTS = ("xiaomi", "mijia", "mibeacon", "yeelight", "aqara", "lumi")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def short_uuid(uuid: str) -> str | None:
    """Return the 16-bit part of a Bluetooth base UUID, if applicable."""
    value = str(uuid).lower()
    if re.fullmatch(r"[0-9a-f]{4}", value):
        return value.upper()
    match = re.fullmatch(
        r"0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb", value
    )
    return match.group(1).upper() if match else None


def byte_fields(value: bytes) -> dict[str, Any]:
    data = bytes(value)
    return {
        "raw_bytes": list(data),
        "raw_bytes_repr": repr(data),
        "hex": data.hex(" ").upper(),
    }


def windows_ad_sections(advertisement_data: Any) -> dict[str, Any] | None:
    """Read WinRT AD sections exposed through Bleak's platform-specific data."""
    platform_data = getattr(advertisement_data, "platform_data", ())
    if not isinstance(platform_data, (tuple, list)) or len(platform_data) < 2:
        return None

    raw_pair = platform_data[1]
    result: dict[str, Any] = {}
    found_winrt_data = False

    for packet_name, packet_attr in (
        ("advertisement", "adv"),
        ("scan_response", "scan"),
    ):
        event = getattr(raw_pair, packet_attr, None)
        advertisement = getattr(event, "advertisement", None)
        sections = getattr(advertisement, "data_sections", None)
        if sections is None:
            result[packet_name] = None
            continue

        found_winrt_data = True
        packet_sections = []
        for section in sections:
            data = bytes(section.data)
            data_type = int(section.data_type)
            packet_sections.append(
                {
                    "ad_type": f"0x{data_type:02X}",
                    **byte_fields(data),
                }
            )
        result[packet_name] = packet_sections

    return result if found_winrt_data else None


def make_record(device: Any, advertisement_data: Any, scan_mode: str) -> dict[str, Any]:
    name = advertisement_data.local_name or device.name
    service_uuids = sorted(str(uuid).lower() for uuid in advertisement_data.service_uuids)

    manufacturer_data = []
    for company_id, payload in sorted(advertisement_data.manufacturer_data.items()):
        manufacturer_data.append(
            {
                "company_id": int(company_id),
                "company_id_hex": f"0x{int(company_id):04X}",
                "company_name": "Xiaomi Inc." if int(company_id) == XIAOMI_COMPANY_ID else None,
                **byte_fields(payload),
            }
        )

    service_data = []
    for uuid, payload in sorted(advertisement_data.service_data.items()):
        service_data.append({"uuid": str(uuid).lower(), **byte_fields(payload)})

    xiaomi_indicators: list[str] = []
    if any(item["company_id"] == XIAOMI_COMPANY_ID for item in manufacturer_data):
        xiaomi_indicators.append("Manufacturer company ID 0x038F (Xiaomi Inc.)")

    seen_uuid_values = service_uuids + [item["uuid"] for item in service_data]
    short_uuids = {short_uuid(uuid) for uuid in seen_uuid_values}
    for uuid in sorted(short_uuids & XIAOMI_SERVICE_UUIDS.keys()):
        xiaomi_indicators.append(
            f"Service UUID 0x{uuid} ({XIAOMI_SERVICE_UUIDS[uuid]})"
        )

    folded_name = (name or "").casefold()
    matching_names = [hint for hint in XIAOMI_NAME_HINTS if hint in folded_name]
    if matching_names:
        xiaomi_indicators.append("Name contains: " + ", ".join(matching_names))

    mesh_indicators = []
    for uuid in sorted(short_uuids & MESH_SERVICE_UUIDS.keys()):
        mesh_indicators.append(f"0x{uuid}: {MESH_SERVICE_UUIDS[uuid]}")

    labels = []
    if xiaomi_indicators:
        labels.append("疑似小米/米家生态")
    if mesh_indicators:
        labels.append("Bluetooth Mesh UUID")

    windows_sections = windows_ad_sections(advertisement_data)

    return {
        "timestamp_utc": utc_now(),
        "scan_mode": scan_mode,
        "name": name,
        "address": str(device.address),
        "rssi_dbm": advertisement_data.rssi,
        "service_uuids": service_uuids,
        "manufacturer_data": manufacturer_data,
        "service_data": service_data,
        "windows_ad_sections": windows_sections,
        "classification": {
            "labels": labels,
            "suspected_xiaomi": bool(xiaomi_indicators),
            "xiaomi_indicators": xiaomi_indicators,
            "bluetooth_mesh_related": bool(mesh_indicators),
            "mesh_indicators": mesh_indicators,
        },
    }


def content_signature(record: dict[str, Any]) -> str:
    """Ignore RSSI and timestamps so unchanged advertisements are not repeated."""
    content = {
        key: record[key]
        for key in (
            "name",
            "service_uuids",
            "manufacturer_data",
            "service_data",
            "windows_ad_sections",
            "classification",
        )
    }
    return json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def write_presence_snapshot(path: Path, latest_records: dict[str, dict[str, Any]]) -> None:
    """Atomically save the latest observation for each address."""
    snapshot = {
        "updated_at_utc": utc_now(),
        "devices": sorted(latest_records.values(), key=lambda item: item["address"]),
    }
    temporary_path = path.with_suffix(".tmp")
    temporary_path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary_path.replace(path)


async def refresh_presence_snapshot(
    path: Path, latest_records: dict[str, dict[str, Any]]
) -> None:
    while True:
        await asyncio.sleep(1)
        write_presence_snapshot(path, latest_records)


def format_tags(record: dict[str, Any]) -> str:
    labels = record["classification"]["labels"]
    return " ".join(f"[{label}]" for label in labels) if labels else ""


async def scan(duration: float, continuous: bool) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / f"ble_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    scan_mode = "continuous" if continuous else "timed"
    last_signatures: dict[str, str] = {}
    latest_records: dict[str, dict[str, Any]] = {}
    presence_path = LOG_DIR / "presence_snapshot.json"
    counts = {"devices": set(), "events": 0}

    with log_path.open("a", encoding="utf-8", newline="\n") as log_file:

        def on_advertisement(device: Any, advertisement_data: Any) -> None:
            record = make_record(device, advertisement_data, scan_mode)
            address = record["address"]
            record["last_seen_utc"] = record["timestamp_utc"]
            latest_records[address] = record
            signature = content_signature(record)
            if last_signatures.get(address) == signature:
                return

            is_new = address not in last_signatures
            last_signatures[address] = signature
            counts["devices"].add(address)
            counts["events"] += 1

            heading = "NEW" if is_new else "CHANGED"
            tags = format_tags(record)
            tag_text = f" {tags}" if tags else ""
            print(f"\n[{heading}]{tag_text} {record['timestamp_utc']}", flush=True)
            print(json.dumps(record, ensure_ascii=False, indent=2), flush=True)

            log_file.write(
                json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
            )
            log_file.flush()

        # Active scanning also requests scan responses where devices provide them.
        scanner = BleakScanner(
            detection_callback=on_advertisement,
            scanning_mode="active",
        )
        print(f"开始 BLE 扫描；日志：{log_path}", flush=True)
        print("按 Ctrl+C 停止。" if continuous else f"扫描时长：{duration:g} 秒。", flush=True)

        await scanner.start()
        presence_task = (
            asyncio.create_task(refresh_presence_snapshot(presence_path, latest_records))
            if continuous
            else None
        )
        try:
            if continuous:
                while True:
                    await asyncio.sleep(3600)
            else:
                await asyncio.sleep(duration)
        finally:
            await scanner.stop()
            if presence_task is not None:
                presence_task.cancel()
                try:
                    await presence_task
                except asyncio.CancelledError:
                    pass
                write_presence_snapshot(presence_path, latest_records)

    print(
        f"扫描结束：发现 {len(counts['devices'])} 个设备，记录 {counts['events']} 条变化；"
        f"日志文件：{log_path}",
        flush=True,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="扫描附近 BLE 广播，保存原始广播字段用于后续协议分析。"
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=15.0,
        help="单次扫描时长（秒），默认 15；持续扫描时忽略。",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="持续扫描，按 Ctrl+C 停止。",
    )
    args = parser.parse_args()
    if not args.continuous and args.duration <= 0:
        parser.error("--duration 必须大于 0")
    return args


def main() -> int:
    args = parse_args()
    try:
        asyncio.run(scan(args.duration, args.continuous))
    except KeyboardInterrupt:
        print("\n已停止扫描。", flush=True)
    except Exception as exc:
        print(f"扫描失败：{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
