"""Analyze a saved DEV_CERT and ECC_PUBKEY capture without using Bluetooth."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ..xiaomi.certificate import analyze_device_certificate
from ..xiaomi.mesh_auth import parse_mesh_ecc_frame


def analyze_capture(capture_log: Path, certificate_path: Path) -> dict[str, Any]:
    records = [
        json.loads(line)
        for line in capture_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ecc_record = next(
        (
            record
            for record in records
            if record.get("event") == "notification"
            and record.get("characteristic") == "0016"
            and record.get("raw_bytes", [])[:4] == [0, 0, 2, 3]
        ),
        None,
    )
    if ecc_record is None:
        raise ValueError("Capture log contains no 88-byte ECC_PUBKEY SGL_CMD notification")

    ecc_frame = bytes(ecc_record["raw_bytes"])
    ecc_parsed = parse_mesh_ecc_frame("0016", ecc_frame)
    if ecc_parsed is None:
        raise ValueError("Captured ECC_PUBKEY frame did not match the known layout")

    certificate_der = certificate_path.read_bytes()
    certificate = analyze_device_certificate(
        certificate_der,
        bytes.fromhex(ecc_parsed["public_key_sec1_hex"]),
    )
    return {
        "address": ecc_record.get("address"),
        "capture_timestamp_utc": ecc_record.get("timestamp_utc"),
        "source_log": str(capture_log.resolve()),
        "raw_ecc_pubkey_frame_hex": ecc_frame.hex(" ").upper(),
        "ecc_pubkey_frame": ecc_parsed,
        "device_certificate_file": str(certificate_path.resolve()),
        "device_certificate": certificate,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline analysis of a captured Xiaomi Mesh device certificate and ECC frame."
    )
    parser.add_argument("capture_log", type=Path, help="mesh_reg_probe JSONL capture")
    parser.add_argument("device_certificate", type=Path, help="reassembled DEV_CERT DER file")
    parser.add_argument("--output", type=Path, help="optional JSON report path")
    args = parser.parse_args()

    try:
        report = analyze_capture(args.capture_log, args.device_certificate)
        encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded, encoding="utf-8")
            print(f"Analysis report: {args.output.resolve()}")
        else:
            print(encoded, end="")
    except Exception as exc:
        print(f"Offline analysis failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
