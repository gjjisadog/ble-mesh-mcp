"""Local identity of the registered lab plug (no account secrets here)."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DeviceConfig:
    address: str
    did: str


def device_config_path() -> Path:
    return Path.home() / ".ble-mesh-mcp" / "lab_power.json"


def load_device_config() -> DeviceConfig:
    """Read identifiers from environment or the current user's local file."""
    path = device_config_path()
    saved = json.loads(path.read_text(encoding="utf-8-sig")) if path.is_file() else {}
    address = os.environ.get("BLE_LAB_POWER_ADDRESS") or saved.get("address")
    did = os.environ.get("BLE_LAB_POWER_DID") or saved.get("did")
    if not isinstance(address, str) or not re.fullmatch(
        r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", address
    ):
        raise ValueError(f"set a BLE address in {path} or BLE_LAB_POWER_ADDRESS")
    if not isinstance(did, str) or not re.fullmatch(r"[0-9]+", did):
        raise ValueError(f"set a decimal DID in {path} or BLE_LAB_POWER_DID")
    return DeviceConfig(address=address.upper(), did=did)
