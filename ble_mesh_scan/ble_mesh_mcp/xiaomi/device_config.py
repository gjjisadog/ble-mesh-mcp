"""Per-user registry for registered plugs of the supported Xiaomi model."""

from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path


MODEL_NAME = "de1.plug.wjzncz"
PRODUCT_ID = 0x90C0
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_ADDRESS = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z")


@dataclass(frozen=True)
class DeviceConfig:
    name: str
    address: str
    did: str
    model: str = MODEL_NAME


def config_dir() -> Path:
    return Path.home() / ".ble-mesh-mcp"


def device_config_path() -> Path:
    """Path of the original single-device file, kept for migration."""
    return config_dir() / "lab_power.json"


def registry_path() -> Path:
    return config_dir() / "devices.json"


def validate_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ValueError("device name must start with a lowercase letter and contain only a-z, 0-9, _ or - (max 64)")
    return name


def normalize_address(address: str) -> str:
    if not isinstance(address, str):
        raise ValueError("BLE address must be a string")
    value = address.strip().replace("-", ":")
    if re.fullmatch(r"[0-9A-Fa-f]{12}", value):
        value = ":".join(value[index:index + 2] for index in range(0, 12, 2))
    if not _ADDRESS.fullmatch(value):
        raise ValueError("BLE address must contain six hexadecimal octets")
    return value.upper()


def _device(name: str, address: object, did: object, model: object = MODEL_NAME) -> DeviceConfig:
    validate_name(name)
    if not isinstance(did, str) or not re.fullmatch(r"[0-9]+", did):
        raise ValueError(f"device {name}: DID must be a decimal string")
    if model != MODEL_NAME:
        raise ValueError(f"device {name}: only model {MODEL_NAME} is supported")
    return DeviceConfig(name=name, address=normalize_address(address), did=did)


def list_device_configs() -> dict[str, DeviceConfig]:
    """Load the registry and include an unmodified legacy lab_power entry."""
    path = registry_path()
    devices: dict[str, DeviceConfig] = {}
    if path.is_file():
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("devices"), dict):
            raise ValueError(f"invalid device registry: {path}")
        for name, item in data["devices"].items():
            if not isinstance(item, dict):
                raise ValueError(f"invalid registry entry: {name}")
            devices[name] = _device(name, item.get("address"), item.get("did"), item.get("model", MODEL_NAME))

    if "lab_power" not in devices:
        old = device_config_path()
        data = json.loads(old.read_text(encoding="utf-8-sig")) if old.is_file() else {}
        address = os.environ.get("BLE_LAB_POWER_ADDRESS") or data.get("address")
        did = os.environ.get("BLE_LAB_POWER_DID") or data.get("did")
        if address is not None or did is not None:
            devices["lab_power"] = _device(
                "lab_power", address, did
            )
    return devices


def load_device_config(name: str = "lab_power") -> DeviceConfig:
    validate_name(name)
    device = list_device_configs().get(name)
    if device is None:
        raise KeyError(f"device {name!r} is not registered locally; run onboard_device.py")
    return device


def save_device_config(device: DeviceConfig, *, replace: bool = False) -> Path:
    """Atomically add one named device without saving any key material."""
    item = _device(device.name, device.address, device.did, device.model)
    devices = list_device_configs()
    previous = devices.get(item.name)
    if previous is not None and previous != item and not replace:
        raise ValueError(f"device name {item.name!r} already belongs to another address or DID")
    for other in devices.values():
        if other.name != item.name and (other.address == item.address or other.did == item.did):
            raise ValueError(f"device already registered locally as {other.name!r}")
    devices[item.name] = item
    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "devices": {
            name: {"address": value.address, "did": value.did, "model": value.model}
            for name, value in sorted(devices.items())
        },
    }
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return path
