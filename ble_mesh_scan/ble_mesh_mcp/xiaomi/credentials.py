"""Current-Windows-user storage for the lab plug's 32-byte GATT_LTMK.

The key is protected with DPAPI and never written to the project directory.
This module does not authenticate with Xiaomi Cloud or print key material.
"""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _crypt(data: bytes, *, protect: bool) -> bytes:
    if os.name != "nt":
        raise OSError("Windows DPAPI is required")
    input_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source = _DataBlob(len(data), input_buffer)
    destination = _DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    operation = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    operation.restype = wintypes.BOOL
    operation.argtypes = [
        ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    if not operation(ctypes.byref(source), None, None, None, None, 1,
                     ctypes.byref(destination)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.LocalFree(ctypes.cast(destination.pbData, ctypes.c_void_p))


def credential_path() -> Path:
    # Packaged desktop apps can redirect LOCALAPPDATA to their private cache.
    # The user-profile root is stable across ordinary and packaged MCP hosts.
    return Path.home() / ".ble-mesh-mcp" / "lab_power.dpapi"


def save_gatt_ltmk(key: bytes) -> Path:
    if len(key) != 32:
        raise ValueError("GATT_LTMK must be exactly 32 bytes")
    encrypted = _crypt(bytes(key), protect=True)
    path = credential_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(encrypted)
    temporary.replace(path)
    return path


def load_gatt_ltmk() -> bytes:
    path = credential_path()
    if not path.is_file():
        raise FileNotFoundError(
            "lab_power credential is missing; run bootstrap_credential.py first"
        )
    key = _crypt(path.read_bytes(), protect=False)
    if len(key) != 32:
        raise ValueError("stored GATT_LTMK has an invalid length")
    return key
