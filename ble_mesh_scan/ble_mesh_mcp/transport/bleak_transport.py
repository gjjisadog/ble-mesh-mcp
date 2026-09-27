"""Thin Bleak adapter for the observed Windows FE95 GATT connection."""

from __future__ import annotations

from typing import Any, Callable

from bleak import BleakClient, BleakScanner

from ..xiaomi.constants import UUID_FE95


class BleakTransport:
    """Own one Bleak connection and expose FE95 characteristic I/O."""

    def __init__(self, address: str, timeout: float = 20.0) -> None:
        self.address = address
        self.timeout = timeout
        self.client: BleakClient | None = None
        self.characteristics: dict[str, Any] = {}
        self.negotiated_dmtu: int | None = None

    async def __aenter__(self) -> "BleakTransport":
        device = await BleakScanner.find_device_by_address(
            self.address,
            timeout=self.timeout,
        )
        if device is None:
            raise RuntimeError(f"BLE device {self.address} was not found during discovery")

        client = BleakClient(
            device,
            timeout=self.timeout,
            winrt={"use_cached_services": False},
        )
        try:
            await client.connect()
            for service in client.services:
                if service.uuid.lower() != UUID_FE95:
                    continue
                for characteristic in service.characteristics:
                    self.characteristics[short_uuid(characteristic.uuid)] = characteristic
            self.client = client
            return self
        except Exception:
            if client.is_connected:
                await client.disconnect()
            raise

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.client is not None and self.client.is_connected:
            await self.client.disconnect()
        self.client = None

    @property
    def services(self) -> Any:
        return self._require_client().services

    @property
    def is_connected(self) -> bool:
        return bool(self.client and self.client.is_connected)

    @property
    def mtu_size(self) -> int | None:
        return getattr(self._require_client(), "mtu_size", None)

    def characteristic(self, short_id: str) -> Any:
        try:
            return self.characteristics[short_id.upper()]
        except KeyError as exc:
            raise RuntimeError(f"FE95 characteristic {short_id} was not found") from exc

    async def start_notify(
        self,
        short_id: str,
        callback: Callable[[Any, bytearray], None],
    ) -> None:
        await self._require_client().start_notify(self.characteristic(short_id), callback)

    async def write(self, short_id: str, value: bytes, response: bool = False) -> None:
        await self._require_client().write_gatt_char(
            self.characteristic(short_id),
            bytes(value),
            response=response,
        )

    def _require_client(self) -> BleakClient:
        if self.client is None:
            raise RuntimeError("BLE transport is not connected")
        return self.client


def short_uuid(uuid: str) -> str:
    return uuid.split("-", 1)[0][-4:].upper()
