"""Local stdio MCP server for the registered lab plug."""

from __future__ import annotations

import asyncio
from typing import Literal

from mcp.server import MCPServer

from ble_mesh_mcp.xiaomi.credentials import load_gatt_ltmk
from ble_mesh_mcp.xiaomi.local_control import power_cycle, power_off, power_on


mcp = MCPServer("ble-lab-power")
_control_lock = asyncio.Lock()


async def _operate(turn_on: bool) -> dict[str, str | int | bool | None]:
    async with _control_lock:
        key = load_gatt_ltmk()
        result = await (power_on(key) if turn_on else power_off(key))
    return {
        "device": "lab_power",
        "requested_state": "on" if turn_on else "off",
        "transport_acked": result.transport_acked,
        "property_status": result.property_status,
        "protocol_verified": result.protocol_verified,
        "physical_state": None,  # No separate power sensor is attached to the PC.
    }


@mcp.tool()
async def poweron(device: Literal["lab_power"]) -> dict[str, str | int | bool | None]:
    """Turn on the registered lab USB plug and verify its MIoT response."""
    return await _operate(True)


@mcp.tool()
async def poweroff(device: Literal["lab_power"]) -> dict[str, str | int | bool | None]:
    """Turn off the registered lab USB plug and verify its MIoT response."""
    return await _operate(False)


@mcp.tool()
async def powercycle(
    device: Literal["lab_power"],
    off_seconds: float = 5.0,
    mode: Literal["auto", "manual", "auto_or_manual"] = "auto_or_manual",
    reason: Literal["after_flash", "connection_recovery"] = "after_flash",
) -> dict[str, object]:
    """Cycle board power after Flash or for a controlled connection recovery.

    The caller must confirm no Flash operation is active, preserve failure
    evidence, and release the old C2000 debug session first. This tool does
    not inspect Flash results or debugger state.
    """
    if not 1.0 <= off_seconds <= 60.0:
        raise ValueError("off_seconds must be between 1 and 60")

    def manual(manual_reason: str) -> dict[str, object]:
        return {
            "device": device,
            "status": "manual_required",
            "reason": manual_reason,
            "trigger": reason,
            "requested_off_seconds": off_seconds,
            "instruction": (
                f"Manually disconnect board power for at least {off_seconds:g} seconds, "
                "restore power, then confirm completion before reconnecting the C2000 debugger."
            ),
            "protocol_verified": False,
            "physical_state": None,
            "may_remain_off": manual_reason.startswith("automatic_cycle_failed"),
        }

    if mode == "manual":
        return manual("manual_mode_selected")

    async with _control_lock:
        try:
            key = load_gatt_ltmk()
            result = await power_cycle(key, off_seconds=off_seconds)
        except Exception as exc:
            if mode == "auto":
                raise
            return manual(f"automatic_cycle_failed:{type(exc).__name__}")

    return {
        "device": device,
        "status": "completed",
        "trigger": reason,
        "mode_used": "auto",
        "requested_off_seconds": off_seconds,
        "off_hold_seconds": round(result.off_hold_seconds, 3),
        "off_transport_acked": result.off.transport_acked,
        "off_property_status": result.off.property_status,
        "on_transport_acked": result.on.transport_acked,
        "on_property_status": result.on.property_status,
        "protocol_verified": result.protocol_verified,
        "physical_state": None,
    }


if __name__ == "__main__":
    mcp.run()
