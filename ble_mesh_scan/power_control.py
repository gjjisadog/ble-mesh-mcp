"""Manual power commands using the stored lab-plug credential."""

from __future__ import annotations

import argparse
import asyncio
import json

from ble_mesh_mcp.xiaomi.credentials import load_gatt_ltmk
from ble_mesh_mcp.xiaomi.local_control import power_cycle, power_off, power_on


async def main(command: str, off_seconds: float, mode: str) -> int:
    if command == "powercycle":
        if not 1.0 <= off_seconds <= 60.0:
            raise ValueError("off_seconds must be between 1 and 60")

        def manual(reason: str) -> int:
            print(json.dumps({
                "device": "lab_power",
                "status": "manual_required",
                "reason": reason,
                "requested_off_seconds": off_seconds,
                "instruction": (
                    f"Manually disconnect board power for at least {off_seconds:g} seconds, "
                    "restore power, then confirm completion before reconnecting C2000."
                ),
                "protocol_verified": False,
                "physical_state": None,
            }, separators=(",", ":")))
            return 3

        if mode == "manual":
            return manual("manual_mode_selected")
        try:
            key = load_gatt_ltmk()
            result = await power_cycle(key, off_seconds=off_seconds)
        except Exception as exc:
            if mode == "auto":
                raise
            return manual(f"automatic_cycle_failed:{type(exc).__name__}")
        print(json.dumps({
            "device": "lab_power",
            "status": "completed",
            "off_hold_seconds": round(result.off_hold_seconds, 3),
            "off_transport_acked": result.off.transport_acked,
            "off_property_status": result.off.property_status,
            "on_transport_acked": result.on.transport_acked,
            "on_property_status": result.on.property_status,
            "protocol_verified": result.protocol_verified,
            "physical_state": None,
        }, separators=(",", ":")))
        return 0 if result.protocol_verified else 2
    key = load_gatt_ltmk()
    result = await (power_on(key) if command == "poweron" else power_off(key))
    print(json.dumps({
        "device": "lab_power",
        "requested_state": "on" if result.requested_on else "off",
        "transport_acked": result.transport_acked,
        "property_status": result.property_status,
        "protocol_verified": result.protocol_verified,
        "physical_state": None,
    }, separators=(",", ":")))
    return 0 if result.protocol_verified else 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("poweron", "poweroff", "powercycle"))
    parser.add_argument("--off-seconds", type=float, default=5.0)
    parser.add_argument("--mode", choices=("auto", "manual", "auto_or_manual"),
                        default="auto_or_manual")
    args = parser.parse_args()
    try:
        raise SystemExit(asyncio.run(main(args.command, args.off_seconds, args.mode)))
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except Exception as exc:
        print(f"CONTROL_FAILED {type(exc).__name__}: {exc}")
        raise SystemExit(1) from None
