"""Ten ON/OFF transitions at ten-second targets in one BLE session.

First issues one unmeasured OFF command to establish a known baseline, then
measures ON/OFF ten times and ends OFF. Stops if a transport or property
response fails. No property command is retried and no key is logged.
"""

from __future__ import annotations

import asyncio
import json
import math
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from ble_mesh_mcp.transport.bleak_transport import BleakTransport
from ble_mesh_mcp.xiaomi.admin_login import MeshSession
from ble_mesh_mcp.xiaomi.credentials import load_gatt_ltmk
from ble_mesh_mcp.xiaomi.constants import RxferAck, RxferMode, RxferType
from ble_mesh_mcp.xiaomi.live_admin_login import verify_admin_login
from ble_mesh_mcp.xiaomi.local_control import send_property_in_session
from ble_mesh_mcp.xiaomi.device_config import load_device_config
from ble_mesh_mcp.xiaomi.rxfer import encode_segment_ack, encode_single_ack, parse_frame
from ble_mesh_mcp.xiaomi.secure_channel import MiotBleSecureChannel


COUNT = 10
INTERVAL_SECONDS = 10.0
WATCH_COUNTDOWN_SECONDS = 5.0
LOG_DIR = Path(__file__).resolve().parent / "logs"


async def main() -> int:
    key = load_gatt_ltmk()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / f"toggle_benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    write_replies: asyncio.Queue[bytes] = asyncio.Queue()
    read_replies: asyncio.Queue[bytes] = asyncio.Queue()
    measurements: list[dict[str, object]] = []
    marks: dict[str, float] = {}
    failure: str | None = None
    started = time.perf_counter()

    def on_write(_characteristic, value: bytearray) -> None:
        write_replies.put_nowait(bytes(value))

    def on_read(_characteristic, value: bytearray) -> None:
        read_replies.put_nowait(bytes(value))

    with log_path.open("w", encoding="utf-8") as journal:
        def record(event: str, **details: object) -> None:
            journal.write(json.dumps({
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **details,
            }, separators=(",", ":")) + "\n")
            journal.flush()

        def progress(stage: str) -> None:
            if stage in ("connected", "admin_login_0x51_verified"):
                marks[stage] = time.perf_counter()
                record("login_stage", stage=stage)

        async def run_series(
            transport: BleakTransport, session: MeshSession,
            _login_queue: asyncio.Queue[tuple[str, bytes]],
        ) -> None:
            nonlocal failure
            for sid in ("001A", "001B"):
                char = transport.characteristics.get(sid)
                if char is None or not {"write-without-response", "notify"}.issubset(char.properties):
                    raise RuntimeError(f"FE95/{sid} write/notify unavailable")
            if transport.negotiated_dmtu is None:
                raise RuntimeError("FE95 data transfer size was not negotiated")
            channel = MiotBleSecureChannel(session)

            async def drain_pending() -> None:
                """ACK state notifications that follow a property response."""
                for _ in range(32):
                    if not write_replies.empty():
                        raw = write_replies.get_nowait()
                        frame = parse_frame(raw)
                        record("extra_001a_frame", mode=frame.mode,
                               code=frame.data_type, length=len(raw))
                        if not (frame.is_control and frame.mode == RxferMode.SEG_ACK
                                and frame.data_type == RxferAck.A_SUCCESS):
                            raise RuntimeError("unexpected 001A notification between commands")
                        continue
                    if read_replies.empty():
                        return
                    raw = read_replies.get_nowait()
                    frame = parse_frame(raw)
                    record("extra_001b_frame", mode=frame.mode,
                           code=frame.data_type, length=len(raw))
                    if not frame.is_control:
                        raise RuntimeError("unexpected 001B segment between commands")
                    if frame.mode == RxferMode.SGL_CMD and frame.data_type == RxferType.PASS_THROUGH:
                        await transport.write("001B", encode_single_ack(RxferAck.A_SUCCESS))
                        try:
                            plaintext = channel.decrypt(frame.body)
                            record("extra_property_notification", plaintext_length=len(plaintext))
                        except Exception as exc:
                            record("extra_notification_decrypt_failed", error_type=type(exc).__name__)
                        continue
                    if frame.mode == RxferMode.SEG_CMD and frame.data_type == RxferType.PASS_THROUGH:
                        count = int.from_bytes(frame.body, "little") if len(frame.body) == 2 else 0
                        if not 1 <= count <= 8:
                            raise RuntimeError("unexpected 001B segment count")
                        await transport.write("001B", encode_segment_ack(RxferAck.A_READY))
                        chunks: dict[int, bytes] = {}
                        while len(chunks) < count:
                            part = parse_frame(await asyncio.wait_for(read_replies.get(), 2.0))
                            if 1 <= part.sequence <= count and part.body:
                                chunks[part.sequence] = part.body
                        await transport.write("001B", encode_segment_ack(RxferAck.A_SUCCESS))
                        try:
                            plaintext = channel.decrypt(b"".join(chunks[i] for i in range(1, count + 1)))
                            record("extra_property_notification", plaintext_length=len(plaintext))
                        except Exception as exc:
                            record("extra_notification_decrypt_failed", error_type=type(exc).__name__)
                        continue
                    if frame.mode in (RxferMode.SEG_ACK, RxferMode.SGL_ACK):
                        continue
                    raise RuntimeError("unexpected 001B control frame between commands")
                raise RuntimeError("too many pending notifications")

            # Establish a known OFF baseline before the ten measured transitions.
            await drain_pending()
            reset_started = time.perf_counter()
            reset_result = await send_property_in_session(
                transport, channel, write_replies, read_replies,
                value=False, tid=0, timeout=8.0,
            )
            record("baseline_reset_off", property_status=reset_result.property_status,
                   latency_ms=round((time.perf_counter() - reset_started) * 1000, 2))
            if not reset_result.protocol_verified:
                raise RuntimeError("OFF baseline reset failed")
            print("BASELINE_RESET_OFF status=0", flush=True)
            await asyncio.sleep(0.3)
            await drain_pending()
            print(f"WATCH_READY first ON in {WATCH_COUNTDOWN_SECONDS:.0f} seconds", flush=True)
            await asyncio.sleep(WATCH_COUNTDOWN_SECONDS)
            schedule_start = time.perf_counter()
            record("series_started", count=COUNT, interval_seconds=INTERVAL_SECONDS,
                   assumed_initial_state="off")

            for index in range(COUNT):
                scheduled = schedule_start + index * INTERVAL_SECONDS
                await asyncio.sleep(max(0.0, scheduled - time.perf_counter()))
                command_started = time.perf_counter()
                value = index % 2 == 0
                tid = index + 1
                try:
                    await drain_pending()
                except Exception as exc:
                    failure = type(exc).__name__
                    record("series_stopped", operation=index + 1, reason=failure)
                    return
                accepted_at: float | None = None

                def acked() -> None:
                    nonlocal accepted_at
                    accepted_at = time.perf_counter()

                record("operation_started", operation=index + 1, desired_state="on" if value else "off",
                       tid=tid, schedule_lag_ms=round((command_started - scheduled) * 1000, 2))
                try:
                    response = await send_property_in_session(
                        transport, channel, write_replies, read_replies,
                        value=value, tid=tid,
                        on_transport_acked=acked,
                        on_unrelated_packet=lambda reason, length: record(
                            "unrelated_001b_packet", operation=index + 1,
                            reason=reason, plaintext_length=length),
                        timeout=8.0,
                    )
                except Exception as exc:
                    failure = type(exc).__name__
                    record("operation_failed", operation=index + 1,
                           desired_state="on" if value else "off",
                           transport_acked=accepted_at is not None,
                           error_type=failure, reason=str(exc))
                    return

                finished = time.perf_counter()
                measurement = {
                    "operation": index + 1,
                    "desired_state": "on" if value else "off",
                    "tid": tid,
                    "transport_acked": accepted_at is not None,
                    "property_status": response.property_status,
                    "ack_latency_ms": round((accepted_at - command_started) * 1000, 2) if accepted_at else None,
                    "response_latency_ms": round((finished - command_started) * 1000, 2),
                    "schedule_lag_ms": round((command_started - scheduled) * 1000, 2),
                    "start_monotonic": command_started,
                }
                measurements.append(measurement)
                record("operation_result", **{k: v for k, v in measurement.items() if k != "start_monotonic"})
                print(f"{index + 1:02d}/{COUNT} {measurement['desired_state'].upper()} "
                      f"ACK={measurement['ack_latency_ms']}ms "
                      f"RESP={measurement['response_latency_ms']}ms "
                      f"STATUS={response.property_status}", flush=True)
                if not response.protocol_verified or accepted_at is None:
                    failure = "property_status_nonzero_or_transport_unacked"
                    record("series_stopped", operation=index + 1, reason=failure)
                    return

        try:
            await verify_admin_login(
                load_device_config().address, key, progress=progress,
                on_authenticated=run_series,
                prelogin_notifications={"001A": on_write, "001B": on_read},
            )
        except Exception as exc:
            failure = type(exc).__name__
            record("benchmark_exception", error_type=failure)

        latencies = [float(item["response_latency_ms"]) for item in measurements]
        ack_latencies = [float(item["ack_latency_ms"]) for item in measurements
                         if item["ack_latency_ms"] is not None]
        starts = [float(item["start_monotonic"]) for item in measurements]
        actual_intervals = [(b - a) * 1000 for a, b in zip(starts, starts[1:])]
        complete = failure is None and len(measurements) == COUNT and all(
            item["transport_acked"] and item["property_status"] == 0 for item in measurements
        )
        summary = {
            "requested_operations": COUNT,
            "completed_operations": len(measurements),
            "success": complete,
            "failure_type": failure,
            "connect_seconds": round(marks["connected"] - started, 3) if "connected" in marks else None,
            "login_seconds": round(marks["admin_login_0x51_verified"] - marks["connected"], 3)
                             if {"connected", "admin_login_0x51_verified"} <= marks.keys() else None,
            "ack_latency_mean_ms": round(statistics.mean(ack_latencies), 2) if ack_latencies else None,
            "response_latency_mean_ms": round(statistics.mean(latencies), 2) if latencies else None,
            "response_latency_min_ms": round(min(latencies), 2) if latencies else None,
            "response_latency_max_ms": round(max(latencies), 2) if latencies else None,
            "response_latency_p95_ms": round(sorted(latencies)[math.ceil(0.95 * len(latencies)) - 1], 2)
                                      if latencies else None,
            "actual_start_interval_mean_ms": round(statistics.mean(actual_intervals), 2)
                                             if actual_intervals else None,
            "final_requested_state": measurements[-1]["desired_state"] if measurements else None,
        }
        record("benchmark_summary", **summary)
    print(f"BENCHMARK_SUMMARY {json.dumps(summary, separators=(',', ':'))}", flush=True)
    print(f"BENCHMARK_LOG {log_path.resolve()}", flush=True)
    return 0 if complete else 2


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        raise SystemExit(130) from None
