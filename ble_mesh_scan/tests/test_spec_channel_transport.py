"""Offline checks for the old Mi Home FE95/001A channel framing."""

from __future__ import annotations

import asyncio
import unittest

from ble_mesh_mcp.xiaomi.spec_channel_transport import encode_write_start, exchange


class SpecTransportTests(unittest.IsolatedAsyncioTestCase):
    def test_one_segment_still_starts_with_seg_cmd(self) -> None:
        self.assertEqual(encode_write_start(18, 107), bytes.fromhex("000000000100"))

    async def test_send_and_single_response(self) -> None:
        queue: asyncio.Queue[bytes] = asyncio.Queue()
        writes: list[bytes] = []
        payload = bytes(range(18))

        async def write(frame: bytes) -> None:
            writes.append(frame)
            if frame == bytes.fromhex("000000000100"):
                queue.put_nowait(bytes.fromhex("00000101"))
            elif frame == b"\x01\x00" + payload:
                queue.put_nowait(bytes.fromhex("00000100"))
                queue.put_nowait(bytes.fromhex("00000200") + b"reply")

        answer = await exchange(
            payload, dmtu=107, incoming=queue, write=write,
            record=lambda _direction, _data: None, timeout=1.0,
        )
        self.assertEqual(answer, b"reply")
        self.assertEqual(writes, [
            bytes.fromhex("000000000100"),
            b"\x01\x00" + payload,
            bytes.fromhex("00000300"),
        ])

    async def test_segmented_response_acknowledged(self) -> None:
        queue: asyncio.Queue[bytes] = asyncio.Queue()
        writes: list[bytes] = []

        async def write(frame: bytes) -> None:
            writes.append(frame)
            if frame == bytes.fromhex("000000000100"):
                queue.put_nowait(bytes.fromhex("00000101"))
            elif frame == b"\x01\x00x":
                queue.put_nowait(bytes.fromhex("00000100"))
                queue.put_nowait(bytes.fromhex("000000000200"))
            elif frame == bytes.fromhex("00000101"):
                queue.put_nowait(b"\x01\x00ab")
                queue.put_nowait(b"\x02\x00cd")

        answer = await exchange(
            b"x", dmtu=107, incoming=queue, write=write,
            record=lambda _direction, _data: None, timeout=1.0,
        )
        self.assertEqual(answer, b"abcd")
        self.assertEqual(writes[-2:], [bytes.fromhex("00000101"),
                                       bytes.fromhex("00000100")])

    async def test_write_001a_response_001b(self) -> None:
        write_queue: asyncio.Queue[bytes] = asyncio.Queue()
        read_queue: asyncio.Queue[bytes] = asyncio.Queue()
        write_frames: list[bytes] = []
        read_acks: list[bytes] = []

        async def write_001a(frame: bytes) -> None:
            write_frames.append(frame)
            if len(write_frames) == 1:
                write_queue.put_nowait(bytes.fromhex("00000101"))
            else:
                write_queue.put_nowait(bytes.fromhex("00000100"))
                read_queue.put_nowait(bytes.fromhex("00000200") + b"ok")

        async def write_001b(frame: bytes) -> None:
            read_acks.append(frame)

        answer = await exchange(
            b"x", dmtu=107, incoming=write_queue, write=write_001a,
            response_incoming=read_queue, write_response_ack=write_001b,
            record=lambda _direction, _data: None, timeout=1.0,
        )
        self.assertEqual(answer, b"ok")
        self.assertEqual(read_acks, [bytes.fromhex("00000300")])


if __name__ == "__main__":
    unittest.main()
