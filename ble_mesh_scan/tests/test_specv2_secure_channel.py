"""Fixed-vector checks for the proposed FE95/001A SpecV2 channel.

The ciphertext constants were generated independently with PyCryptodome
AES.MODE_CCM. Runtime code needs only the project's cryptography dependency.
"""

from __future__ import annotations

import unittest

from ble_mesh_mcp.xiaomi.secure_channel import MiotBleSecureChannel, SecureChannelError
from ble_mesh_mcp.xiaomi.specv2 import (
    SpecV2Error, build_set_property, parse_set_property_response,
)


MATERIAL = bytes(range(64))
OFF_PLAIN = bytes.fromhex("0c2001000001020100010000")
OFF_WIRE = bytes.fromhex("0000055afe3896b0a62a7850bee99b0a06a1")
RESPONSE_PLAIN = bytes.fromhex("0b20010001010201000000")
RESPONSE_WIRE = bytes.fromhex("00007b0e944e86f904380ca1ae40f398cb")


class SpecV2Tests(unittest.TestCase):
    def test_boolean_off_encoding(self) -> None:
        self.assertEqual(build_set_property(tid=1, siid=2, piid=1, value=False), OFF_PLAIN)
        self.assertEqual(len(OFF_PLAIN), 12)

    def test_response_accepts_matching_success(self) -> None:
        response = parse_set_property_response(
            RESPONSE_PLAIN, expected_tid=1, expected_siid=2, expected_piid=1,
        )
        self.assertEqual(response.status, 0)
        with self.assertRaises(SpecV2Error):
            parse_set_property_response(
                RESPONSE_PLAIN, expected_tid=2, expected_siid=2, expected_piid=1,
            )


class SecureChannelTests(unittest.TestCase):
    def test_fixed_independent_ccm_vectors(self) -> None:
        channel = MiotBleSecureChannel(MATERIAL)
        self.assertEqual(channel.encrypt(OFF_PLAIN), OFF_WIRE)
        self.assertEqual(channel.decrypt(RESPONSE_WIRE), RESPONSE_PLAIN)
        self.assertNotIn(MATERIAL.hex(), repr(channel))

    def test_bad_mic_and_duplicate_are_rejected(self) -> None:
        channel = MiotBleSecureChannel(MATERIAL)
        tampered = RESPONSE_WIRE[:-1] + bytes((RESPONSE_WIRE[-1] ^ 1,))
        with self.assertRaisesRegex(SecureChannelError, "MIC"):
            channel.decrypt(tampered)
        self.assertEqual(channel.decrypt(RESPONSE_WIRE), RESPONSE_PLAIN)
        with self.assertRaisesRegex(SecureChannelError, "duplicate"):
            channel.decrypt(RESPONSE_WIRE)

    def test_bit15_epoch_transition(self) -> None:
        channel = MiotBleSecureChannel(MATERIAL)
        channel._tx_seq = 0x7FFF
        channel._tx_epoch = 0
        first = channel.encrypt(OFF_PLAIN)
        self.assertEqual(first[:2], b"\xff\x7f")
        self.assertEqual(channel._tx_seq, 0x8000)
        self.assertEqual(channel._tx_epoch, 1)
        second = channel.encrypt(OFF_PLAIN)
        self.assertEqual(second[:2], b"\x00\x80")
        self.assertNotEqual(first[2:], second[2:])


if __name__ == "__main__":
    unittest.main()
