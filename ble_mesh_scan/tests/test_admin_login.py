"""Synthetic fixed vectors for the offline Xiaomi Mesh Admin Login layer.

Expected outputs were generated independently with PyCryptodome P-256/CCM,
manual HMAC-SHA256 HKDF, and zlib.crc32. No device credentials are used.
"""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from ble_mesh_mcp.xiaomi.admin_login import (
    LoginState,
    MeshAdminLogin,
    MeshLoginError,
)


CLIENT_PRIVATE = int(
    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201", 16
)
GATT_LTMK = bytes(range(32))
CLIENT_PUBLIC = bytes.fromhex(
    "67acad2d1008836776ce44720e8ac9fa5a5010742c156bd2b85d8b31683474a"
    "28de98824f726c9f4b0f588a7419dd9e4a18df6b82adcb70d0f6dd4ab31cace9d"
)
DEVICE_PUBLIC = bytes.fromhex(
    "515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f"
    "4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354"
)
SESSION_MATERIAL = bytes.fromhex(
    "a53c6788f7210d9f886b16ca367b3bd8837734d631486988bdbb96d3025083ed"
    "6d7661294f906ed0604209d54f6d8507a07a5107b8bba7f88690b6a08f550634"
)
LOGIN_PAYLOAD = bytes.fromhex("3cb95d7079e26358")


def fixed_login() -> MeshAdminLogin:
    return MeshAdminLogin(
        GATT_LTMK,
        private_key=ec.derive_private_key(CLIENT_PRIVATE, ec.SECP256R1()),
    )


class MeshAdminLoginTests(unittest.TestCase):
    def test_fixed_vector_and_success_state(self) -> None:
        login = fixed_login()
        self.assertEqual(login.state, LoginState.NEW)
        self.assertEqual(login.start(), b"\x50\x00\x00\x00")
        self.assertEqual(login.public_key_payload(), CLIENT_PUBLIC)
        self.assertEqual(login.accept_device_public_key(DEVICE_PUBLIC), LOGIN_PAYLOAD)
        self.assertEqual(login.state, LoginState.WAIT_RESULT)
        with self.assertRaises(MeshLoginError):
            _ = login.session
        session = login.complete(bytearray(b"\x51\x00\x00\x00"))
        self.assertEqual(login.state, LoginState.AUTHENTICATED)
        self.assertEqual(session.material, SESSION_MATERIAL)
        self.assertEqual(session.device_key, SESSION_MATERIAL[:16])
        self.assertEqual(session.application_key, SESSION_MATERIAL[16:32])
        self.assertEqual(session.device_iv, int.from_bytes(SESSION_MATERIAL[32:36], "little"))
        self.assertEqual(session.application_iv, int.from_bytes(SESSION_MATERIAL[36:40], "little"))
        self.assertIs(login.session, session)
        self.assertNotIn(GATT_LTMK.hex(), repr(login))
        self.assertNotIn(SESSION_MATERIAL.hex(), repr(session))

    def test_order_and_bad_public_key(self) -> None:
        login = fixed_login()
        with self.assertRaises(MeshLoginError):
            login.public_key_payload()
        login.start()
        login.public_key_payload()
        with self.assertRaises(ValueError):
            login.accept_device_public_key(bytes(64))
        self.assertEqual(login.state, LoginState.FAILED)

    def test_rejected_ltmk_is_terminal(self) -> None:
        login = fixed_login()
        login.start()
        login.public_key_payload()
        login.accept_device_public_key(DEVICE_PUBLIC)
        with self.assertRaisesRegex(MeshLoginError, "0x52"):
            login.complete(b"\x52\x00\x00\x00")
        self.assertEqual(login.state, LoginState.FAILED)
        with self.assertRaises(MeshLoginError):
            _ = login.session

    def test_rejects_wrong_ltmk_size(self) -> None:
        with self.assertRaises(ValueError):
            MeshAdminLogin(bytes(31))

    def test_generic_failure_is_terminal(self) -> None:
        login = fixed_login()
        login.start()
        login.public_key_payload()
        login.accept_device_public_key(DEVICE_PUBLIC)
        with self.assertRaisesRegex(MeshLoginError, "0x53"):
            login.complete(b"\x53\x00\x00\x00")
        self.assertEqual(login.state, LoginState.FAILED)


if __name__ == "__main__":
    unittest.main()
