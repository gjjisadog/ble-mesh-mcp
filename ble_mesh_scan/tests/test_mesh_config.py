"""Offline, synthetic fixtures for the X08A Mesh config layout."""

import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from ble_mesh_mcp.xiaomi.cloud.miio_blemesh import (
    MeshModelElement,
    MeshModelInfo,
    XiaomiMiioBleMeshCloud,
)
from ble_mesh_mcp.xiaomi.mesh_config import MeshConfigBuilder, derive_device_key_x08a
from ble_mesh_mcp.xiaomi.registration_state import RegistrationProgress, RegistrationStage


class _FixtureMiio:
    def __init__(self) -> None:
        self.requests = []

    async def miio_request(self, uri, data):
        self.requests.append((uri, data))
        if uri.endswith("ctl_info"):
            return {
                "iv_index": "01020304",
                "primary_netkey": {"key": bytes(range(32, 48)).hex()},
                "ctl_appkey": {"key": bytes(range(48, 64)).hex()},
            }
        if uri.endswith("query_model"):
            return {"elements": [{"num": 0, "model_id": ["1000", "12345678"]}]}
        raise AssertionError("unexpected Cloud endpoint")


class MeshConfigFixtureTests(unittest.TestCase):
    def test_four_tlvs_device_key_and_ccm(self):
        static_oob = bytes(range(16, 32))
        model = MeshModelInfo(0x90C0, (MeshModelElement(0, (0x1000, 0x12345678)),))
        artifact = MeshConfigBuilder.build(
            random16=bytes(range(16)),
            static_oob=static_oob,
            netkey=bytes(range(32, 48)),
            netkey_index=0x123,
            flags=2,
            iv_index=0x01020304,
            unicast_address=0x4567,
            appkey=bytes(range(48, 64)),
            appkey_index=0,
            model_info=model,
        )
        self.assertEqual(
            derive_device_key_x08a(bytes(range(16)), static_oob).hex(),
            "be1d1a323e7cf2cd59a0793b271649bb",
        )
        self.assertEqual(artifact.device_key.hex(), "be1d1a323e7cf2cd59a0793b271649bb")
        self.assertEqual(
            artifact.plaintext.hex(),
            "0110be1d1a323e7cf2cd59a0793b271649bb"
            "0219202122232425262728292a2b2c2d2e2f230102040302016745"
            "031423010000303132333435363738393a3b3c3d3e3f"
            "041000000000001000000000341278560000",
        )
        self.assertEqual(len(artifact.plaintext), 69 + 8 * 2)
        self.assertEqual(artifact.model_bind_count, 2)
        self.assertEqual(
            artifact.encrypted_payload.hex(),
            "f4b319b1abb6a4e6dae3b616a4a280d73b962aa969d2f12c83bd8748cd745aa"
            "7b0717e730d2240fdc9a6f03f647ae7e6a47718d4658edba4f9ab7d550459f"
            "0e7817a07e523ee027ee7b339e4b0840a004148bf2bb08cbe630d",
        )
        self.assertEqual(
            AESCCM(static_oob, tag_length=4).decrypt(
                static_oob[:8], artifact.encrypted_payload, None
            ),
            artifact.plaintext,
        )
        self.assertNotIn(static_oob.hex(), repr(artifact))

    def test_registration_milestones_do_not_skip_device_result(self):
        progress = RegistrationProgress().advance(
            RegistrationStage.CLOUD_AUTH_RESPONSE_RECEIVED
        ).advance(RegistrationStage.DEVICE_SIGNATURE_RECEIVED)
        with self.assertRaises(ValueError):
            progress.advance(RegistrationStage.DEVICE_REGISTERED)
        self.assertEqual(progress.stage, RegistrationStage.DEVICE_SIGNATURE_RECEIVED)


class ReadOnlyCloudFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def test_requests_and_metadata(self):
        fake = _FixtureMiio()
        cloud = XiaomiMiioBleMeshCloud(fake)
        controller = await cloud.get_controller_info()
        model = await cloud.get_model_info(0x90C0)
        self.assertEqual(
            fake.requests,
            [
                ("/v2/blemesh/ctl_info", {}),
                ("/v2/blemesh/query_model", {"pdid": 37056}),
            ],
        )
        self.assertEqual(controller.iv_index, 0x01020304)
        self.assertEqual(len(controller.primary_netkey), 16)
        self.assertEqual(len(controller.ctl_appkey), 16)
        self.assertEqual(model.elements[0].model_ids, (0x1000, 0x12345678))
        self.assertNotIn(controller.primary_netkey.hex(), repr(controller))


if __name__ == "__main__":
    unittest.main()
