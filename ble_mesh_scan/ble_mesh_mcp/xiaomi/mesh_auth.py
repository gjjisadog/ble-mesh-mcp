"""Mesh Auth opcodes and parsers for captured FE95 payloads."""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import MeshAuthOpcode, RXFER_MODE_NAMES, RXFER_TYPE_NAMES, RxferMode, RxferType


MESH_REG_START = int(MeshAuthOpcode.MESH_REG_START).to_bytes(4, "little")


def generate_client_ephemeral_key() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Return a fresh P-256 private key and Xiaomi wire-format X||Y (64 bytes)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_sec1 = private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return private_key, public_sec1[1:]


def derive_ltmk(
    client_private_key: ec.EllipticCurvePrivateKey,
    device_ephemeral_public_key: bytes,
    *,
    oob: bytes | None = None,
) -> bytes:
    """Derive the 32-byte Mesh registration LTMK from P-256 ECDH.

    The Telink NO_OOB branch uses a zero-length salt. Its OOB branch uses a
    16-byte salt; callers must supply that exact value when OOB is selected.
    The device key accepts 64-byte X||Y or 65-byte SEC1 uncompressed form.
    """
    if not isinstance(client_private_key.curve, ec.SECP256R1):
        raise ValueError("client key must use P-256")
    point = bytes(device_ephemeral_public_key)
    if len(point) == 64:
        point = b"\x04" + point
    if len(point) != 65 or point[0] != 4:
        raise ValueError("device public key must be 64-byte X||Y or 65-byte SEC1")
    if oob is not None and len(oob) != 16:
        raise ValueError("OOB salt must be exactly 16 bytes")
    device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    shared_secret = client_private_key.exchange(ec.ECDH(), device_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=oob,
        info=b"miot-mesh-auth-info",
    ).derive(shared_secret)


def compute_ltmk_digest(ltmk: bytes) -> bytes:
    """Return SHA-256(LTMK), the digest signed in Mesh registration."""
    if len(ltmk) != 32:
        raise ValueError("LTMK must be exactly 32 bytes")
    return hashlib.sha256(ltmk).digest()


def verify_device_signature(
    device_certificate_der: bytes, ltmk_digest: bytes, device_signature: bytes
) -> bool:
    """Verify DEV_SIGNATURE as P-256 raw R||S over SHA-256(LTMK).

    This proves possession of the certificate private key only; it does not
    verify the certificate chain or manufacturer identity.
    """
    if len(ltmk_digest) != 32 or len(device_signature) != 64:
        raise ValueError("expected a 32-byte digest and 64-byte R||S signature")
    public_key = x509.load_der_x509_certificate(bytes(device_certificate_der)).public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise ValueError("device certificate must contain a P-256 public key")
    signature_der = utils.encode_dss_signature(
        int.from_bytes(device_signature[:32], "big"),
        int.from_bytes(device_signature[32:], "big"),
    )
    try:
        public_key.verify(
            signature_der, bytes(ltmk_digest), ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
    except InvalidSignature:
        return False
    return True


def derive_gatt_ltmk(ltmk: bytes) -> bytes:
    """Derive the 32-byte key used by the later Admin Login path."""
    if len(ltmk) != 32:
        raise ValueError("LTMK must be exactly 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"gatt-ltmk",
        info=b"miot-mesh-ltmk-info",
    ).derive(ltmk)


def parse_mesh_ecc_frame(characteristic: str, frame: bytes) -> dict[str, Any] | None:
    """Parse the observed 88-byte ECC_PUBKEY SGL_CMD frame."""
    data = bytes(frame)
    if (
        characteristic != "0016"
        or len(data) != 88
        or data[2:4] != bytes((RxferMode.SGL_CMD, RxferType.ECC_PUBKEY))
    ):
        return None

    payload = data[4:]
    cipher_suite = int.from_bytes(payload[8:10], "little")
    protocol_version = int.from_bytes(payload[10:12], "little")
    public_key_x = payload[20:52]
    public_key_y = payload[52:84]
    return {
        "sn": int.from_bytes(data[0:2], "little"),
        "mode": data[2],
        "mode_name": RXFER_MODE_NAMES.get(data[2], "UNKNOWN"),
        "type": data[3],
        "type_name": RXFER_TYPE_NAMES.get(data[3], "UNKNOWN"),
        "base_io": payload[0],
        "future_io": payload[1],
        "reserved_hex": payload[2:8].hex(" ").upper(),
        "cipher_suite": cipher_suite,
        "cipher_suite_hex": f"0x{cipher_suite:04X}",
        "protocol_version": protocol_version,
        "protocol_version_hex": f"0x{protocol_version:04X}",
        "manufacturer_sn_hex": payload[12:20].hex().upper(),
        "public_key_x_hex": public_key_x.hex().upper(),
        "public_key_y_hex": public_key_y.hex().upper(),
        "public_key_sec1_hex": (b"\x04" + public_key_x + public_key_y).hex().upper(),
    }
