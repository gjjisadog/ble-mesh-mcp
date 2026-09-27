"""Offline X.509 and public-key analysis for captured Xiaomi certificates."""

from __future__ import annotations

import warnings
from datetime import timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID


def _oid_name(oid: Any) -> str | None:
    return getattr(oid, "_name", None)


def _name_fields(name: x509.Name) -> list[dict[str, str | None]]:
    return [
        {
            "oid": attribute.oid.dotted_string,
            "name": _oid_name(attribute.oid),
            "value": attribute.value,
        }
        for attribute in name
    ]


def _utc_value(certificate: x509.Certificate, modern_name: str, legacy_name: str) -> str:
    value = getattr(certificate, modern_name, None)
    if value is None:
        value = getattr(certificate, legacy_name).replace(tzinfo=timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _general_name(value: Any) -> dict[str, str]:
    item = {"type": type(value).__name__}
    if hasattr(value, "value"):
        item["value"] = str(value.value)
    else:
        item["value"] = str(value)
    return item


def _key_usage(value: x509.KeyUsage) -> dict[str, bool]:
    result = {
        "digital_signature": value.digital_signature,
        "content_commitment": value.content_commitment,
        "key_encipherment": value.key_encipherment,
        "data_encipherment": value.data_encipherment,
        "key_agreement": value.key_agreement,
        "key_cert_sign": value.key_cert_sign,
        "crl_sign": value.crl_sign,
    }
    if value.key_agreement:
        result["encipher_only"] = value.encipher_only
        result["decipher_only"] = value.decipher_only
    return result


def _extension_value(value: Any) -> Any:
    if isinstance(value, x509.BasicConstraints):
        return {"ca": value.ca, "path_length": value.path_length}
    if isinstance(value, x509.KeyUsage):
        return _key_usage(value)
    if isinstance(value, x509.ExtendedKeyUsage):
        return [
            {"oid": oid.dotted_string, "name": _oid_name(oid)}
            for oid in value
        ]
    if isinstance(value, x509.SubjectKeyIdentifier):
        return {"digest_hex": value.digest.hex().upper()}
    if isinstance(value, x509.AuthorityKeyIdentifier):
        return {
            "key_identifier_hex": (
                value.key_identifier.hex().upper() if value.key_identifier else None
            ),
            "authority_cert_issuer": (
                [_general_name(name) for name in value.authority_cert_issuer]
                if value.authority_cert_issuer
                else None
            ),
            "authority_cert_serial_number": value.authority_cert_serial_number,
        }
    if isinstance(value, x509.SubjectAlternativeName):
        return [_general_name(name) for name in value]
    if isinstance(value, x509.IssuerAlternativeName):
        return [_general_name(name) for name in value]
    if isinstance(value, x509.UnrecognizedExtension):
        return {"raw_hex": value.value.hex().upper()}
    return {"text": str(value)}


def _serialize_extensions(certificate: x509.Certificate) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    known_oids = {
        value.dotted_string
        for value in vars(ExtensionOID).values()
        if hasattr(value, "dotted_string")
    }
    extensions: list[dict[str, Any]] = []
    custom_oids: list[dict[str, Any]] = []

    for extension in certificate.extensions:
        oid = extension.oid
        value = extension.value
        item = {
            "oid": oid.dotted_string,
            "name": _oid_name(oid),
            "critical": extension.critical,
            "value": _extension_value(value),
        }
        extensions.append(item)
        if oid.dotted_string not in known_oids:
            custom_oids.append(item)

    return extensions, custom_oids


def _public_key_fields(public_key: Any) -> dict[str, Any]:
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        return {
            "key_type": type(public_key).__name__,
            "curve": None,
            "key_size": getattr(public_key, "key_size", None),
            "x_hex": None,
            "y_hex": None,
            "sec1_uncompressed_hex": None,
            "p256_point_valid": None,
        }

    numbers = public_key.public_numbers()
    coordinate_size = (public_key.curve.key_size + 7) // 8
    point = public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    p256_point_valid: bool | None = None
    if public_key.curve.name in {"secp256r1", "prime256v1"}:
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
            p256_point_valid = True
        except ValueError:
            p256_point_valid = False

    return {
        "key_type": type(public_key).__name__,
        "curve": public_key.curve.name,
        "key_size": public_key.key_size,
        "x_hex": numbers.x.to_bytes(coordinate_size, "big").hex().upper(),
        "y_hex": numbers.y.to_bytes(coordinate_size, "big").hex().upper(),
        "sec1_uncompressed_hex": point.hex().upper(),
        "p256_point_valid": p256_point_valid,
    }


def _compare_public_keys(static_key: Any, ephemeral_sec1: bytes | None) -> dict[str, Any] | None:
    if ephemeral_sec1 is None:
        return None

    try:
        ephemeral_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes(ephemeral_sec1)
        )
        ephemeral_numbers = ephemeral_key.public_numbers()
        ephemeral_valid = True
    except ValueError as exc:
        return {
            "ephemeral_p256_point_valid": False,
            "same_public_key": None,
            "error": str(exc),
        }

    static_is_p256 = (
        isinstance(static_key, ec.EllipticCurvePublicKey)
        and static_key.curve.name in {"secp256r1", "prime256v1"}
    )
    same_key = None
    if static_is_p256:
        static_numbers = static_key.public_numbers()
        same_key = (
            static_numbers.x == ephemeral_numbers.x
            and static_numbers.y == ephemeral_numbers.y
        )

    return {
        "ephemeral_p256_point_valid": ephemeral_valid,
        "same_public_key": same_key,
        "interpretation": "device certificate key is static; ECC_PUBKEY is the session's registration key",
    }


def analyze_device_certificate(
    der_bytes: bytes,
    ephemeral_public_key_sec1: bytes | None = None,
) -> dict[str, Any]:
    """Parse certificate identity, extensions and P-256 key without trusting its issuer."""
    parse_warnings: list[str] = []
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        certificate = x509.load_der_x509_certificate(bytes(der_bytes))
        public_key = certificate.public_key()
        extensions, custom_oids = _serialize_extensions(certificate)
        try:
            signature_hash = certificate.signature_hash_algorithm.name
        except Exception as exc:
            signature_hash = None
            parse_warnings.append(f"Could not decode signature hash algorithm: {exc}")
        parse_warnings.extend(str(item.message) for item in caught)

    serial_number = certificate.serial_number
    serial_bytes = serial_number.to_bytes(max(1, (serial_number.bit_length() + 7) // 8), "big")
    static_key = _public_key_fields(public_key)
    comparison = _compare_public_keys(public_key, ephemeral_public_key_sec1)

    result = {
        "format": "X.509 DER",
        "der_length": len(der_bytes),
        "serial_number": serial_number,
        "serial_hex": serial_bytes.hex().upper(),
        "issuer": _name_fields(certificate.issuer),
        "subject": _name_fields(certificate.subject),
        "validity": {
            "not_before_utc": _utc_value(certificate, "not_valid_before_utc", "not_valid_before"),
            "not_after_utc": _utc_value(certificate, "not_valid_after_utc", "not_valid_after"),
        },
        "signature_algorithm": {
            "oid": certificate.signature_algorithm_oid.dotted_string,
            "name": _oid_name(certificate.signature_algorithm_oid),
            "hash": signature_hash,
        },
        "sha256_fingerprint": certificate.fingerprint(hashes.SHA256()).hex().upper(),
        "subject_key_identifier": next(
            (
                extension["value"]["digest_hex"]
                for extension in extensions
                if extension["oid"] == ExtensionOID.SUBJECT_KEY_IDENTIFIER.dotted_string
            ),
            None,
        ),
        "authority_key_identifier": next(
            (
                extension["value"]
                for extension in extensions
                if extension["oid"] == ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string
            ),
            None,
        ),
        "basic_constraints": next(
            (
                extension["value"]
                for extension in extensions
                if extension["oid"] == ExtensionOID.BASIC_CONSTRAINTS.dotted_string
            ),
            None,
        ),
        "key_usage": next(
            (
                extension["value"]
                for extension in extensions
                if extension["oid"] == ExtensionOID.KEY_USAGE.dotted_string
            ),
            None,
        ),
        "extended_key_usage": next(
            (
                extension["value"]
                for extension in extensions
                if extension["oid"] == ExtensionOID.EXTENDED_KEY_USAGE.dotted_string
            ),
            None,
        ),
        "extensions": extensions,
        "custom_oids": custom_oids,
        "static_public_key": static_key,
        "public_key_comparison": comparison,
        "did_candidate": {
            "hex": serial_bytes.rjust(8, b"\x00").hex().upper(),
            "did_source": "derived_from_device_cert_serial",
            "verified": False,
        },
        "chain_signature_verified": False,
        "chain_verification_note": "No trusted manufacturer CA certificate was available for chain verification.",
        "parser_warnings": list(dict.fromkeys(parse_warnings)),
    }
    return result
