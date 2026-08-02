"""Tagged hashing and HMAC constructions (spec PROTOCOL.md sec 4-5)."""

import hashlib
import hmac as _hmac
from .canonical import encode


def sha256_text(s: str) -> str:
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


def tagged_digest(tag: str, value) -> str:
    if not tag or not tag.isascii():
        raise ValueError("tag must be non-empty ASCII")
    preimage = tag.encode("ascii") + b"\x0a" + encode(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def hmac_sha256(key_hex_arg: str, msg: str) -> str:
    """Primitive HMAC-SHA256: key_hex_arg is hex-decoded to raw bytes."""
    key_bytes = bytes.fromhex(key_hex_arg)
    return _hmac.new(key_bytes, msg.encode("utf-8"), hashlib.sha256).hexdigest()


def certificate_mac(key_hex_arg: str, unsigned_cert: dict) -> str:
    """Clean v2 construction: key_hex_arg used directly as hex-decoded key."""
    key_bytes = bytes.fromhex(key_hex_arg)
    message = b"confine.certificate.mac.v2\x0a" + encode(unsigned_cert).encode("utf-8")
    mac = _hmac.new(key_bytes, message, hashlib.sha256).hexdigest()
    return "sha256:" + mac


def certificate_mac_v1_fard(secret: str, unsigned_cert: dict) -> str:
    """Matches packages/confine/certificate.fard exactly: broker_secret is
    an arbitrary caller string, normalized via bytes.to_hex(bytes.of_str(secret))
    before being passed to hmac_sha256 (which hex-decodes it again). Net
    effect: the actual HMAC key is the raw UTF-8 bytes of the secret
    STRING itself -- not bytes.fromhex(secret). v1-fard artifact.
    """
    key_bytes = secret.encode("utf-8")
    message = b"confine.certificate.mac.v1\x0a" + encode(unsigned_cert).encode("utf-8")
    mac = _hmac.new(key_bytes, message, hashlib.sha256).hexdigest()
    return "sha256:" + mac
