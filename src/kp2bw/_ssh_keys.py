"""Validate explicitly selected SSH key material without logging its contents."""

import base64
import hashlib
import struct
from dataclasses import dataclass
from textwrap import wrap

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from .bw_types import BwSshKey

type SupportedPrivateKey = ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey


@dataclass(frozen=True)
class SshConversion:
    key: BwSshKey | None
    reason: str | None = None


def _openssh_private(key: SupportedPrivateKey, public_blob: bytes) -> str:
    """Emit a stable unencrypted OpenSSH representation for unchanged reruns.

    OpenSSH's two equal check integers detect corruption; they are not a salt
    for an unencrypted key. cryptography chooses them randomly even without
    encryption. Derive them from the public key to avoid spurious item updates.
    All private-key validation stays enabled in the loader.
    """
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    blob = base64.b64decode(b"".join(pem.splitlines()[1:-1]))
    offset = len(b"openssh-key-v1\0")
    # ciphername, kdfname and kdfoptions are length-prefixed strings.
    for _ in range(3):
        length = struct.unpack_from(">I", blob, offset)[0]
        offset += 4 + length
    offset += 4  # number of keys (the serializer emits one)
    length = struct.unpack_from(">I", blob, offset)[0]
    offset += 4 + length  # public-key string
    offset += 4  # private-block length
    check = hashlib.sha256(public_blob).digest()[:4]
    blob = blob[:offset] + check * 2 + blob[offset + 8 :]
    encoded = "\n".join(wrap(base64.b64encode(blob).decode("ascii"), 70))
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{encoded}\n-----END OPENSSH PRIVATE KEY-----\n"


def convert_ssh_key(
    private_key: str,
    *,
    public_key: str | None = None,
    fingerprint: str | None = None,
) -> SshConversion:
    """Derive native fields, or report a lossless fallback without a secret error."""
    try:
        encoded = private_key.strip().encode("utf-8")
        if encoded.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
            key = serialization.load_ssh_private_key(encoded, password=None)
        else:
            key = serialization.load_pem_private_key(encoded, password=None)
    except TypeError:
        return SshConversion(
            None, "Encrypted SSH private key retained in its source representation"
        )
    except ValueError, UnsupportedAlgorithm:
        return SshConversion(
            None,
            "Malformed or unsupported SSH private key retained in its source representation",
        )
    if not isinstance(key, ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey):
        return SshConversion(
            None,
            "SSH key algorithm is not supported by the Bitwarden agent; source retained",
        )
    derived = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    public_blob = base64.b64decode(derived.split()[1], validate=True)
    derived_fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(public_blob).digest()
    ).decode("ascii").rstrip("=")
    if public_key:
        try:
            supplied = public_key.strip().encode("utf-8")
            public = (
                serialization.load_pem_public_key(supplied)
                if supplied.startswith(b"-----BEGIN")
                else serialization.load_ssh_public_key(supplied)
            )
            normalized = public.public_bytes(
                serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
            )
        except ValueError, TypeError, UnsupportedAlgorithm:
            return SshConversion(
                None, "Malformed or unsupported SSH public key; source retained"
            )
        if normalized != derived:
            return SshConversion(
                None, "SSH public key does not match the private key; source retained"
            )
    if fingerprint and fingerprint.strip().rstrip("=") != derived_fingerprint:
        return SshConversion(
            None, "SSH fingerprint does not match the private key; source retained"
        )
    return SshConversion(
        BwSshKey(
            privateKey=_openssh_private(key, public_blob),
            publicKey=derived.decode("ascii"),
            keyFingerprint=derived_fingerprint,
        )
    )
