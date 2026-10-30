"""Real SSH keys validate and keep a stable native representation."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from kp2bw._ssh_keys import convert_ssh_key


def main() -> None:
    for key in (
        ed25519.Ed25519PrivateKey.generate(),
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
    ):
        public = (
            key
            .public_key()
            .public_bytes(
                serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
            )
            .decode()
        )
        for fmt in (
            serialization.PrivateFormat.OpenSSH,
            serialization.PrivateFormat.PKCS8,
        ):
            source = key.private_bytes(
                serialization.Encoding.PEM, fmt, serialization.NoEncryption()
            ).decode()
            converted = convert_ssh_key(
                source, public_key=public + " synthetic@example.test"
            )
            assert converted.reason is None and converted.key is not None
            assert converted.key["publicKey"] == public
            reread = serialization.load_ssh_private_key(
                converted.key["privateKey"].encode(), None
            )
            assert (
                reread
                .public_key()
                .public_bytes(
                    serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
                )
                .decode()
                == public
            )
            assert convert_ssh_key(source).key == converted.key, (
                "Unchanged key must not generate a new item revision"
            )
            assert (
                convert_ssh_key(source, fingerprint=converted.key["keyFingerprint"]).key
                == converted.key
            )
            assert convert_ssh_key(source, fingerprint="SHA256:wrong").key is None
            other = (
                ed25519.Ed25519PrivateKey
                .generate()
                .public_key()
                .public_bytes(
                    serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
                )
                .decode()
            )
            assert convert_ssh_key(source, public_key=other).key is None
        encrypted = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"synthetic-passphrase"),
        ).decode()
        failure = convert_ssh_key(encrypted)
        assert failure.key is None and failure.reason and "Encrypted" in failure.reason
        assert (
            "synthetic-passphrase" not in failure.reason
            and "BEGIN" not in failure.reason
        )
    unsupported = (
        ec
        .generate_private_key(ec.SECP256R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    assert convert_ssh_key(unsupported).key is None
    for malformed in (
        "",
        "secret malformed private key",
        "-----BEGIN OPENSSH PRIVATE KEY-----\ninvalid\n-----END OPENSSH PRIVATE KEY-----",
    ):
        failure = convert_ssh_key(malformed)
        assert failure.key is None and failure.reason and "secret" not in failure.reason
    print("SSH key conversion tests passed")


if __name__ == "__main__":
    main()
