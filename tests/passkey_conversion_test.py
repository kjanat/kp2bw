"""Regression checks for KeePassXC-to-Bitwarden passkey conversion."""

from types import SimpleNamespace
from typing import cast

from pykeepass import Entry

from kp2bw.convert import Converter


def _converter() -> Converter:
    """Build a converter that never connects to a live vault."""
    return Converter(
        keepass_file_path="dummy.kdbx",
        keepass_password="pw",
        keepass_keyfile_path=None,
        bitwarden_password="pw",
        bitwarden_organization_id=None,
        bitwarden_coll_id=None,
        path2name=False,
        path2nameskip=1,
        import_tags=None,
    )


def _credential_id(converted_id: str) -> str:
    """Convert a representative passkey and return its Bitwarden ID."""
    entry = cast(
        Entry,
        SimpleNamespace(title="Passkey", username="alice", ctime=None),
    )
    credentials = _converter()._build_fido2_credentials(
        entry,
        {
            "KPEX_PASSKEY_CREDENTIAL_ID": converted_id,
            "KPEX_PASSKEY_PRIVATE_KEY_PEM": (
                "-----BEGIN PRIVATE KEY-----\nAAE=\n-----END PRIVATE KEY-----"
            ),
            "KPEX_PASSKEY_RELYING_PARTY": "example.com",
            "KPEX_PASSKEY_USER_HANDLE": "dXNlci1oYW5kbGU",
            "KPEX_PASSKEY_USERNAME": "alice",
        },
    )
    if credentials is None:
        raise AssertionError("passkey conversion unexpectedly returned no credential")
    return credentials[0]["credentialId"]


def assert_base64url_credential_id_uses_bitwarden_marker() -> None:
    """A KeePassXC byte-string ID must not be parsed as a Bitwarden UUID."""
    source_id = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    if _credential_id(source_id) != f"b64.{source_id}":
        raise AssertionError(
            "base64url credential ID is missing Bitwarden's b64 marker"
        )


def assert_existing_bitwarden_marker_is_preserved() -> None:
    """Defensively avoid adding the marker twice."""
    source_id = "b64.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    if _credential_id(source_id) != source_id:
        raise AssertionError("existing Bitwarden b64 marker was duplicated")


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_base64url_credential_id_uses_bitwarden_marker()
    assert_existing_bitwarden_marker_is_preserved()


if __name__ == "__main__":
    main()
