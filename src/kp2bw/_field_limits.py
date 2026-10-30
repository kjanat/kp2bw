"""Conservative budgets for Bitwarden structured-field encryption.

The serve API does not expose the effective cipher encryption format. Apply
legacy EncString type 2 budgets to both personal and organization targets;
never infer blob encryption support from a CLI/server version.

Limits follow Bitwarden's CipherRequestModel, CipherFieldModel and
CipherLoginModel EncryptedStringLength attributes. Reference:
https://github.com/bitwarden/server/tree/cb98b7e81c83145a2ea02d121ecb4da81d3611b1/src/Api/Vault/Models
"""

from .bw_types import BwItemCreate
from .exceptions import ConversionError

NAME_LIMIT = 1000
FIELD_VALUE_LIMIT = 5000
PASSWORD_LIMIT = 5000
NOTES_LIMIT = 10000
URI_LIMIT = 10000
TOTP_LIMIT = 1000


def encrypted_length(value: str) -> int:
    """Size of `2.<IV>|<AES-CBC ciphertext>|<HMAC>` after UTF-8 and PKCS#7."""
    padded_bytes = (len(value.encode("utf-8")) // 16 + 1) * 16
    return 2 + 24 + 1 + 4 * ((padded_bytes + 2) // 3) + 1 + 44


def fits_field(value: str | None, limit: int) -> bool:
    return value is None or encrypted_length(value) <= limit


def require_field(value: str | None, limit: int, label: str) -> None:
    if not fits_field(value, limit):
        raise ConversionError(
            f"{label} exceeds the destination's {limit}-character encrypted limit "
            "under conservative structured-field budgeting. Shorten the source "
            "value before migrating; it has not been truncated."
        )


def validate_item(item: BwItemCreate) -> None:
    """Check the final transformed item before any destination writes."""
    require_field(item["name"], NAME_LIMIT, "Item title")
    require_field(item["notes"], NOTES_LIMIT, "Item notes")
    for field in item["fields"]:
        require_field(field["name"], NAME_LIMIT, "Custom field name")
        require_field(field["value"], FIELD_VALUE_LIMIT, "Custom field value")
    login = item["login"]
    require_field(login["username"], NAME_LIMIT, "Login username")
    require_field(login["password"], PASSWORD_LIMIT, "Login password")
    require_field(login["totp"], TOTP_LIMIT, "Login TOTP")
    for uri in login["uris"]:
        require_field(uri["uri"], URI_LIMIT, "Login URI")
