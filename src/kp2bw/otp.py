"""KeePass OTP (TOTP/HOTP) → Bitwarden ``login.totp`` resolution.

KeePass 2 and KeePassXC store one-time-password configuration in custom string
fields, documented at https://keepass.info/help/base/placeholders.html#otp.
Bitwarden's ``login.totp`` accepts a bare Base32 secret (interpreted as
6 digits / 30 s / SHA-1) or a full ``otpauth://`` URI.

This module resolves the KeePass fields into the lossless Bitwarden form:

* The common case — a Base32 secret with default settings — passes through as
  the bare secret (what users expect to see in Bitwarden).
* A non-default digit count / period / algorithm, or a secret stored in one of
  the other three encodings (UTF-8 / Hex / Base64), is emitted as an
  ``otpauth://`` URI so Bitwarden generates *correct* codes rather than
  defaulting silently to 6/30/SHA-1.
* HMAC-based OTP (HOTP) has no time-based target in Bitwarden, so its secret is
  preserved as a hidden custom field and the caller is warned.
* Any OTP secret that cannot be migrated (HOTP, an undecodable value, or a
  ``TimeOtp`` secret shadowed by an existing ``otp`` URI) is kept as a *hidden*
  custom field rather than silently dropped.

The module is deliberately free of ``pykeepass`` and ``logging`` dependencies:
it takes plain strings and returns a record (warnings included as *messages*),
so it is unit-testable in isolation and the caller owns all I/O and logging.
"""

import base64
import binascii
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import quote, urlencode

# ---------------------------------------------------------------------------
# KeePass OTP custom-field keys — https://keepass.info/help/base/placeholders.html#otp
#
# Casing is load-bearing and matched exactly: KeePass uses "TimeOtp" and "Hmac"
# (lowercase "mac"), not "HMAC".  Exactly one secret-encoding field is present
# per family; a reader must detect whichever exists.
# ---------------------------------------------------------------------------

KP_TOTP_SECRET_UTF8_KEY: str = "TimeOtp-Secret"
KP_TOTP_SECRET_HEX_KEY: str = "TimeOtp-Secret-Hex"
KP_TOTP_SECRET_BASE32_KEY: str = "TimeOtp-Secret-Base32"
KP_TOTP_SECRET_BASE64_KEY: str = "TimeOtp-Secret-Base64"

KP_TOTP_LENGTH_KEY: str = "TimeOtp-Length"
KP_TOTP_PERIOD_KEY: str = "TimeOtp-Period"
KP_TOTP_ALGORITHM_KEY: str = "TimeOtp-Algorithm"

KP_HOTP_SECRET_UTF8_KEY: str = "HmacOtp-Secret"
KP_HOTP_SECRET_HEX_KEY: str = "HmacOtp-Secret-Hex"
KP_HOTP_SECRET_BASE32_KEY: str = "HmacOtp-Secret-Base32"
KP_HOTP_SECRET_BASE64_KEY: str = "HmacOtp-Secret-Base64"
KP_HOTP_COUNTER_KEY: str = "HmacOtp-Counter"

# Bitwarden / otpauth defaults (sdk-internal crates/bitwarden-vault/src/totp.rs).
DEFAULT_DIGITS: int = 6
DEFAULT_PERIOD: int = 30
DEFAULT_ALGORITHM: str = "SHA1"
# KeePass spec: default 6, maximum 8 digits.
MIN_SPEC_DIGITS: int = 6
MAX_SPEC_DIGITS: int = 8

# KeePass "HMAC-SHA-*" → the otpauth token Bitwarden matches (case-insensitively
# against bare "sha1"/"sha256"/"sha512"; a dashed/prefixed value would silently
# fall back to SHA-1 and generate wrong codes).
_ALGORITHM_MAP: dict[str, str] = {
    "HMAC-SHA-1": "SHA1",
    "HMAC-SHA-256": "SHA256",
    "HMAC-SHA-512": "SHA512",
}


def _decode_utf8(value: str) -> bytes:
    """Bare ``TimeOtp-Secret``/``HmacOtp-Secret``: the UTF-8 bytes *are* the key."""
    return value.encode("utf-8")


def _decode_hex(value: str) -> bytes:
    """Decode a hex secret, tolerating common ``:``/``-``/space group separators."""
    cleaned = "".join(value.split()).replace("-", "").replace(":", "")
    return bytes.fromhex(cleaned)


def _decode_base32(value: str) -> bytes:
    """Decode a Base32 secret, tolerating lowercase, spaces and any padding state.

    Existing ``=`` padding is stripped before re-padding to a multiple of 8, so
    unpadded, correctly-padded and over-padded inputs all decode.
    """
    cleaned = "".join(value.split()).replace("-", "").upper().rstrip("=")
    cleaned += "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned)


def _decode_base64(value: str) -> bytes:
    """Decode a standard Base64 secret, tolerating whitespace and missing padding."""
    cleaned = "".join(value.split())
    cleaned += "=" * (-len(cleaned) % 4)
    return base64.b64decode(cleaned, validate=True)


# Secret key → decoder, in detection-priority order (Base32 is by far the most
# common).  Only one is normally present; the order only disambiguates a
# malformed entry that carries several.
_TOTP_SECRET_DECODERS: tuple[tuple[str, Callable[[str], bytes]], ...] = (
    (KP_TOTP_SECRET_BASE32_KEY, _decode_base32),
    (KP_TOTP_SECRET_HEX_KEY, _decode_hex),
    (KP_TOTP_SECRET_BASE64_KEY, _decode_base64),
    (KP_TOTP_SECRET_UTF8_KEY, _decode_utf8),
)
_TOTP_SECRET_DECODER_BY_KEY: dict[str, Callable[[str], bytes]] = dict(
    _TOTP_SECRET_DECODERS
)

_TOTP_CONFIG_KEYS: frozenset[str] = frozenset({
    KP_TOTP_LENGTH_KEY,
    KP_TOTP_PERIOD_KEY,
    KP_TOTP_ALGORITHM_KEY,
})

_HOTP_SECRET_KEYS: frozenset[str] = frozenset({
    KP_HOTP_SECRET_UTF8_KEY,
    KP_HOTP_SECRET_HEX_KEY,
    KP_HOTP_SECRET_BASE32_KEY,
    KP_HOTP_SECRET_BASE64_KEY,
})

# Every OTP *secret* field (TOTP + HOTP).  Any of these that is not consumed
# into ``login.totp`` is sensitive and must be stored as a hidden custom field.
_ALL_SECRET_KEYS: frozenset[str] = (
    frozenset(_TOTP_SECRET_DECODER_BY_KEY) | _HOTP_SECRET_KEYS
)


@dataclass(frozen=True)
class _TotpConfig:
    """Resolved TOTP parameters, already mapped to otpauth tokens."""

    digits: int
    period: int
    algorithm: str  # otpauth token: "SHA1" / "SHA256" / "SHA512"

    @property
    def is_default(self) -> bool:
        """Whether these match Bitwarden's bare-secret defaults (6 / 30 / SHA1)."""
        return (
            self.digits == DEFAULT_DIGITS
            and self.period == DEFAULT_PERIOD
            and self.algorithm == DEFAULT_ALGORITHM
        )


@dataclass(frozen=True)
class OtpMigration:
    """Outcome of resolving an entry's OTP fields for Bitwarden.

    ``totp`` is the value for ``login.totp`` — a bare Base32 secret or an
    ``otpauth://`` URI — or ``None`` when the entry has no migratable TOTP.

    ``consumed_keys`` are custom-property keys folded into ``totp``; the caller
    must drop them from the item's custom fields to avoid duplication/leak.

    ``hidden_keys`` are OTP secret keys that remain as custom fields and must be
    stored hidden (field type 1) because they are sensitive but could not be
    migrated.

    ``warnings`` are human-readable messages the caller should log (with entry
    context); the module performs no logging itself.
    """

    totp: str | None
    consumed_keys: frozenset[str]
    hidden_keys: frozenset[str]
    warnings: tuple[str, ...]


def _nonempty(props: Mapping[str, str | None], key: str) -> str | None:
    """Return the trimmed value for *key* if present and non-blank, else ``None``.

    ``custom_properties`` values can be ``None`` (an empty ``<Value/>`` element),
    so every read goes through this guard.
    """
    value = props.get(key)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _present_secret_keys(
    props: Mapping[str, str | None], candidates: frozenset[str]
) -> frozenset[str]:
    """Subset of *candidates* present in *props* with a non-blank value."""
    return frozenset(key for key in candidates if _nonempty(props, key) is not None)


def _find_totp_secret(props: Mapping[str, str | None]) -> tuple[str, str] | None:
    """Return ``(key, raw_value)`` for the present TimeOtp secret, or ``None``.

    The raw (un-stripped) value is returned so encoding-specific decoders decide
    their own cleaning — notably the UTF-8 secret, whose literal bytes are the key.
    """
    for key, _ in _TOTP_SECRET_DECODERS:
        value = props.get(key)
        if value is not None and value.strip() != "":
            return (key, value)
    return None


def _parse_int_field(
    raw: str, key: str, default: int, *, warnings: list[str]
) -> int | None:
    """Parse a positive integer config value, appending a warning on failure.

    Returns the parsed value, or ``None`` if it was invalid (caller uses *default*).
    """
    try:
        parsed = int(raw)
    except ValueError:
        warnings.append(f"Invalid {key} {raw!r}; using default {default}.")
        return None
    if parsed < 1:
        warnings.append(
            f"Invalid {key} {raw!r} (must be >= 1); using default {default}."
        )
        return None
    return parsed


def _parse_config(
    props: Mapping[str, str | None],
) -> tuple[_TotpConfig, list[str]]:
    """Resolve digit count, period and algorithm from the ``TimeOtp-*`` fields."""
    warnings: list[str] = []

    digits = DEFAULT_DIGITS
    raw_len = _nonempty(props, KP_TOTP_LENGTH_KEY)
    if raw_len is not None:
        parsed = _parse_int_field(
            raw_len, KP_TOTP_LENGTH_KEY, DEFAULT_DIGITS, warnings=warnings
        )
        if parsed is not None:
            if parsed > MAX_SPEC_DIGITS:
                warnings.append(
                    f"{KP_TOTP_LENGTH_KEY}={parsed} exceeds the KeePass maximum of "
                    f"{MAX_SPEC_DIGITS}; clamping to {MAX_SPEC_DIGITS}."
                )
                digits = MAX_SPEC_DIGITS
            else:
                if parsed < MIN_SPEC_DIGITS:
                    warnings.append(
                        f"{KP_TOTP_LENGTH_KEY}={parsed} is below the usual minimum of "
                        f"{MIN_SPEC_DIGITS}; passing through."
                    )
                digits = parsed

    period = DEFAULT_PERIOD
    raw_period = _nonempty(props, KP_TOTP_PERIOD_KEY)
    if raw_period is not None:
        parsed = _parse_int_field(
            raw_period, KP_TOTP_PERIOD_KEY, DEFAULT_PERIOD, warnings=warnings
        )
        if parsed is not None:
            period = parsed

    algorithm = DEFAULT_ALGORITHM
    raw_alg = _nonempty(props, KP_TOTP_ALGORITHM_KEY)
    if raw_alg is not None:
        mapped = _ALGORITHM_MAP.get(raw_alg.upper())
        if mapped is None:
            warnings.append(
                f"Unknown {KP_TOTP_ALGORITHM_KEY} {raw_alg!r}; using {DEFAULT_ALGORITHM}."
            )
        else:
            algorithm = mapped

    return _TotpConfig(digits=digits, period=period, algorithm=algorithm), warnings


def _build_otpauth_uri(raw_secret: bytes, config: _TotpConfig, *, label: str) -> str:
    """Build an ``otpauth://totp/`` URI Bitwarden parses losslessly.

    The secret is unpadded uppercase Base32 (per the Key URI Format); the label
    is percent-encoded; ``algorithm``/``digits``/``period`` are emitted
    explicitly so the value is fully self-describing.
    """
    secret_b32 = base64.b32encode(raw_secret).rstrip(b"=").decode("ascii")
    safe_label = quote(label, safe="") or "kp2bw"
    params = urlencode({
        "secret": secret_b32,
        "algorithm": config.algorithm,
        "digits": config.digits,
        "period": config.period,
    })
    return f"otpauth://totp/{safe_label}?{params}"


def resolve_otp(
    otp_uri: str | None,
    custom_properties: Mapping[str, str | None],
    *,
    entry_label: str,
) -> OtpMigration:
    """Resolve an entry's OTP fields into a Bitwarden ``login.totp`` value.

    *otp_uri* is ``entry.otp`` (the KeePassXC ``otp`` field, already an
    ``otpauth://`` URI when set).  *custom_properties* is ``entry.custom_properties``
    (raw ``TimeOtp-*`` / ``HmacOtp-*`` strings).  *entry_label* labels any
    generated ``otpauth://`` URI.
    """
    warnings: list[str] = []

    # A blank/whitespace-only otp field counts as absent (mirroring _nonempty),
    # so the TimeOtp-* fallback can still fire and we never emit a whitespace
    # login.totp; a real URI is trimmed of surrounding whitespace.
    otp_value = otp_uri.strip() if otp_uri else None

    # HOTP (RFC 4226) is counter-based and has no time-based target in Bitwarden.
    if _present_secret_keys(custom_properties, _HOTP_SECRET_KEYS):
        warnings.append(
            "HMAC-based OTP (HOTP) cannot be migrated to Bitwarden's time-based "
            "TOTP; its secret is kept as a hidden custom field."
        )

    # entry.otp (a full otpauth:// URI for KeePassXC) is already lossless and
    # wins outright; the TimeOtp-* fields are NOT consumed in that case.
    if otp_value:
        return OtpMigration(
            totp=otp_value,
            consumed_keys=frozenset(),
            hidden_keys=_present_secret_keys(custom_properties, _ALL_SECRET_KEYS),
            warnings=tuple(warnings),
        )

    found = _find_totp_secret(custom_properties)
    if found is None:
        return OtpMigration(
            totp=None,
            consumed_keys=frozenset(),
            hidden_keys=_present_secret_keys(custom_properties, _ALL_SECRET_KEYS),
            warnings=tuple(warnings),
        )

    secret_key, raw_value = found
    try:
        raw_bytes = _TOTP_SECRET_DECODER_BY_KEY[secret_key](raw_value)
    except ValueError, binascii.Error:
        warnings.append(
            f"Could not decode TOTP secret field {secret_key!r}; "
            "kept as a hidden custom field."
        )
        return OtpMigration(
            totp=None,
            consumed_keys=frozenset(),
            hidden_keys=_present_secret_keys(custom_properties, _ALL_SECRET_KEYS),
            warnings=tuple(warnings),
        )

    config, config_warnings = _parse_config(custom_properties)
    warnings.extend(config_warnings)

    present_config_keys = frozenset(
        key
        for key in _TOTP_CONFIG_KEYS
        if _nonempty(custom_properties, key) is not None
    )
    consumed = present_config_keys | {secret_key}

    if config.is_default and secret_key == KP_TOTP_SECRET_BASE32_KEY:
        # A default-config Base32 secret round-trips through Bitwarden's bare
        # form, which is friendlier than an opaque otpauth:// URI.  Emit the
        # canonical (uppercase, unpadded) encoding of the validated bytes so the
        # value never carries stray case/whitespace nor depends on Bitwarden's
        # lenient decoding.
        totp = base64.b32encode(raw_bytes).rstrip(b"=").decode("ascii")
    else:
        totp = _build_otpauth_uri(raw_bytes, config, label=entry_label)

    hidden = _present_secret_keys(custom_properties, _ALL_SECRET_KEYS) - consumed
    return OtpMigration(
        totp=totp,
        consumed_keys=frozenset(consumed),
        hidden_keys=hidden,
        warnings=tuple(warnings),
    )
