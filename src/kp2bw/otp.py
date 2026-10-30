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
* Any OTP secret that cannot be migrated (HOTP, an undecodable value, a
  ``TimeOtp`` secret shadowed by an existing ``otp`` URI, or a secret written
  under the field names of the scheme that is not active) is kept as a *hidden*
  custom field rather than silently dropped.

Pleasant Password Server exports the same configuration under its own names
(``TOTPSecret`` / ``TOTPDigits`` / ``TOTPPeriod``, secret always Base32 and
algorithm always SHA-1).  ``resolve_otp(..., totp_pps=True)`` reads those field
names in place of the KeePass ones.  Only the selected scheme is ever read for
migration, but a secret field belonging to the other one still counts as a
secret and is hidden; its digit-count/period/algorithm fields are not secret and
stay ordinary custom fields.

The module is deliberately free of ``pykeepass`` and ``logging`` dependencies:
it takes plain strings and returns a record (warnings included as *messages*),
so it is unit-testable in isolation and the caller owns all I/O and logging.
"""

import base64
import binascii
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import parse_qs, quote, urlencode, urlsplit

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

PPS_TOTP_SECRET_KEY: str = "TOTPSecret"
PPS_TOTP_DIGITS_KEY: str = "TOTPDigits"
PPS_TOTP_PERIOD_KEY: str = "TOTPPeriod"

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
ALGORITHM_MAP: dict[str, str] = {
    "HMAC-SHA-1": "SHA1",
    "HMAC-SHA-256": "SHA256",
    "HMAC-SHA-512": "SHA512",
}

OTPAUTH_ALGORITHM_MAP: dict[str, str] = {
    "SHA1": "SHA1",
    "SHA256": "SHA256",
    "SHA512": "SHA512",
}
OTPAUTH_CODE_PARAMETER_KEYS: frozenset[str] = frozenset({
    "secret",
    "algorithm",
    "digits",
    "period",
})


def decode_utf8(value: str) -> bytes:
    """Bare ``TimeOtp-Secret``/``HmacOtp-Secret``: the UTF-8 bytes *are* the key."""
    return value.encode("utf-8")


def decode_hex(value: str) -> bytes:
    """Decode a hex secret, tolerating common ``:``/``-``/space group separators."""
    cleaned = "".join(value.split()).replace("-", "").replace(":", "")
    return bytes.fromhex(cleaned)


def decode_base32(value: str) -> bytes:
    """Decode a Base32 secret, tolerating lowercase, spaces and any padding state.

    Existing ``=`` padding is stripped before re-padding to a multiple of 8, so
    unpadded, correctly-padded and over-padded inputs all decode.
    """
    cleaned = "".join(value.split()).replace("-", "").upper().rstrip("=")
    cleaned += "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned)


def decode_base64(value: str) -> bytes:
    """Decode a standard Base64 secret, tolerating whitespace and missing padding."""
    cleaned = "".join(value.split())
    cleaned += "=" * (-len(cleaned) % 4)
    return base64.b64decode(cleaned, validate=True)


@dataclass(frozen=True)
class TotpScheme:
    """One producer's TOTP custom-field naming, and how its secret is encoded.

    ``secret_decoders`` maps each secret key to its decoder in detection-priority
    order; only one key is normally present, and the order only disambiguates a
    malformed entry that carries several.  ``base32_key`` is the key whose value
    is Base32, the one encoding Bitwarden also accepts bare.  ``algorithm_key``
    is ``None`` for a producer that has no algorithm field, in which case
    :data:`DEFAULT_ALGORITHM` applies.
    """

    secret_decoders: tuple[tuple[str, Callable[[str], bytes]], ...]
    base32_key: str
    length_key: str
    period_key: str
    algorithm_key: str | None

    @property
    def secret_keys(self) -> frozenset[str]:
        """Every secret key this scheme reads."""
        return frozenset(key for key, _ in self.secret_decoders)

    @property
    def config_keys(self) -> frozenset[str]:
        """Every digit-count / period / algorithm key this scheme reads."""
        keys = {self.length_key, self.period_key}
        if self.algorithm_key is not None:
            keys.add(self.algorithm_key)
        return frozenset(keys)


KEEPASS_TOTP_SCHEME: TotpScheme = TotpScheme(
    secret_decoders=(
        (KP_TOTP_SECRET_BASE32_KEY, decode_base32),
        (KP_TOTP_SECRET_HEX_KEY, decode_hex),
        (KP_TOTP_SECRET_BASE64_KEY, decode_base64),
        (KP_TOTP_SECRET_UTF8_KEY, decode_utf8),
    ),
    base32_key=KP_TOTP_SECRET_BASE32_KEY,
    length_key=KP_TOTP_LENGTH_KEY,
    period_key=KP_TOTP_PERIOD_KEY,
    algorithm_key=KP_TOTP_ALGORITHM_KEY,
)

PPS_TOTP_SCHEME: TotpScheme = TotpScheme(
    secret_decoders=((PPS_TOTP_SECRET_KEY, decode_base32),),
    base32_key=PPS_TOTP_SECRET_KEY,
    length_key=PPS_TOTP_DIGITS_KEY,
    period_key=PPS_TOTP_PERIOD_KEY,
    algorithm_key=None,
)

HOTP_SECRET_KEYS: frozenset[str] = frozenset({
    KP_HOTP_SECRET_UTF8_KEY,
    KP_HOTP_SECRET_HEX_KEY,
    KP_HOTP_SECRET_BASE32_KEY,
    KP_HOTP_SECRET_BASE64_KEY,
})

# Every OTP *secret* field this module recognises: both TOTP schemes plus HOTP.
# Any of these that is not consumed into ``login.totp`` is sensitive and must be
# stored as a hidden custom field, whichever scheme is active.
ALL_SECRET_KEYS: frozenset[str] = (
    KEEPASS_TOTP_SCHEME.secret_keys | PPS_TOTP_SCHEME.secret_keys | HOTP_SECRET_KEYS
)


def is_otp_secret_field(name: str) -> bool:
    """Identify source secrets even when duplicate fields need escaped names."""
    return name in ALL_SECRET_KEYS


@dataclass(frozen=True)
class TotpConfig:
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


def otpauth_int_parameter(
    parameters: Mapping[str, str], key: str, default: int
) -> int | None:
    """Return one positive ASCII-decimal parameter, or ``None`` if malformed."""
    value = parameters.get(key)
    if value is None:
        return default
    if not value.isascii() or not value.isdecimal():
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed > 0 else None


def otpauth_code_parameters(query: str) -> dict[str, str] | None:
    """Return unambiguous lowercase parameters that affect generated codes."""
    parameters: dict[str, str] = {}
    for key, values in parse_qs(query, keep_blank_values=True).items():
        normalized_key = key.lower()
        if normalized_key not in OTPAUTH_CODE_PARAMETER_KEYS:
            continue
        if key != normalized_key or normalized_key in parameters or len(values) != 1:
            return None
        parameters[normalized_key] = values[0]
    return parameters


def totp_identity(value: str) -> tuple[bytes, TotpConfig] | None:
    """Parse the code-generating parts of a Bitwarden TOTP value."""
    stripped = value.strip()
    if stripped.lower().startswith("otpauth://"):
        try:
            parsed = urlsplit(stripped)
        except ValueError:
            return None
        if parsed.scheme.lower() != "otpauth" or parsed.netloc.lower() != "totp":
            return None

        parameters = otpauth_code_parameters(parsed.query)
        if parameters is None:
            return None
        raw_secret = parameters.get("secret")
        if raw_secret is None:
            return None
        raw_algorithm = parameters.get("algorithm", DEFAULT_ALGORITHM)
        algorithm = (
            OTPAUTH_ALGORITHM_MAP.get(raw_algorithm.upper())
            if raw_algorithm.isascii()
            else None
        )
        digits = otpauth_int_parameter(parameters, "digits", DEFAULT_DIGITS)
        period = otpauth_int_parameter(parameters, "period", DEFAULT_PERIOD)
        if algorithm is None or digits is None or period is None:
            return None
    else:
        raw_secret = stripped
        algorithm = DEFAULT_ALGORITHM
        digits = DEFAULT_DIGITS
        period = DEFAULT_PERIOD

    try:
        secret = decode_base32(raw_secret)
    except ValueError, binascii.Error:
        return None
    if not secret:
        return None
    return secret, TotpConfig(digits=digits, period=period, algorithm=algorithm)


def totp_values_equivalent(left: str, right: str) -> bool:
    """Whether two Bitwarden TOTP values generate the same codes.

    Labels, issuers, query ordering and Base32 presentation do not affect code
    generation. Malformed or unsupported values remain equivalent only by exact
    string equality.
    """
    if left == right:
        return True
    left_identity = totp_identity(left)
    return left_identity is not None and left_identity == totp_identity(right)


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


def nonempty(props: Mapping[str, str | None], key: str) -> str | None:
    """Return the trimmed value for *key* if present and non-blank, else ``None``.

    ``custom_properties`` values can be ``None`` (an empty ``<Value/>`` element),
    so every read goes through this guard.
    """
    value = props.get(key)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def present_secret_keys(
    props: Mapping[str, str | None], candidates: frozenset[str]
) -> frozenset[str]:
    """Subset of *candidates* present in *props* with a non-blank value."""
    return frozenset(key for key in candidates if nonempty(props, key) is not None)


def find_totp_secret(
    props: Mapping[str, str | None], scheme: TotpScheme
) -> tuple[str, str, Callable[[str], bytes]] | None:
    """Return ``(key, raw_value, decoder)`` for the present TOTP secret, or ``None``.

    The raw (un-stripped) value is returned so encoding-specific decoders decide
    their own cleaning — notably the UTF-8 secret, whose literal bytes are the key.
    """
    for key, decoder in scheme.secret_decoders:
        value = props.get(key)
        if value is not None and value.strip() != "":
            return (key, value, decoder)
    return None


def parse_int_field(
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


def parse_config(
    props: Mapping[str, str | None], scheme: TotpScheme
) -> tuple[TotpConfig, list[str]]:
    """Resolve digit count, period and algorithm from *scheme*'s config fields."""
    warnings: list[str] = []

    digits = DEFAULT_DIGITS
    raw_len = nonempty(props, scheme.length_key)
    if raw_len is not None:
        parsed = parse_int_field(
            raw_len, scheme.length_key, DEFAULT_DIGITS, warnings=warnings
        )
        if parsed is not None:
            if parsed > MAX_SPEC_DIGITS:
                warnings.append(
                    f"{scheme.length_key}={parsed} exceeds the maximum of "
                    f"{MAX_SPEC_DIGITS}; clamping to {MAX_SPEC_DIGITS}."
                )
                digits = MAX_SPEC_DIGITS
            else:
                if parsed < MIN_SPEC_DIGITS:
                    warnings.append(
                        f"{scheme.length_key}={parsed} is below the usual minimum of "
                        f"{MIN_SPEC_DIGITS}; passing through."
                    )
                digits = parsed

    period = DEFAULT_PERIOD
    raw_period = nonempty(props, scheme.period_key)
    if raw_period is not None:
        parsed = parse_int_field(
            raw_period, scheme.period_key, DEFAULT_PERIOD, warnings=warnings
        )
        if parsed is not None:
            period = parsed

    algorithm = DEFAULT_ALGORITHM
    raw_alg = (
        nonempty(props, scheme.algorithm_key)
        if scheme.algorithm_key is not None
        else None
    )
    if raw_alg is not None:
        mapped = ALGORITHM_MAP.get(raw_alg.upper())
        if mapped is None:
            warnings.append(
                f"Unknown {scheme.algorithm_key} {raw_alg!r}; using {DEFAULT_ALGORITHM}."
            )
        else:
            algorithm = mapped

    return TotpConfig(digits=digits, period=period, algorithm=algorithm), warnings


def build_otpauth_uri(raw_secret: bytes, config: TotpConfig, *, label: str) -> str:
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
    totp_pps: bool = False,
) -> OtpMigration:
    """Resolve an entry's OTP fields into a Bitwarden ``login.totp`` value.

    *otp_uri* is ``entry.otp`` (the KeePassXC ``otp`` field, already an
    ``otpauth://`` URI when set). *custom_properties* contains the entry's raw
    ``TimeOtp-*`` / ``HmacOtp-*`` strings. *entry_label* labels any
    generated ``otpauth://`` URI.

    *totp_pps* reads TOTP from Pleasant Password Server's ``TOTPSecret`` /
    ``TOTPDigits`` / ``TOTPPeriod`` fields instead of the KeePass ``TimeOtp-*``
    ones: the PPS secret is always Base32 and its algorithm is always SHA-1, so
    there is no algorithm field to read.  Only the selected scheme is read, so
    the other scheme's fields are never migrated; its *secret* field is still
    returned in ``hidden_keys``, while its digit-count/period/algorithm fields
    stay ordinary custom fields.  HOTP handling is unaffected.
    """
    scheme = PPS_TOTP_SCHEME if totp_pps else KEEPASS_TOTP_SCHEME
    warnings: list[str] = []

    # A blank/whitespace-only otp field counts as absent (mirroring nonempty),
    # so the TimeOtp-* fallback can still fire and we never emit a whitespace
    # login.totp; a real URI is trimmed of surrounding whitespace.
    otp_value = otp_uri.strip() if otp_uri else None

    # HOTP (RFC 4226) is counter-based and has no time-based target in Bitwarden.
    if present_secret_keys(custom_properties, HOTP_SECRET_KEYS):
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
            hidden_keys=present_secret_keys(custom_properties, ALL_SECRET_KEYS),
            warnings=tuple(warnings),
        )

    found = find_totp_secret(custom_properties, scheme)
    if found is None:
        return OtpMigration(
            totp=None,
            consumed_keys=frozenset(),
            hidden_keys=present_secret_keys(custom_properties, ALL_SECRET_KEYS),
            warnings=tuple(warnings),
        )

    secret_key, raw_value, decoder = found
    try:
        raw_bytes = decoder(raw_value)
    except ValueError, binascii.Error:
        warnings.append(
            f"Could not decode TOTP secret field {secret_key!r}; "
            "kept as a hidden custom field."
        )
        return OtpMigration(
            totp=None,
            consumed_keys=frozenset(),
            hidden_keys=present_secret_keys(custom_properties, ALL_SECRET_KEYS),
            warnings=tuple(warnings),
        )

    # A value that decodes to no bytes (e.g. a field of only separators) yields
    # no usable secret -- treat it as a decode failure rather than emitting an
    # empty otpauth secret or silently dropping the field.
    if not raw_bytes:
        warnings.append(
            f"Could not decode TOTP secret field {secret_key!r}; "
            "kept as a hidden custom field."
        )
        return OtpMigration(
            totp=None,
            consumed_keys=frozenset(),
            hidden_keys=present_secret_keys(custom_properties, ALL_SECRET_KEYS),
            warnings=tuple(warnings),
        )

    config, config_warnings = parse_config(custom_properties, scheme)
    warnings.extend(config_warnings)

    present_config_keys = frozenset(
        key
        for key in scheme.config_keys
        if nonempty(custom_properties, key) is not None
    )
    consumed = present_config_keys | {secret_key}

    if config.is_default and secret_key == scheme.base32_key:
        # A default-config Base32 secret round-trips through Bitwarden's bare
        # form, which is friendlier than an opaque otpauth:// URI.  Emit the
        # canonical (uppercase, unpadded) encoding of the validated bytes so the
        # value never carries stray case/whitespace nor depends on Bitwarden's
        # lenient decoding.
        totp = base64.b32encode(raw_bytes).rstrip(b"=").decode("ascii")
    else:
        totp = build_otpauth_uri(raw_bytes, config, label=entry_label)

    hidden = present_secret_keys(custom_properties, ALL_SECRET_KEYS) - consumed
    return OtpMigration(
        totp=totp,
        consumed_keys=frozenset(consumed),
        hidden_keys=hidden,
        warnings=tuple(warnings),
    )
