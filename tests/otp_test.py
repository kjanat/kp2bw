"""Unit tests for ``kp2bw.otp.resolve_otp`` (KeePass OTP → Bitwarden totp).

Script-style like the other tests: ``assert_*`` helpers raising ``AssertionError``
plus a ``main()``.  Pure logic, no pykeepass/network, so it runs by default via
``tests/test_script_adapters.py``.
"""

import base64
from collections.abc import Mapping
from urllib.parse import parse_qs, urlsplit

from kp2bw.otp import (
    KP_HOTP_SECRET_BASE32_KEY,
    KP_TOTP_ALGORITHM_KEY,
    KP_TOTP_LENGTH_KEY,
    KP_TOTP_PERIOD_KEY,
    KP_TOTP_SECRET_BASE32_KEY,
    KP_TOTP_SECRET_BASE64_KEY,
    KP_TOTP_SECRET_HEX_KEY,
    KP_TOTP_SECRET_UTF8_KEY,
    resolve_otp,
)

# A fixed 10-byte secret with an externally verified Base32 form (Google
# Authenticator KeyUriFormat example vector).
_RAW = b"Hello!\xde\xad\xbe\xef"
_B32 = "JBSWY3DPEHPK3PXP"


def _decode_b32(secret: str) -> bytes:
    padded = secret.upper() + "=" * (-len(secret) % 8)
    return base64.b32decode(padded)


def _otpauth_params(uri: str) -> dict[str, str]:
    parts = urlsplit(uri)
    if parts.scheme != "otpauth" or parts.netloc != "totp":
        raise AssertionError(f"not a totp otpauth URI: {uri!r}")
    return {k: v[0] for k, v in parse_qs(parts.query).items()}


def assert_b32_anchor() -> None:
    """Sanity-check the test vector against the known Base32 encoding."""
    if base64.b32encode(_RAW).rstrip(b"=").decode() != _B32:
        raise AssertionError("test vector drift: _RAW does not encode to _B32")


def assert_fallback_base32_default() -> None:
    result = resolve_otp(None, {KP_TOTP_SECRET_BASE32_KEY: _B32}, entry_label="Acme")
    if result.totp != _B32:
        raise AssertionError(f"expected bare secret, got {result.totp!r}")
    if result.consumed_keys != frozenset({KP_TOTP_SECRET_BASE32_KEY}):
        raise AssertionError(f"unexpected consumed_keys: {result.consumed_keys}")
    if result.hidden_keys:
        raise AssertionError(f"expected no hidden keys, got {result.hidden_keys}")
    if result.warnings:
        raise AssertionError(f"expected no warnings, got {result.warnings}")


def assert_entry_otp_precedence() -> None:
    uri = "otpauth://totp/Acme:bob?secret=GEZDGNBVGY3TQOJQ&issuer=Acme"
    # A *different* TimeOtp secret also present: it must not be consumed, but it
    # is sensitive, so it must be preserved as a hidden field (not dropped).
    result = resolve_otp(uri, {KP_TOTP_SECRET_BASE32_KEY: _B32}, entry_label="Acme")
    if result.totp != uri:
        raise AssertionError(f"entry.otp must win, got {result.totp!r}")
    if result.consumed_keys:
        raise AssertionError(f"expected nothing consumed, got {result.consumed_keys}")
    if result.hidden_keys != frozenset({KP_TOTP_SECRET_BASE32_KEY}):
        raise AssertionError(
            f"shadowed secret must be hidden, got {result.hidden_keys}"
        )


def assert_no_otp() -> None:
    result = resolve_otp(None, {}, entry_label="x")
    if result.totp is not None or result.consumed_keys or result.hidden_keys:
        raise AssertionError(f"expected empty migration, got {result}")
    if result.warnings:
        raise AssertionError(f"expected no warnings, got {result.warnings}")


def assert_nondefault_config_builds_otpauth() -> None:
    props: Mapping[str, str | None] = {
        KP_TOTP_SECRET_BASE32_KEY: _B32,
        KP_TOTP_LENGTH_KEY: "8",
        KP_TOTP_PERIOD_KEY: "60",
        KP_TOTP_ALGORITHM_KEY: "HMAC-SHA-256",
    }
    result = resolve_otp(None, props, entry_label="Acme Corp")
    if result.totp is None or not result.totp.startswith("otpauth://totp/"):
        raise AssertionError(f"expected otpauth URI, got {result.totp!r}")
    params = _otpauth_params(result.totp)
    if _decode_b32(params["secret"]) != _RAW:
        raise AssertionError("otpauth secret does not round-trip to the raw key")
    if params.get("digits") != "8":
        raise AssertionError(f"expected digits=8, got {params.get('digits')}")
    if params.get("period") != "60":
        raise AssertionError(f"expected period=60, got {params.get('period')}")
    if params.get("algorithm") != "SHA256":
        raise AssertionError(
            f"algorithm must map HMAC-SHA-256 -> SHA256, got {params.get('algorithm')}"
        )
    if "=" in params["secret"]:
        raise AssertionError("otpauth secret must be unpadded Base32")
    expected = frozenset({
        KP_TOTP_SECRET_BASE32_KEY,
        KP_TOTP_LENGTH_KEY,
        KP_TOTP_PERIOD_KEY,
        KP_TOTP_ALGORITHM_KEY,
    })
    if result.consumed_keys != expected:
        raise AssertionError(f"unexpected consumed_keys: {result.consumed_keys}")
    if result.hidden_keys:
        raise AssertionError(f"expected no hidden keys, got {result.hidden_keys}")


def assert_default_config_keys_consumed() -> None:
    # Even when explicit config equals the defaults, the bare-secret path is used
    # and the redundant config keys are consumed (not left as custom fields).
    props: Mapping[str, str | None] = {
        KP_TOTP_SECRET_BASE32_KEY: _B32,
        KP_TOTP_LENGTH_KEY: "6",
        KP_TOTP_PERIOD_KEY: "30",
        KP_TOTP_ALGORITHM_KEY: "HMAC-SHA-1",
    }
    result = resolve_otp(None, props, entry_label="x")
    if result.totp != _B32:
        raise AssertionError(f"expected bare secret, got {result.totp!r}")
    if KP_TOTP_LENGTH_KEY not in result.consumed_keys:
        raise AssertionError(f"default config not consumed: {result.consumed_keys}")


def _assert_encoding_round_trips(key: str, encoded: str) -> None:
    result = resolve_otp(None, {key: encoded}, entry_label="x")
    if result.totp is None or not result.totp.startswith("otpauth://totp/"):
        raise AssertionError(f"{key}: expected otpauth URI, got {result.totp!r}")
    params = _otpauth_params(result.totp)
    if _decode_b32(params["secret"]) != _RAW:
        raise AssertionError(f"{key}: secret did not round-trip to raw key")
    if result.consumed_keys != frozenset({key}):
        raise AssertionError(f"{key}: unexpected consumed_keys {result.consumed_keys}")


def assert_hex_encoding() -> None:
    _assert_encoding_round_trips(KP_TOTP_SECRET_HEX_KEY, _RAW.hex())


def assert_base64_encoding() -> None:
    _assert_encoding_round_trips(
        KP_TOTP_SECRET_BASE64_KEY, base64.b64encode(_RAW).decode()
    )


def assert_utf8_encoding() -> None:
    text = "abcdefgh"
    result = resolve_otp(None, {KP_TOTP_SECRET_UTF8_KEY: text}, entry_label="x")
    if result.totp is None:
        raise AssertionError("expected otpauth URI for UTF-8 secret")
    params = _otpauth_params(result.totp)
    if _decode_b32(params["secret"]) != text.encode("utf-8"):
        raise AssertionError("UTF-8 secret bytes must be used verbatim as the key")


def assert_hotp_warned_not_dropped() -> None:
    props: Mapping[str, str | None] = {
        KP_HOTP_SECRET_BASE32_KEY: _B32,
        "HmacOtp-Counter": "5",
    }
    result = resolve_otp(None, props, entry_label="x")
    if result.totp is not None:
        raise AssertionError(f"HOTP must not produce a totp, got {result.totp!r}")
    if result.hidden_keys != frozenset({KP_HOTP_SECRET_BASE32_KEY}):
        raise AssertionError(f"HOTP secret must be hidden, got {result.hidden_keys}")
    if not any("HOTP" in w for w in result.warnings):
        raise AssertionError(f"expected HOTP warning, got {result.warnings}")
    if "HmacOtp-Counter" in result.hidden_keys:
        raise AssertionError("counter is not a secret and should not be hidden")


def assert_hotp_alongside_totp() -> None:
    props: Mapping[str, str | None] = {
        KP_TOTP_SECRET_BASE32_KEY: _B32,
        KP_HOTP_SECRET_BASE32_KEY: "GEZDGNBVGY3TQOJQ",
    }
    result = resolve_otp(None, props, entry_label="x")
    if result.totp != _B32:
        raise AssertionError(f"TOTP must still migrate, got {result.totp!r}")
    if result.consumed_keys != frozenset({KP_TOTP_SECRET_BASE32_KEY}):
        raise AssertionError(f"unexpected consumed_keys: {result.consumed_keys}")
    if result.hidden_keys != frozenset({KP_HOTP_SECRET_BASE32_KEY}):
        raise AssertionError(f"HOTP secret must be hidden, got {result.hidden_keys}")


def assert_undecodable_secret_preserved() -> None:
    # 'zz' is not valid hex.
    result = resolve_otp(None, {KP_TOTP_SECRET_HEX_KEY: "zz"}, entry_label="x")
    if result.totp is not None:
        raise AssertionError(
            f"undecodable secret must not migrate, got {result.totp!r}"
        )
    if result.consumed_keys:
        raise AssertionError(f"nothing should be consumed, got {result.consumed_keys}")
    if result.hidden_keys != frozenset({KP_TOTP_SECRET_HEX_KEY}):
        raise AssertionError(f"bad secret must be hidden, got {result.hidden_keys}")
    if not any("decode" in w.lower() for w in result.warnings):
        raise AssertionError(f"expected a decode warning, got {result.warnings}")


def assert_empty_decoded_secret_preserved() -> None:
    # Values that decode to zero bytes without raising (only separators) must be
    # treated as decode failures: not migrated, kept hidden, warned.
    for key, value in (
        (KP_TOTP_SECRET_HEX_KEY, "---"),
        (KP_TOTP_SECRET_BASE32_KEY, "===="),
    ):
        result = resolve_otp(None, {key: value}, entry_label="x")
        if result.totp is not None:
            raise AssertionError(
                f"{key}={value!r} decodes to empty; must not migrate, got {result.totp!r}"
            )
        if result.consumed_keys:
            raise AssertionError(
                f"nothing should be consumed, got {result.consumed_keys}"
            )
        if result.hidden_keys != frozenset({key}):
            raise AssertionError(
                f"empty secret must be hidden, got {result.hidden_keys}"
            )
        if not any("decode" in w.lower() for w in result.warnings):
            raise AssertionError(f"expected a decode warning, got {result.warnings}")


def assert_messy_base32_nondefault() -> None:
    # Lowercase + spaces + non-default period must still decode correctly.
    props: Mapping[str, str | None] = {
        KP_TOTP_SECRET_BASE32_KEY: "jbsw y3dp ehpk 3pxp",
        KP_TOTP_PERIOD_KEY: "15",
    }
    result = resolve_otp(None, props, entry_label="x")
    if result.totp is None:
        raise AssertionError("expected otpauth URI")
    params = _otpauth_params(result.totp)
    if _decode_b32(params["secret"]) != _RAW:
        raise AssertionError("messy Base32 secret did not decode correctly")
    if params.get("period") != "15":
        raise AssertionError(f"expected period=15, got {params.get('period')}")


def assert_none_value_is_absent() -> None:
    # An empty <Value/> surfaces as None and must be treated as absent.
    result = resolve_otp(None, {KP_TOTP_SECRET_BASE32_KEY: None}, entry_label="x")
    if result.totp is not None or result.consumed_keys or result.hidden_keys:
        raise AssertionError(f"None-valued secret must be ignored, got {result}")


def assert_unknown_algorithm_defaults_with_warning() -> None:
    props: Mapping[str, str | None] = {
        KP_TOTP_SECRET_HEX_KEY: _RAW.hex(),
        KP_TOTP_ALGORITHM_KEY: "HMAC-MD5",
    }
    result = resolve_otp(None, props, entry_label="x")
    if result.totp is None:
        raise AssertionError("expected otpauth URI")
    params = _otpauth_params(result.totp)
    if params.get("algorithm") != "SHA1":
        raise AssertionError(f"unknown algorithm must default to SHA1, got {params}")
    if not any("algorithm" in w.lower() for w in result.warnings):
        raise AssertionError(f"expected an algorithm warning, got {result.warnings}")


def assert_oversized_digits_clamped() -> None:
    props: Mapping[str, str | None] = {
        KP_TOTP_SECRET_HEX_KEY: _RAW.hex(),
        KP_TOTP_LENGTH_KEY: "12",
    }
    result = resolve_otp(None, props, entry_label="x")
    if result.totp is None:
        raise AssertionError("expected otpauth URI")
    params = _otpauth_params(result.totp)
    if params.get("digits") != "8":
        raise AssertionError(f"digits >8 must clamp to 8, got {params.get('digits')}")
    if not any(
        "clamp" in w.lower() and "maximum" in w.lower() and "12" in w
        for w in result.warnings
    ):
        raise AssertionError(
            f"expected a clamp-to-maximum warning, got {result.warnings}"
        )


def assert_blank_otp_falls_back() -> None:
    # The PR's literal subject: "when entry.otp is empty".  A blank or
    # whitespace-only otp field must not shadow the TimeOtp fallback.
    for blank in ("", "   ", "\t\n"):
        result = resolve_otp(blank, {KP_TOTP_SECRET_BASE32_KEY: _B32}, entry_label="x")
        if result.totp != _B32:
            raise AssertionError(
                f"blank otp {blank!r} must fall back to the secret, got {result.totp!r}"
            )
        if result.consumed_keys != frozenset({KP_TOTP_SECRET_BASE32_KEY}):
            raise AssertionError(f"unexpected consumed_keys: {result.consumed_keys}")
        if result.hidden_keys:
            raise AssertionError(
                f"secret must be migrated, not hidden: {result.hidden_keys}"
            )


def assert_whitespace_wrapped_otp_trimmed() -> None:
    uri = "otpauth://totp/Acme:bob?secret=GEZDGNBVGY3TQOJQ"
    result = resolve_otp(f"  {uri}  ", {}, entry_label="x")
    if result.totp != uri:
        raise AssertionError(
            f"surrounding whitespace must be trimmed, got {result.totp!r}"
        )


def assert_bare_base32_canonical() -> None:
    # A default-config Base32 secret with messy case/whitespace must be emitted
    # in canonical (uppercase, unpadded, no-space) form, not verbatim.
    result = resolve_otp(
        None, {KP_TOTP_SECRET_BASE32_KEY: "jbsw\ty3dp ehpk3pxp"}, entry_label="x"
    )
    if result.totp != _B32:
        raise AssertionError(f"expected canonical {_B32!r}, got {result.totp!r}")


def assert_padded_base32_decodes() -> None:
    # A correctly-padded Base32 secret (2-byte secret -> 6 '=') must round-trip.
    raw = b"\xde\xad"
    padded = base64.b32encode(raw).decode()  # "3WWQ===="
    if "=" not in padded:
        raise AssertionError("test vector should be padded")
    result = resolve_otp(
        None,
        {KP_TOTP_SECRET_BASE32_KEY: padded, KP_TOTP_PERIOD_KEY: "45"},
        entry_label="x",
    )
    if result.totp is None:
        raise AssertionError("padded Base32 secret must decode, not be dropped")
    params = _otpauth_params(result.totp)
    if _decode_b32(params["secret"]) != raw:
        raise AssertionError("padded Base32 secret did not round-trip")


def assert_sha512_maps() -> None:
    props: Mapping[str, str | None] = {
        KP_TOTP_SECRET_HEX_KEY: _RAW.hex(),
        KP_TOTP_ALGORITHM_KEY: "HMAC-SHA-512",
    }
    result = resolve_otp(None, props, entry_label="x")
    if result.totp is None:
        raise AssertionError("expected otpauth URI")
    params = _otpauth_params(result.totp)
    if params.get("algorithm") != "SHA512":
        raise AssertionError(
            f"HMAC-SHA-512 must map to SHA512, got {params.get('algorithm')}"
        )


def assert_invalid_period_defaults() -> None:
    for bad in ("0", "abc"):
        props: Mapping[str, str | None] = {
            KP_TOTP_SECRET_HEX_KEY: _RAW.hex(),
            KP_TOTP_PERIOD_KEY: bad,
        }
        result = resolve_otp(None, props, entry_label="x")
        if result.totp is None:
            raise AssertionError("expected otpauth URI")
        params = _otpauth_params(result.totp)
        if params.get("period") != "30":
            raise AssertionError(
                f"invalid period {bad!r} must default to 30, got {params.get('period')}"
            )
        if not any(KP_TOTP_PERIOD_KEY in w for w in result.warnings):
            raise AssertionError(f"expected a period warning, got {result.warnings}")


def assert_below_min_length_passthrough() -> None:
    # Below the usual minimum is passed through (Bitwarden accepts >=1), distinct
    # from the oversize path which clamps.
    props: Mapping[str, str | None] = {
        KP_TOTP_SECRET_HEX_KEY: _RAW.hex(),
        KP_TOTP_LENGTH_KEY: "4",
    }
    result = resolve_otp(None, props, entry_label="x")
    if result.totp is None:
        raise AssertionError("expected otpauth URI")
    params = _otpauth_params(result.totp)
    if params.get("digits") != "4":
        raise AssertionError(
            f"below-min digits must pass through, got {params.get('digits')}"
        )
    if not any("minimum" in w.lower() for w in result.warnings):
        raise AssertionError(f"expected a below-minimum warning, got {result.warnings}")


def assert_entry_otp_precedence_with_hotp() -> None:
    # entry.otp wins AND a HOTP secret exists: URI migrates, HOTP warned + hidden.
    uri = "otpauth://totp/Acme:bob?secret=GEZDGNBVGY3TQOJQ"
    props: Mapping[str, str | None] = {
        KP_HOTP_SECRET_BASE32_KEY: _B32,
        "HmacOtp-Counter": "9",
    }
    result = resolve_otp(uri, props, entry_label="x")
    if result.totp != uri:
        raise AssertionError(f"entry.otp must still win, got {result.totp!r}")
    if result.hidden_keys != frozenset({KP_HOTP_SECRET_BASE32_KEY}):
        raise AssertionError(f"HOTP secret must be hidden, got {result.hidden_keys}")
    if not any("HOTP" in w for w in result.warnings):
        raise AssertionError(
            f"HOTP warning must fire even when otp wins: {result.warnings}"
        )


def assert_decoder_priority() -> None:
    # Malformed entry with two encodings: Base32 wins; the other is hidden.
    other = bytes.fromhex("0011223344")
    props: Mapping[str, str | None] = {
        KP_TOTP_SECRET_BASE32_KEY: _B32,
        KP_TOTP_SECRET_HEX_KEY: other.hex(),
    }
    result = resolve_otp(None, props, entry_label="x")
    if result.totp != _B32:
        raise AssertionError(f"Base32 must win priority, got {result.totp!r}")
    if KP_TOTP_SECRET_HEX_KEY not in result.hidden_keys:
        raise AssertionError(
            f"shadowed Hex secret must be hidden, got {result.hidden_keys}"
        )


def assert_label_encoded() -> None:
    result = resolve_otp(
        None,
        {KP_TOTP_SECRET_HEX_KEY: _RAW.hex(), KP_TOTP_PERIOD_KEY: "45"},
        entry_label="Acme: bob/work?x=1",
    )
    if result.totp is None:
        raise AssertionError("expected otpauth URI")
    path = result.totp[len("otpauth://totp/") :].split("?", 1)[0]
    for raw_char in (" ", "/", "?", ":"):
        if raw_char in path:
            raise AssertionError(
                f"label must be percent-encoded, raw {raw_char!r} in {path!r}"
            )


def assert_empty_label_fallback() -> None:
    result = resolve_otp(
        None,
        {KP_TOTP_SECRET_HEX_KEY: _RAW.hex(), KP_TOTP_PERIOD_KEY: "45"},
        entry_label="",
    )
    if result.totp is None:
        raise AssertionError("expected otpauth URI")
    path = result.totp[len("otpauth://totp/") :].split("?", 1)[0]
    if path != "kp2bw":
        raise AssertionError(f"empty label must fall back to 'kp2bw', got {path!r}")


def main() -> None:
    assert_b32_anchor()
    assert_fallback_base32_default()
    assert_entry_otp_precedence()
    assert_no_otp()
    assert_nondefault_config_builds_otpauth()
    assert_default_config_keys_consumed()
    assert_hex_encoding()
    assert_base64_encoding()
    assert_utf8_encoding()
    assert_hotp_warned_not_dropped()
    assert_hotp_alongside_totp()
    assert_undecodable_secret_preserved()
    assert_empty_decoded_secret_preserved()
    assert_messy_base32_nondefault()
    assert_none_value_is_absent()
    assert_unknown_algorithm_defaults_with_warning()
    assert_oversized_digits_clamped()
    assert_blank_otp_falls_back()
    assert_whitespace_wrapped_otp_trimmed()
    assert_bare_base32_canonical()
    assert_padded_base32_decodes()
    assert_sha512_maps()
    assert_invalid_period_defaults()
    assert_below_min_length_passthrough()
    assert_entry_otp_precedence_with_hotp()
    assert_decoder_priority()
    assert_label_encoded()
    assert_empty_label_fallback()
    print("otp resolution test passed")


if __name__ == "__main__":
    main()
