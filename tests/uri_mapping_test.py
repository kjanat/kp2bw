"""Checks the KeePass(XC) URL -> Bitwarden login-URI mapping (`uri_mapping`).

Covers the per-URI match table: plain strings -> base domain (the faithful
KeePassXC default), quoted -> exact, trailing-path wildcard -> starts-with,
host/interior wildcard -> regex, non-web schemes / references / garbage dropped,
AndroidApp -> androidapp://, de-duplication, and the two config knobs
(plain-tier match value, interpret-syntax on/off).
"""

from typing import cast

from kp2bw.bw_types import BwField, BwUri
from kp2bw.uri_mapping import (
    UriMatchValue,
    build_login_uris,
    collision_groups,
    is_url_attribute_key,
    parse_match_name,
    registrable_domain,
    remap_item_fields_to_uris,
    uri_host,
)


def _uris(
    *,
    primary_url: str,
    additional_urls: list[str],
    android_packages: list[str] | None = None,
    plain_match: UriMatchValue = None,
    interpret_syntax: bool = True,
) -> list[tuple[str, object]]:
    """Run build_login_uris and return [(uri, match)] for terse assertions."""
    result = build_login_uris(
        primary_url=primary_url,
        additional_urls=additional_urls,
        android_packages=android_packages or [],
        plain_match=plain_match,
        interpret_syntax=interpret_syntax,
    )
    return [(u["uri"], u.get("match")) for u in result]


def assert_match_names_parse() -> None:
    """Symbolic names resolve to Bitwarden values; unknown names raise."""
    expected = {
        "domain": 0,
        "host": 1,
        "startswith": 2,
        "exact": 3,
        "regex": 4,
        "never": 5,
        "default": None,
        "null": None,
    }
    for name, value in expected.items():
        if parse_match_name(name) != value:
            raise AssertionError(f"{name} -> {parse_match_name(name)}, want {value}")
    if parse_match_name("DOMAIN") != 0:
        raise AssertionError("match name should be case-insensitive")
    try:
        parse_match_name("nope")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown match name should raise ValueError")


def assert_url_attribute_keys() -> None:
    """URL-like (KP2A_URL*/URL*) and AndroidApp* keys are siphoned; others aren't."""
    for key in (
        "KP2A_URL",
        "KP2A_URL_1",
        "KP2A_URL_16",
        "URL",
        "URL_1",
        "AndroidApp",
        "AndroidApp_2",
        "AndroidApp1",  # no-underscore variant
    ):
        if not is_url_attribute_key(key):
            raise AssertionError(f"{key} should be a URL attribute")
    # Free-text labels and near-misses must stay as custom fields.
    for key in (
        "API Url",
        "Alt. URL",
        "Website",
        "KP2A_URLX",
        "Notes",
        "AndroidApplication",
    ):
        if is_url_attribute_key(key):
            raise AssertionError(f"{key} should NOT be a URL attribute")


def assert_plain_urls_default_to_account_default_and_dedup() -> None:
    """Plain primary + additional URLs default to match=None (account default), deduped."""
    got = _uris(
        primary_url="thuisbezorgd.nl",
        additional_urls=[
            "https://takeaway.com",
            "https://10bis.co.il",
            "thuisbezorgd.nl",
        ],
        android_packages=["com.takeaway.android"],
    )
    expected = [
        ("thuisbezorgd.nl", None),
        ("https://takeaway.com", None),
        ("https://10bis.co.il", None),
        ("androidapp://com.takeaway.android", None),
    ]
    if got != expected:
        raise AssertionError(f"got {got}, want {expected}")


def assert_uri_match_domain_forces_base_domain() -> None:
    """``plain_match=0`` forces base-domain on plain URLs (the KeePassXC-faithful opt-in)."""
    got = _uris(
        primary_url="example.com",
        additional_urls=["https://alt.example"],
        android_packages=[],
        plain_match=0,
    )
    expected = [("example.com", 0), ("https://alt.example", 0)]
    if got != expected:
        raise AssertionError(f"got {got}, want {expected}")


def assert_special_syntaxes_map_when_interpreting() -> None:
    """Quoted -> exact(3); trailing wildcard -> starts-with(2); host wildcard -> regex(4)."""
    got = dict(
        _uris(
            primary_url="",
            additional_urls=[
                '"https://exact.example/login"',
                "https://host.example/app/*",
                "https://*.wild.example/*",
            ],
            android_packages=[],
        )
    )
    if got.get("https://exact.example/login") != 3:
        raise AssertionError(f"quoted should be exact(3): {got}")
    if got.get("https://host.example/app/") != 2:
        raise AssertionError(f"trailing wildcard should be starts-with(2): {got}")
    regex_uris = [u for u, m in got.items() if m == 4]
    if not regex_uris or "wild" not in regex_uris[0]:
        raise AssertionError(f"host wildcard should be regex(4): {got}")


def assert_drops() -> None:
    """Non-web schemes, references, illegal chars, and invalid wildcards are dropped."""
    got = _uris(
        primary_url="",
        additional_urls=[
            "keepassxc://by-uuid/abc",
            "cmd://run",
            "kdbx://x",
            "file:///etc/hosts",
            "{REF:A@I:1234}",
            "https://has space<bad>",
            "https://**",
            "https://*.com",
        ],
        android_packages=[],
    )
    if got:
        raise AssertionError(f"all inputs should be dropped, got {got}")


def assert_literal_mode_skips_interpretation() -> None:
    """interpret_syntax=False keeps quote/wildcard strings as plain URIs verbatim."""
    got = _uris(
        primary_url="",
        additional_urls=['"https://x/login"', "https://host/*"],
        android_packages=[],
        interpret_syntax=False,
    )
    expected = [('"https://x/login"', None), ("https://host/*", None)]
    if got != expected:
        raise AssertionError(f"literal mode: got {got}, want {expected}")


def assert_plain_match_override() -> None:
    """plain_match tunes the plain tier (e.g. None defers to the account default)."""
    got = _uris(
        primary_url="example.com",
        additional_urls=['"https://x/login"'],
        android_packages=[],
        plain_match=None,
    )
    # Plain primary follows the override (None); the quoted form stays exact(3).
    if ("example.com", None) not in got:
        raise AssertionError(f"plain tier should use override None: {got}")
    if ("https://x/login", 3) not in got:
        raise AssertionError(f"quoted form should stay exact(3): {got}")


def assert_remap_lifts_legacy_fields() -> None:
    """remap_item_fields_to_uris drops KP2A_URL*/AndroidApp fields and adds URIs."""
    fields = [
        cast(BwField, {"name": "Notes", "value": "keep", "type": 0}),
        cast(BwField, {"name": "KP2A_URL", "value": "https://alt.example", "type": 0}),
        cast(BwField, {"name": "AndroidApp", "value": "com.example.app", "type": 0}),
    ]
    uris = [cast(BwUri, {"uri": "https://primary.example", "match": 0})]

    new_fields, new_uris, changed = remap_item_fields_to_uris(fields, uris)

    if not changed:
        raise AssertionError("expected changed=True")
    if [f["name"] for f in new_fields] != ["Notes"]:
        raise AssertionError(f"legacy fields not dropped: {new_fields}")
    new_values = [u["uri"] for u in new_uris]
    if new_values != [
        "https://primary.example",
        "https://alt.example",
        "androidapp://com.example.app",
    ]:
        raise AssertionError(f"unexpected merged uris: {new_values}")


def assert_remap_noop_without_legacy_fields() -> None:
    """An item without KP2A_URL*/AndroidApp fields is reported unchanged."""
    fields = [cast(BwField, {"name": "Notes", "value": "keep", "type": 0})]
    uris = [cast(BwUri, {"uri": "https://x.example", "match": 0})]
    _, _, changed = remap_item_fields_to_uris(fields, uris)
    if changed:
        raise AssertionError("expected changed=False when no legacy fields present")


def assert_collision_report_helpers() -> None:
    """uri_host / registrable_domain / collision_groups power --report-uris."""
    # Host extraction strips scheme/port/path; app + bare-label URIs yield None.
    if uri_host("https://vault.kajkowalski.nl/login?x=1") != "vault.kajkowalski.nl":
        raise AssertionError("host extraction failed")
    if uri_host("androidapp://com.x") is not None or uri_host("Windows") is not None:
        raise AssertionError("app/bare URIs should have no host")
    # Registrable domain honours the two-level public-suffix heuristic.
    if registrable_domain("vault.kajkowalski.nl") != "kajkowalski.nl":
        raise AssertionError("registrable domain (.nl) failed")
    if registrable_domain("app.10bis.co.il") != "10bis.co.il":
        raise AssertionError("registrable domain (.co.il) failed")
    # Only multi-host registrable domains are reported; singletons are omitted.
    groups = collision_groups([
        "https://vault.kajkowalski.nl",
        "https://gitea.kajkowalski.nl",
        "https://example.com",
        "androidapp://com.x",
    ])
    if set(groups) != {"kajkowalski.nl"}:
        raise AssertionError(f"expected only kajkowalski.nl group, got {groups}")
    if groups["kajkowalski.nl"] != ["gitea.kajkowalski.nl", "vault.kajkowalski.nl"]:
        raise AssertionError(f"unexpected hosts: {groups}")


def main() -> None:
    assert_match_names_parse()
    assert_url_attribute_keys()
    assert_plain_urls_default_to_account_default_and_dedup()
    assert_uri_match_domain_forces_base_domain()
    assert_special_syntaxes_map_when_interpreting()
    assert_drops()
    assert_literal_mode_skips_interpretation()
    assert_plain_match_override()
    assert_remap_lifts_legacy_fields()
    assert_remap_noop_without_legacy_fields()
    assert_collision_report_helpers()
    print("uri mapping test passed")


if __name__ == "__main__":
    main()
