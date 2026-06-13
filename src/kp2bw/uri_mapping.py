"""Map KeePass(XC) entry URLs onto Bitwarden login URIs with per-URI match modes.

KeePass2Android / KeePassXC store a primary ``URL`` plus any number of
*additional URLs* in ``KP2A_URL`` / ``KP2A_URL_<n>`` custom attributes, and
Android package ids in ``AndroidApp`` attributes. Historically kp2bw copied
those verbatim into Bitwarden *custom fields*, where they are inert noise.

This module converts them into the thing Bitwarden actually uses for autofill:
extra entries in ``login.uris``. Each emitted URI carries a ``match`` mode chosen
to reproduce how KeePassXC itself would have matched that URL string:

* KeePassXC's default matching is **host-based** -- a stored URL matches its base
  domain and all subdomains, ignoring path/query/fragment for inclusion. The
  faithful Bitwarden equivalent is **base domain (0)**, which is the default for
  a plain string.
* KeePassXC honours two inline syntaxes **on additional URLs only**: a
  double-quoted string is an *exact* match, and a ``*`` is a wildcard. These map
  to **exact (3)** and **starts-with (2)** / **regex (4)** respectively.
* Non-web schemes (``keepassxc://``, ``cmd://``, ``kdbx://``, ``file://``) and
  unresolved ``{REF:...}`` placeholders are dropped -- they are not site URLs and
  would only leave dead URIs behind.

Two orthogonal knobs steer the behaviour:

* ``plain_match`` -- what a no-encoded-intent (plain) string becomes. Defaults to
  base domain (0); ``None`` defers to the user's Bitwarden account default.
* ``interpret_syntax`` -- whether the quote/wildcard conventions are honoured at
  all. With it off, every additional URL is treated as a plain string (the
  scheme/garbage drops still apply), for a deliberately literal import.

Important caveat on regex: Bitwarden applies a single regex to the **whole URL**
(unanchored, case-insensitive), whereas KeePassXC regexes host and path
*separately*. The wildcard->regex translation here is therefore a best-effort
whole-URL pattern, not a byte-for-byte copy of KeePassXC's internal regex;
complex wildcards are emitted with a warning so the user can review them.
"""

import logging
import re
from typing import Literal

from .bw_types import BwUri

logger = logging.getLogger(__name__)

# Bitwarden URI match-detection modes; ``None`` means "use the account default".
type UriMatchValue = Literal[0, 1, 2, 3, 4, 5] | None

# Symbolic names accepted by the --uri-match / KP2BW_URI_MATCH knob. ``domain``
# is the faithful KeePassXC-replication setting; ``default``/``null`` defer to the
# user's Bitwarden account default.
_MATCH_NAMES: dict[str, UriMatchValue] = {
    "domain": 0,
    "host": 1,
    "startswith": 2,
    "exact": 3,
    "regex": 4,
    "never": 5,
    "default": None,
    "null": None,
}

# KeePass2Android / KeePassXC additional-URL attribute names: KP2A_URL, KP2A_URL_1, ...
_ADDITIONAL_URL_RE = re.compile(r"^KP2A_URL(_\d+)?$")
# Android package attribute names: AndroidApp, AndroidApp_1, ...
_ANDROID_APP_RE = re.compile(r"^AndroidApp(_\d+)?$")

# Schemes that are never site URLs and must not become Bitwarden URIs.
_DROP_SCHEMES: tuple[str, ...] = ("keepassxc://", "cmd://", "kdbx://", "file://")
# Unresolved KeePass field-reference placeholder.
_KP_REF_MARKER = "{REF:"
# Characters KeePassXC rejects in a URL (`isUrlValid`); we drop strings carrying them.
_ILLEGAL_URL_CHARS = re.compile(r"[<>^`{|}]")
_ANDROID_APP_SCHEME = "androidapp://"


def match_value_names() -> tuple[str, ...]:
    """Return the accepted --uri-match names, for help text and arg validation."""
    return tuple(_MATCH_NAMES)


def parse_match_name(name: str) -> UriMatchValue:
    """Resolve a symbolic match name to its Bitwarden value (or ``None``).

    Raises :class:`ValueError` on an unknown name so the CLI/env layer can report
    it with the list of valid options.
    """
    key = name.strip().lower()
    if key not in _MATCH_NAMES:
        valid = ", ".join(_MATCH_NAMES)
        raise ValueError(f"Invalid URI match mode {name!r}; choose one of: {valid}")
    return _MATCH_NAMES[key]


def is_url_attribute_key(key: str) -> bool:
    """True for KeePass keys that hold URLs/app ids handled as login URIs.

    Used by the converter to keep these out of the custom-fields section -- they
    are folded into ``login.uris`` instead.
    """
    return bool(_ADDITIONAL_URL_RE.match(key)) or bool(_ANDROID_APP_RE.match(key))


def is_additional_url_key(key: str) -> bool:
    """True for ``KP2A_URL`` / ``KP2A_URL_<n>`` additional-URL attribute names."""
    return bool(_ADDITIONAL_URL_RE.match(key))


def is_android_app_key(key: str) -> bool:
    """True for ``AndroidApp`` / ``AndroidApp_<n>`` package attribute names."""
    return bool(_ANDROID_APP_RE.match(key))


def url_attribute_index(key: str) -> int:
    """Stable sort index for a URL attribute: bare name first, then by suffix.

    ``KP2A_URL`` -> -1, ``KP2A_URL_2`` -> 2, ``KP2A_URL_10`` -> 10, so the emitted
    URI order is deterministic across runs (the dedup content-diff compares the
    ``uris`` list positionally, so a stable order avoids spurious "changed" runs).
    """
    match = re.search(r"_(\d+)$", key)
    return int(match.group(1)) if match else -1


def _android_uri(package: str) -> BwUri | None:
    """Build an ``androidapp://`` URI from a package id, or ``None`` if empty.

    ``match`` is left unset (account default): Bitwarden matches Android apps by
    package id, so a URL match mode does not apply.
    """
    pkg = package.strip()
    if not pkg:
        return None
    if not pkg.startswith(_ANDROID_APP_SCHEME):
        pkg = f"{_ANDROID_APP_SCHEME}{pkg}"
    return BwUri(uri=pkg)


def _split_packages(value: str) -> list[str]:
    """Split an AndroidApp attribute into package ids (comma/whitespace separated)."""
    return [p for p in re.split(r"[\s,]+", value.strip()) if p]


def _host_part(url: str) -> str:
    """Return the host portion of *url* (between scheme:// and the first '/')."""
    after_scheme = url.split("://", 1)[-1]
    return after_scheme.split("/", 1)[0]


def _is_invalid_wildcard(glob: str) -> bool:
    """Reproduce KeePassXC's wildcard validity rejections (the common subset).

    Rejects double/adjacent wildcards, all-wildcard strings, and bare TLD
    wildcards like ``*.com`` -- inputs KeePassXC itself refuses, so we never emit
    a Bitwarden URI for them. (Public-suffix edge cases such as ``*.co.uk`` are a
    documented minor divergence.)
    """
    if "**" in glob or "*.*" in glob:
        return True
    # A string that is only wildcards / separators carries no real target.
    if not glob.replace("*", "").replace(".", "").replace("/", "").replace(":", ""):
        return True
    host = _host_part(glob)
    # `*.com` style: a wildcard label in front of a single bare TLD label.
    return host.startswith("*.") and "." not in host[2:]


def _trailing_path_wildcard_prefix(s: str) -> str | None:
    """If *s* is a trailing-path-only wildcard, return the literal prefix.

    e.g. ``https://host/app/*`` -> ``https://host/app/`` for a starts-with (2)
    match. Returns ``None`` when the wildcard is in the host or appears interior,
    which need the regex path instead.
    """
    if s.count("*") != 1 or not s.endswith("*"):
        return None
    if "*" in _host_part(s):
        return None
    return s[:-1]


def _glob_to_regex(glob: str) -> str:
    """Best-effort whole-URL regex for a wildcard URL (Bitwarden match mode 4).

    Bitwarden applies one regex to the entire URL (unanchored, case-insensitive),
    unlike KeePassXC's separate host/path regexes, so this expands each ``*`` to
    ``.*`` over the regex-escaped literal rather than copying KeePassXC's internal
    pattern. Faithful enough for autofill on the intended URLs; emitted with a
    warning by the caller for human review.
    """
    return ".*".join(re.escape(part) for part in glob.split("*"))


def _classify_additional_url(
    raw: str, *, plain_match: UriMatchValue, interpret_syntax: bool
) -> BwUri | None:
    """Map a single additional-URL string to a Bitwarden URI, or ``None`` to drop.

    Drops (scheme/reference/garbage) apply in every mode; the quote and wildcard
    interpretations are skipped when *interpret_syntax* is off, so the string is
    emitted as a plain URI instead.
    """
    s = raw.strip()
    if not s:
        return None
    if s.lower().startswith(_DROP_SCHEMES):
        logger.debug(f"Dropping non-web URL from URIs: {s!r}")
        return None
    if _KP_REF_MARKER in s:
        logger.debug(f"Dropping unresolved reference URL from URIs: {s!r}")
        return None
    if _ILLEGAL_URL_CHARS.search(s):
        logger.debug(f"Dropping URL with illegal characters from URIs: {s!r}")
        return None

    if interpret_syntax:
        if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
            inner = s[1:-1]
            if not inner or "*" in inner:
                logger.debug(f"Dropping invalid quoted-exact URL: {s!r}")
                return None
            return BwUri(uri=inner, match=3)
        if "*" in s:
            if _is_invalid_wildcard(s):
                logger.debug(f"Dropping invalid wildcard URL: {s!r}")
                return None
            prefix = _trailing_path_wildcard_prefix(s)
            if prefix is not None:
                return BwUri(uri=prefix, match=2)
            logger.warning(
                f"Wildcard URL {s!r} migrated as a regex match; review it in "
                f"Bitwarden -- complex wildcard fidelity is best-effort"
            )
            return BwUri(uri=_glob_to_regex(s), match=4)

    return BwUri(uri=s, match=plain_match)


def build_login_uris(
    *,
    primary_url: str,
    additional_urls: list[str],
    android_packages: list[str],
    plain_match: UriMatchValue = 0,
    interpret_syntax: bool = True,
) -> list[BwUri]:
    """Build the ordered, de-duplicated ``login.uris`` list for an entry.

    The primary URL is always treated as a plain string (KeePassXC honours the
    quote/wildcard syntax only on *additional* URLs), additional URLs go through
    :func:`_classify_additional_url`, and each Android package becomes an
    ``androidapp://`` URI. Duplicate URI values are collapsed, first occurrence
    winning, so the primary URL is never repeated by an identical alias.
    """
    uris: list[BwUri] = []
    seen: set[str] = set()

    def _add(uri: BwUri | None) -> None:
        if uri is None:
            return
        if uri["uri"] in seen:
            return
        seen.add(uri["uri"])
        uris.append(uri)

    primary = primary_url.strip()
    if primary:
        _add(BwUri(uri=primary, match=plain_match))
    for raw in additional_urls:
        _add(
            _classify_additional_url(
                raw, plain_match=plain_match, interpret_syntax=interpret_syntax
            )
        )
    for value in android_packages:
        for package in _split_packages(value):
            _add(_android_uri(package))

    return uris
