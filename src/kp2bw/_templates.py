"""Explicit KeePass template recognition and lossless native-field planning."""

import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast
from uuid import UUID

from ._item_sync import stamp_content
from .bw_types import BwField, BwItemCreate, ItemCard, ItemIdentity
from .exceptions import ConversionError

type TemplateKind = Literal["card", "identity", "secureNote"]

# Stable identifiers from Keepass2Android's AddTemplateEntries.cs. Template
# titles and field labels are translated; these identifiers are not.
_DEFAULT_TYPES: dict[str, TemplateKind] = {
    "49DD48DBFF149445B3392CE90EA75309": "card",
    "A7B525BD0CECC84EB9F0CEDC0B49B5B8": "identity",
    "10F8C25C26AE9B49A47FDA7CDACACEE2": "secureNote",
}
_CARD_FIELDS = frozenset({
    "cardholderName",
    "brand",
    "number",
    "expMonth",
    "expYear",
    "code",
})
_IDENTITY_FIELDS = frozenset({
    "title",
    "firstName",
    "middleName",
    "lastName",
    "address1",
    "address2",
    "address3",
    "city",
    "state",
    "postalCode",
    "country",
    "company",
    "email",
    "phone",
    "ssn",
    "username",
    "passportNumber",
    "licenseNumber",
})


def _key(value: str) -> str:
    return "".join(
        c for c in unicodedata.normalize("NFKC", value).casefold() if c.isalnum()
    )


def template_uuid(value: str) -> str | None:
    """Accept UUID spellings without guessing at malformed source markers."""
    try:
        return UUID(value).hex.upper()
    except ValueError:
        return None


@dataclass(frozen=True)
class TemplateRule:
    kind: TemplateKind
    fields: Mapping[str, str]


@dataclass(frozen=True)
class TemplatePlan:
    kind: TemplateKind
    values: Mapping[str, str]
    consumed: frozenset[str]
    warnings: tuple[str, ...]


def parse_template_overrides(value: object) -> dict[str, TemplateRule]:
    """Validate a UUID-keyed JSON map before opening or mutating a vault."""
    if not isinstance(value, dict):
        raise ConversionError(
            "Template map must be a JSON object keyed by template UUID"
        )
    result: dict[str, TemplateRule] = {}
    for raw_uuid, raw_rule in cast(dict[object, object], value).items():
        identifier = template_uuid(raw_uuid) if isinstance(raw_uuid, str) else None
        if identifier is None or identifier in result:
            raise ConversionError("Template map contains an invalid or duplicate UUID")
        if not isinstance(raw_rule, dict):
            raise ConversionError("Each template rule must be an object")
        rule = cast(dict[object, object], raw_rule)
        if set(rule) - {"type", "fields"}:
            raise ConversionError("Each template rule accepts only type and fields")
        kind = rule.get("type")
        checked_kind: TemplateKind
        if kind == "card":
            checked_kind = "card"
        elif kind == "identity":
            checked_kind = "identity"
        elif kind == "secureNote":
            checked_kind = "secureNote"
        else:
            raise ConversionError("Template type must be card, identity or secureNote")
        fields = rule.get("fields", {})
        if not isinstance(fields, dict):
            raise ConversionError(
                "Template fields must map source names to native field names"
            )
        allowed: frozenset[str] = (
            _CARD_FIELDS
            if kind == "card"
            else _IDENTITY_FIELDS
            if kind == "identity"
            else frozenset()
        )
        checked: dict[str, str] = {}
        for source, target in cast(dict[object, object], fields).items():
            if (
                not isinstance(source, str)
                or not source
                or not isinstance(target, str)
                or target not in allowed
            ):
                raise ConversionError(
                    "Template field mapping has an invalid source or target"
                )
            checked[source] = target
        result[identifier] = TemplateRule(checked_kind, checked)
    return result


def recognize_template(identifier: str, title: str) -> TemplateKind | None:
    """Classify a referenced template, never an ordinary entry's title."""
    if kind := _DEFAULT_TYPES.get(identifier):
        return kind
    titles: dict[str, TemplateKind] = {
        "creditcard": "card",
        "card": "card",
        "idcard": "identity",
        "identity": "identity",
        "passport": "identity",
        "securenote": "secureNote",
        "note": "secureNote",
        "notes": "secureNote",
    }
    return titles.get(_key(title))


def _aliases(kind: TemplateKind) -> dict[str, str]:
    groups: dict[str, tuple[str, ...]]
    if kind == "card":
        groups = {
            "number": ("number", "card number", "card no"),
            "code": ("cvv", "cvc", "code", "security code"),
            "cardholderName": ("owner", "cardholder", "cardholder name", "name"),
            "brand": ("brand", "type"),
            "expMonth": ("expiry month", "expiration month"),
            "expYear": ("expiry year", "expiration year"),
        }
    elif kind == "identity":
        groups = {field: (field,) for field in _IDENTITY_FIELDS}
        groups.update({
            "postalCode": ("postal code", "zip", "zip code"),
            "phone": ("phone", "telephone"),
            "ssn": ("ssn", "social security number"),
        })
    else:
        groups = {}
    return {
        _key(alias): target for target, aliases in groups.items() for alias in aliases
    }


def _value(target: str, value: str) -> str | None:
    if target == "number":
        number = re.sub(r"[ -]", "", value)
        return number if re.fullmatch(r"[0-9]{8,19}", number) else None
    if target == "expMonth":
        return str(int(value)) if re.fullmatch(r"0?[1-9]|1[0-2]", value) else None
    if target == "expYear":
        if re.fullmatch(r"[0-9]{2}", value):
            return "20" + value
        return value if re.fullmatch(r"[0-9]{4}", value) else None
    if target == "brand":
        brands = {
            _key(b): b
            for b in (
                "Visa",
                "Mastercard",
                "American Express",
                "Discover",
                "Diners Club",
                "JCB",
                "Maestro",
                "UnionPay",
                "RuPay",
                "Other",
            )
        }
        return brands.get(_key(value))
    return value


def plan_template(rule: TemplateRule, fields: Mapping[str, str | None]) -> TemplatePlan:
    """Consume only validated, unambiguous native values; retain everything else."""
    candidates: dict[str, list[tuple[str, str]]] = {}
    warnings: list[str] = []
    aliases = _aliases(rule.kind)
    for source, raw in fields.items():
        if raw is None or not raw or source.startswith("_etm_"):
            continue
        targets: dict[str, str] = {}
        target = rule.fields.get(source) or aliases.get(_key(source))
        if target:
            converted = _value(target, raw)
            if converted is not None:
                targets[target] = converted
            else:
                warnings.append(
                    "A template value could not be parsed; its custom field was retained"
                )
        elif rule.kind == "card" and _key(source) in {
            "expiration",
            "expiry",
            "validthru",
            "validuntil",
        }:
            match = re.fullmatch(r"(0?[1-9]|1[0-2])\s*/\s*([0-9]{2}|[0-9]{4})", raw)
            if match:
                targets = {
                    "expMonth": str(int(match[1])),
                    "expYear": "20" + match[2] if len(match[2]) == 2 else match[2],
                }
            else:
                warnings.append(
                    "Card expiry could not be parsed; its custom field was retained"
                )
        for name, value in targets.items():
            candidates.setdefault(name, []).append((source, value))
    values: dict[str, str] = {}
    consumed: set[str] = set()
    rejected_sources: set[str] = set()
    for target, matches in candidates.items():
        if len({value for _, value in matches}) > 1:
            rejected_sources.update(source for source, _ in matches)
            warnings.append(
                "Conflicting template fields were retained as custom fields"
            )
        else:
            values[target] = matches[0][1]
            consumed.update(source for source, _ in matches)
    # A combined expiry must not disappear when only one component agrees.
    consumed.difference_update(rejected_sources)
    return TemplatePlan(
        rule.kind, values, frozenset(consumed), tuple(dict.fromkeys(warnings))
    )


def apply_template(item: BwItemCreate, rule: TemplateRule) -> tuple[str, ...]:
    """Map a parsed login after REF resolution, retaining its source-only data."""
    login = item["login"]
    if login.get("fido2Credentials"):
        return ("Template mapping skipped: native passkeys require a login item",)
    plan = plan_template(
        rule, {field["name"]: field["value"] for field in item["fields"]}
    )
    retained_login = {
        key: value
        for key, value in login.items()
        if value and key != "passwordRevisionDate"
    }
    encoded_login = json.dumps(retained_login, ensure_ascii=False, sort_keys=True)
    if len(encoded_login) > 10000:
        return (
            "Template mapping skipped: source login data exceeds the custom-field limit",
        )
    fields = [
        field.copy()
        for field in item["fields"]
        if field["name"] not in plan.consumed and field["name"] != "_etm_template_uuid"
    ]
    if retained_login:
        used = {field["name"] for field in fields}
        name = "KeePass login data"
        ordinal = 2
        while name in used:
            name = f"KeePass login data ({ordinal})"
            ordinal += 1
        fields.append(
            BwField(
                name=name,
                value=encoded_login,
                type=1 if login["password"] or login["totp"] else 0,
            )
        )
    item["fields"] = fields
    item["type"] = {"secureNote": 2, "card": 3, "identity": 4}[plan.kind]
    item["card"] = cast(ItemCard, dict(plan.values)) if plan.kind == "card" else None
    item["identity"] = (
        cast(ItemIdentity, dict(plan.values)) if plan.kind == "identity" else None
    )
    item["secureNote"] = {"type": 0} if plan.kind == "secureNote" else None
    # The parsed source login stays available internally for REF provenance.
    # The transport omits it for native non-login items.
    stamp_content(item)
    return plan.warnings
