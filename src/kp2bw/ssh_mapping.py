"""Explicit SSH selectors and preservation of source key representations."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from .attachments import SourceFile, source_file
from .bw_types import BwField, BwItemCreate
from .exceptions import ConversionError
from .item_sync import stamp_content
from .source_fields import source_field_name
from .ssh_keys import convert_ssh_key
from .templates import template_uuid


@dataclass(frozen=True)
class SshRule:
    selector: Literal["group", "template", "field"]
    value: str
    discriminator: str | None
    fields: Mapping[str, str]

    def matches(
        self, group: str, template: str | None, fields: Mapping[str, str | None]
    ) -> bool:
        if self.selector == "group":
            return group == self.value
        if self.selector == "template":
            return template == self.value
        return fields.get(source_field_name(self.discriminator or "")) == self.value


def parse_ssh_rules(value: object) -> tuple[SshRule, ...]:
    if not isinstance(value, list):
        raise ConversionError("SSH map must be a JSON list of explicit mapping rules")
    rules: list[SshRule] = []
    for candidate in cast(list[object], value):
        if not isinstance(candidate, dict):
            raise ConversionError("SSH mapping rules must be objects")
        rule = cast(dict[str, object], candidate)
        selectors = set(rule) & {"group", "template", "field"}
        if len(selectors) != 1 or set(rule) - {"group", "template", "field", "fields"}:
            raise ConversionError(
                "Each SSH rule requires exactly one group, template or field selector"
            )
        discriminator = None
        selector: Literal["group", "template", "field"]
        if "group" in rule:
            selector = "group"
            if not isinstance(rule["group"], str):
                raise ConversionError("SSH group selector must be a group path")
            selected = rule["group"].strip("/")
        elif "template" in rule:
            selector = "template"
            raw = rule["template"]
            selected = template_uuid(raw) if isinstance(raw, str) else None
            if selected is None:
                raise ConversionError("SSH template selector must be a UUID")
        else:
            selector = "field"
            raw = rule["field"]
            if not isinstance(raw, dict):
                raise ConversionError("SSH field selector requires name and value")
            field = cast(dict[str, object], raw)
            if (
                set(field) != {"name", "value"}
                or not isinstance(field["name"], str)
                or not isinstance(field["value"], str)
                or not field["name"]
            ):
                raise ConversionError(
                    "SSH field selector requires a name and string value"
                )
            discriminator, selected = field["name"], field["value"]
        raw_fields = rule.get("fields")
        if not isinstance(raw_fields, dict):
            raise ConversionError(
                "SSH rule fields must map native key fields to source field names"
            )
        fields = cast(dict[str, object], raw_fields)
        if "privateKey" not in fields or set(fields) - {
            "privateKey",
            "publicKey",
            "keyFingerprint",
        }:
            raise ConversionError(
                "SSH fields require privateKey and allow publicKey and keyFingerprint"
            )
        checked: dict[str, str] = {}
        for role, source in fields.items():
            if not isinstance(source, str) or not source:
                raise ConversionError("SSH source field names must be nonempty strings")
            checked[role] = source_field_name(source)
        rules.append(SshRule(selector, selected, discriminator, checked))
    return tuple(rules)


def apply_ssh_rule(
    item: BwItemCreate,
    source: Mapping[str, str | None],
    rule: SshRule,
) -> tuple[list[SourceFile], tuple[str, ...]]:
    """Keep original key fields or attachments even when native conversion fails."""
    if item["type"] != 1:
        raise ConversionError(
            "An entry cannot match both SSH and another native template mapping"
        )
    values = {role: source.get(name) for role, name in rule.fields.items()}
    files: list[SourceFile] = []
    for role, name in rule.fields.items():
        value = values[role]
        if value is None:
            continue
        existing = next(
            (field for field in item["fields"] if field["name"] == name), None
        )
        if len(value) <= 10000:
            if existing is None:
                item["fields"].append(
                    BwField(
                        name=name, value=value, type=1 if role == "privateKey" else 0
                    )
                )
            elif role == "privateKey":
                existing["type"] = 1
        else:
            files.append(
                source_file(
                    "ssh-source", role, 1, "ssh-" + role + ".txt", value.encode("utf-8")
                )
            )
    conversion = convert_ssh_key(
        values.get("privateKey") or "",
        public_key=values.get("publicKey"),
        fingerprint=values.get("keyFingerprint"),
    )
    if conversion.key is None:
        stamp_content(item)
        return files, (
            conversion.reason or "SSH conversion unavailable; source retained",
        )
    login = item["login"]
    if login.get("fido2Credentials"):
        stamp_content(item)
        return files, ("SSH mapping skipped: a native passkey requires a login item",)
    retained = {
        key: value
        for key, value in login.items()
        if value and key != "passwordRevisionDate"
    }
    if retained:
        encoded = json.dumps(retained, ensure_ascii=False, sort_keys=True)
        if len(encoded) > 10000:
            files.append(
                source_file(
                    "ssh-source",
                    "login",
                    1,
                    "ssh-login-data.json",
                    encoded.encode("utf-8"),
                )
            )
        else:
            names = {field["name"] for field in item["fields"]}
            name = "KeePass login data"
            ordinal = 2
            while name in names:
                name = f"KeePass login data ({ordinal})"
                ordinal += 1
            item["fields"].append(
                BwField(
                    name=name,
                    value=encoded,
                    type=1 if login["password"] or login["totp"] else 0,
                )
            )
    item["type"] = 5
    item["sshKey"] = conversion.key
    item["fields"] = [
        field for field in item["fields"] if field["name"] != "_etm_template_uuid"
    ]
    stamp_content(item)
    return files, ()
