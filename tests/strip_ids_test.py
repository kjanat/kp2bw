"""Checks the KP2BW_ID strip/finalize pass (`--strip-ids`).

Once a migration is trusted, `BitwardenServeClient.strip_field_from_items`
removes kp2bw's `KP2BW_ID` dedup stamp from every in-scope item, leaving other
fields and unstamped items untouched, and is safe to repeat (a second pass finds
nothing). These checks drive the method with a client double, so no live
`bw serve` process is spawned.
"""

from typing import cast

from kp2bw.bw_serve import KP2BW_ID_FIELD_NAME, BitwardenServeClient
from kp2bw.bw_types import BwField, BwItemResponse


def _item(item_id: str, field_names: list[str]) -> BwItemResponse:
    """Build a minimal list-shaped item carrying the named custom fields."""
    fields = [cast(BwField, {"name": name, "value": "v"}) for name in field_names]
    return cast(BwItemResponse, {"id": item_id, "name": item_id, "fields": fields})


class _StripClient(BitwardenServeClient):
    """Client double serving a fixed item list and recording every update.

    Bypasses the real ``__init__`` (which would spawn ``bw serve``); only the
    scope state and the two transport methods the strip touches are provided.
    The inherited ``strip_field_from_items`` is the code under test.
    """

    def __init__(self, items: list[BwItemResponse]) -> None:
        self._org_id = None
        self._collection_id = None
        self._items = items
        # (item_id, remaining field names) for each PUT the method issues.
        self.updates: list[tuple[str, list[str]]] = []

    def list_items(
        self,
        *,
        folder_id: str | None = None,
        organization_id: str | None = None,
        collection_id: str | None = None,
    ) -> list[BwItemResponse]:
        return self._items

    def update_item(self, item_id: str, item: BwItemResponse) -> None:
        names = [field.get("name", "") for field in item.get("fields") or []]
        self.updates.append((item_id, names))


def assert_only_stamped_items_stripped() -> None:
    """Only items carrying KP2BW_ID are rewritten, and only that field is removed."""
    items = [
        _item("stamped-both", [KP2BW_ID_FIELD_NAME, "keep"]),
        _item("plain", ["keep"]),
        _item("stamped-only", [KP2BW_ID_FIELD_NAME]),
        _item("no-fields", []),
    ]
    client = _StripClient(items)

    result = client.strip_field_from_items(KP2BW_ID_FIELD_NAME)

    if result.scanned != 4:
        raise AssertionError(f"expected 4 scanned, got {result.scanned}")
    if result.stripped != 2:
        raise AssertionError(f"expected 2 stripped, got {result.stripped}")

    updated_ids = [item_id for item_id, _ in client.updates]
    if updated_ids != ["stamped-both", "stamped-only"]:
        raise AssertionError(f"unexpected items updated: {updated_ids}")

    for item_id, remaining in client.updates:
        if KP2BW_ID_FIELD_NAME in remaining:
            raise AssertionError(f"{item_id} still carries {KP2BW_ID_FIELD_NAME}")
    # The unrelated field on the multi-field item must survive.
    both_remaining = dict(client.updates)["stamped-both"]
    if both_remaining != ["keep"]:
        raise AssertionError(f"non-stamp field not preserved: {both_remaining}")


def assert_second_pass_is_noop() -> None:
    """Re-running over already-clean items strips nothing and issues no PUTs."""
    items = [_item("plain", ["keep"]), _item("no-fields", [])]
    client = _StripClient(items)

    result = client.strip_field_from_items(KP2BW_ID_FIELD_NAME)

    if result.stripped != 0:
        raise AssertionError(f"expected 0 stripped, got {result.stripped}")
    if client.updates:
        raise AssertionError(f"expected no updates, got {client.updates}")


def assert_declined_confirmation_aborts_without_touching_vault() -> None:
    """Answering 'n' at the prompt aborts before any client is built.

    Stripping is irreversible, so an interactive run (``skip_confirm=False``)
    must not reach ``bw serve`` unless the user explicitly confirms.
    """
    from unittest import mock

    from kp2bw import cli

    def _must_not_build(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("client built despite a declined confirmation")

    with (
        mock.patch("builtins.input", return_value="n"),
        mock.patch.object(cli, "BitwardenServeClient", _must_not_build),
    ):
        try:
            cli._run_strip_ids(
                bitwarden_password_arg="bw-pw",
                org_id=None,
                collection_id=None,
                skip_confirm=False,
            )
        except SystemExit as exc:
            if exc.code != 2:
                raise AssertionError(f"expected exit code 2, got {exc.code}")
        else:
            raise AssertionError("expected SystemExit on a declined confirmation")


def assert_yes_skips_confirmation_prompt() -> None:
    """``-y`` (``skip_confirm=True``) runs the strip without prompting at all.

    The user is trusted to opt out of the confirmation; reaching ``input`` would
    mean the override was ignored.
    """
    from typing import Self
    from unittest import mock

    from kp2bw import cli
    from kp2bw.bw_serve import StripResult

    class _FakeClient:
        """Minimal context-manager stand-in exposing the one method called."""

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def strip_field_from_items(self, _field_name: str) -> StripResult:
            return StripResult(scanned=3, stripped=0)

    def _must_not_prompt(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("prompted despite -y (skip_confirm=True)")

    def _make_client(*_args: object, **_kwargs: object) -> _FakeClient:
        return _FakeClient()

    with (
        mock.patch("builtins.input", _must_not_prompt),
        mock.patch.object(cli, "BitwardenServeClient", _make_client),
    ):
        cli._run_strip_ids(
            bitwarden_password_arg="bw-pw",
            org_id=None,
            collection_id=None,
            skip_confirm=True,
        )


def main() -> None:
    assert_only_stamped_items_stripped()
    assert_second_pass_is_noop()
    assert_declined_confirmation_aborts_without_touching_vault()
    assert_yes_skips_confirmation_prompt()
    print("strip ids test passed")


if __name__ == "__main__":
    main()
