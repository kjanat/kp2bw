"""Org-collection requests must carry the ``organizationId`` query parameter (#43).

``POST /object/org-collection`` declares ``organizationId`` as a required query
parameter in ``specs/vault-management-api.json``.  Sending it only in the JSON
body made ``bw serve`` reject the create with "organizationid option is
required", which broke every migration into an organisation.  These checks drive
the real :meth:`BitwardenServeClient.create_org_collection` and
:meth:`BitwardenServeClient.list_collections` against a recording HTTP double,
so no ``bw serve`` process is spawned.
"""

from typing import Any, cast

import httpx

from kp2bw.bw_serve import BitwardenServeClient

ORG_ID = "org-1234"


class RecordingHttp:
    """Records every request and replays a canned ``bw serve`` envelope."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.calls: list[tuple[str, str, Any, Any]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Any = None,
    ) -> httpx.Response:
        self.calls.append((method, path, json, params))
        return httpx.Response(200, json={"success": True, "data": self.payload})


class CollectionClient(BitwardenServeClient):
    """Client double wired to a recording transport.

    Bypasses the real ``__init__`` (which would spawn ``bw serve``); only the
    state the org-collection methods touch is initialised.  The inherited
    methods are the code under test.
    """

    def __init__(self, *, org_id: str | None, payload: dict[str, Any]) -> None:
        self.organization_id = org_id
        self.collections = None
        self.recording_http = RecordingHttp(payload)
        self.http = cast(httpx.Client, self.recording_http)


def assert_create_org_collection_sends_organization_id_param() -> None:
    """The #43 regression: the create POST omitted the query parameter."""
    bw = CollectionClient(org_id=ORG_ID, payload={"id": "coll-1"})
    coll_id = bw.create_org_collection("Imported")
    if coll_id != "coll-1":
        raise AssertionError(f"expected the server-assigned id, got {coll_id!r}")
    if len(bw.recording_http.calls) != 1:
        raise AssertionError(
            f"expected exactly one request, got {bw.recording_http.calls}"
        )
    method, path, json_body, params = bw.recording_http.calls[0]
    if (method, path) != ("POST", "/object/org-collection"):
        raise AssertionError(f"unexpected request: {method} {path}")
    if params != {"organizationId": ORG_ID}:
        raise AssertionError(f"organizationId query param missing, got {params!r}")
    if json_body != {"organizationId": ORG_ID, "name": "Imported", "groups": []}:
        raise AssertionError(f"unexpected create body: {json_body!r}")


def assert_cached_collection_skips_second_request() -> None:
    """A second create of the same name is served from cache, not re-POSTed."""
    bw = CollectionClient(org_id=ORG_ID, payload={"id": "coll-1"})
    first = bw.create_org_collection("Imported")
    second = bw.create_org_collection("Imported")
    if first != second:
        raise AssertionError(f"cached id must match, got {first!r} and {second!r}")
    if len(bw.recording_http.calls) != 1:
        raise AssertionError(
            f"cache must avoid a second POST, got {bw.recording_http.calls}"
        )


def assert_no_org_makes_no_request() -> None:
    """Without an organisation there is no collection to create."""
    bw = CollectionClient(org_id=None, payload={"id": "coll-1"})
    if bw.create_org_collection("Imported") is not None:
        raise AssertionError("a personal-vault run must not create a collection")
    if bw.recording_http.calls:
        raise AssertionError(
            f"no request should be sent, got {bw.recording_http.calls}"
        )


def assert_list_collections_sends_organization_id_param() -> None:
    """The list endpoint declares the same required query parameter."""
    bw = CollectionClient(
        org_id=ORG_ID, payload={"data": [{"name": "Imported", "id": "coll-1"}]}
    )
    if bw.list_collections() != {"Imported": "coll-1"}:
        raise AssertionError("list_collections must map name to id")
    method, path, _, params = bw.recording_http.calls[0]
    if (method, path) != ("GET", "/list/object/org-collections"):
        raise AssertionError(f"unexpected request: {method} {path}")
    if params != {"organizationId": ORG_ID}:
        raise AssertionError(f"organizationId query param missing, got {params!r}")


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_create_org_collection_sends_organization_id_param()
    assert_cached_collection_skips_second_request()
    assert_no_org_makes_no_request()
    assert_list_collections_sends_organization_id_param()
    print("bw serve org collection test passed")


if __name__ == "__main__":
    main()
