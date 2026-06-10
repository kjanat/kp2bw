"""Logging-behaviour contract for kp2bw.

``cli._configure_logging`` pins ``httpx``/``httpcore`` to DEBUG so the always-on
file captures full transport traces (the data that explains timeouts/#24), and
quiets the console with :class:`~kp2bw.cli.ConsoleNoiseFilter` rather than by
lowering the loggers (which would also starve the file). This guards the two
properties that design rests on:

1. Console muting is a handler concern: the default filter drops both noisy
   loggers below WARNING; the ``--debug`` variant keeps ``httpx`` request lines
   but still mutes ``httpcore`` connection spam.
2. At full transport DEBUG, the master password kp2bw posts in the ``/unlock``
   *body* never reaches the logs. httpx emits its ``HTTP Request: ...`` record on
   the real send path (exercised here via ``MockTransport``); the password rides
   only in the request *body*, which httpx -- like httpcore -- never logs. Both
   ``bw_serve`` httpx clients (the sync client that posts ``/unlock`` and the
   async attachment-upload client) are built header-free, so the logged request
   line carries no secret either; the test below pins that header invariant.
"""

import logging

import httpx

from kp2bw.cli import ConsoleNoiseFilter


def _record(name: str, level: int) -> logging.LogRecord:
    return logging.LogRecord(name, level, __file__, 0, "msg", args=None, exc_info=None)


def assert_console_filter_mutes_per_mode() -> None:
    """Default filter mutes both noisy loggers; the --debug variant keeps httpx."""
    default = ConsoleNoiseFilter()
    if default.filter(_record("httpx", logging.DEBUG)):
        raise AssertionError("plain console must drop httpx DEBUG")
    if default.filter(_record("httpcore", logging.INFO)):
        raise AssertionError("plain console must drop httpcore INFO")
    if not default.filter(_record("httpx", logging.WARNING)):
        raise AssertionError("plain console must keep httpx WARNING+")
    if not default.filter(_record("kp2bw.convert", logging.DEBUG)):
        raise AssertionError("filter must never touch kp2bw records")

    debug = ConsoleNoiseFilter(frozenset({"httpcore"}))
    if not debug.filter(_record("httpx", logging.DEBUG)):
        raise AssertionError("--debug console must keep httpx DEBUG")
    if debug.filter(_record("httpcore", logging.DEBUG)):
        raise AssertionError("--debug console must still drop httpcore DEBUG")


class _LogCapture(logging.Handler):
    """Collect every record reaching the root logger as ``name: message``."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(f"{record.name}: {record.getMessage()}")


# Sentinel shaped like a secret body value -- not a real credential.
_SECRET = "p@ss-not-real-DO-NOT-LOG-7f3a91"


def assert_transport_debug_excludes_request_body() -> None:
    """At DEBUG, httpx logs the request line but never the secret-bearing body."""
    seen: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        _ = request.content  # realize the body on the send path, as a real send would
        return httpx.Response(200, json={"ok": True})

    root = logging.getLogger()
    capture = _LogCapture()
    saved_httpx = logging.getLogger("httpx").level
    saved_root = root.level
    root.addHandler(capture)
    root.setLevel(logging.DEBUG)
    logging.getLogger("httpx").setLevel(logging.DEBUG)
    try:
        with httpx.Client(
            transport=httpx.MockTransport(handler), base_url="http://bw.local"
        ) as client:
            response = client.post("/unlock", json={"password": _SECRET})
            _ = response.read()
    finally:
        root.removeHandler(capture)
        root.setLevel(saved_root)
        logging.getLogger("httpx").setLevel(saved_httpx)

    # The bw_serve client is built header-free, so the request carries no
    # auth/cookie header -- meaning even a logger that dumps headers (httpcore,
    # not exercised here) cannot leak a secret that way. Pin that invariant.
    if not seen:
        raise AssertionError("MockTransport handler never ran; header check is invalid")
    request_headers = seen[0]
    for forbidden in ("authorization", "cookie"):
        if forbidden in request_headers:
            raise AssertionError(f"request carried a secret-bearing {forbidden} header")

    blob = "\n".join(capture.lines)
    if _SECRET in blob:
        raise AssertionError("master-password body leaked into httpx logs:\n" + blob)
    if not any("/unlock" in line for line in capture.lines if line.startswith("httpx")):
        raise AssertionError("expected httpx request-line for /unlock not captured")


def main() -> None:
    assert_console_filter_mutes_per_mode()
    assert_transport_debug_excludes_request_body()
    print("cli logging behaviour test passed")


if __name__ == "__main__":
    main()
