"""Checks that command help stays compact and links to the full CLI guide."""

from unittest import mock

from kp2bw import cli


def assert_plain_help_is_compact_and_copyable() -> None:
    with mock.patch.object(cli.sys.stdout, "isatty", return_value=False):
        output = cli._argparser().format_help()

    if "usage: kp2bw [OPTIONS] [FILE]" not in output:
        raise AssertionError("help expanded every option in the usage line")
    if cli.CLI_DOCS_URL not in output or "\x1b]8;" in output:
        raise AssertionError("redirected help must contain a plain documentation URL")
    if "env: KP2BW_" in output:
        raise AssertionError(
            "detailed environment documentation leaked into short help"
        )


def assert_terminal_help_links_with_osc8() -> None:
    with (
        mock.patch.object(cli.sys.stdout, "isatty", return_value=True),
        mock.patch.dict(cli.os.environ, {"TERM": "xterm-256color"}),
    ):
        output = cli._argparser().format_help()

    if "\x1b]8;" not in output or cli.CLI_DOCS_URL not in output:
        raise AssertionError("terminal help did not contain a clickable OSC 8 link")
    if "CLI reference" not in output:
        raise AssertionError("terminal help link has no readable label")


def assert_narrow_terminal_keeps_osc8_link_intact() -> None:
    with (
        mock.patch.object(cli.sys.stdout, "isatty", return_value=True),
        mock.patch.dict(cli.os.environ, {"COLUMNS": "12", "TERM": "xterm-256color"}),
    ):
        output = cli._argparser().format_help()

    if cli._cli_docs_link(terminal=True) not in output:
        raise AssertionError("narrow help split the OSC 8 documentation link")


def assert_narrow_redirect_keeps_plain_url_intact() -> None:
    with (
        mock.patch.object(cli.sys.stdout, "isatty", return_value=False),
        mock.patch.dict(cli.os.environ, {"COLUMNS": "12"}),
    ):
        output = cli._argparser().format_help()

    if cli.CLI_DOCS_URL not in output:
        raise AssertionError("narrow redirected help split the documentation URL")


def assert_unsupported_terminal_gets_plain_url() -> None:
    with (
        mock.patch.object(cli.sys.stdout, "isatty", return_value=True),
        mock.patch.dict(cli.os.environ, {"TERM": "dumb"}),
    ):
        output = cli._argparser().format_help()

    if "\x1b]8;" in output or cli.CLI_DOCS_URL not in output:
        raise AssertionError("unsupported terminal did not receive the plain URL")


def main() -> None:
    assert_plain_help_is_compact_and_copyable()
    assert_terminal_help_links_with_osc8()
    assert_narrow_terminal_keeps_osc8_link_intact()
    assert_narrow_redirect_keeps_plain_url_intact()
    assert_unsupported_terminal_gets_plain_url()
    print("cli help test passed")


if __name__ == "__main__":
    main()
