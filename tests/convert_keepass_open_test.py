"""Single actionable error when the KeePass database cannot be opened (issue #47).

A wrong password used to surface ``construct``'s ``ChecksumError`` chained to
``pykeepass``'s ``CredentialsError``, so the CLI printed two full tracebacks.
The open path now raises :class:`kp2bw.exceptions.ConversionError`, which the
CLI renders as one line and exits non-zero on.
"""

import logging
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

from pykeepass import PyKeePass, create_database
from pykeepass.exceptions import CredentialsError

from kp2bw import cli
from kp2bw._console import console
from kp2bw.convert import Converter, collect_keepass_uris
from kp2bw.exceptions import ConversionError

PASSWORD = "correct-horse-battery-staple"
WRONG_PASSWORD = "definitely-not-the-password"
ENTRY_URL = "https://example.com"


class OpenTestConverter(Converter):
    """Converter exposing the offline database load for open-failure tests."""

    def load_keepass_data(self) -> None:
        """Run the load phase that opens the ``.kdbx`` file."""
        self._load_keepass_data()


def _seed(db_path: str) -> None:
    kp: PyKeePass = create_database(db_path, password=PASSWORD)
    group = kp.add_group(kp.root_group, "Demo")
    _ = kp.add_entry(group, "Example", "user", "entry-secret", url=ENTRY_URL)
    kp.save()


def _converter(db_path: str, password: str) -> OpenTestConverter:
    return OpenTestConverter(
        keepass_file_path=db_path,
        keepass_password=password,
        keepass_keyfile_path=None,
        bitwarden_password="bw-pw",
        bitwarden_organization_id=None,
        bitwarden_coll_id=None,
        path2name=False,
        path2nameskip=1,
        import_tags=None,
    )


def _check_message(exc: ConversionError, db_path: str) -> None:
    message = str(exc)
    if db_path not in message:
        raise AssertionError(f"message must name the database, got {message!r}")
    for secret in (PASSWORD, WRONG_PASSWORD, "entry-secret", "bw-pw"):
        if secret in message:
            raise AssertionError(f"message leaked a secret: {message!r}")


def assert_wrong_password_raises_conversion_error() -> None:
    """The migration load path must report a wrong password as a ConversionError."""
    with tempfile.TemporaryDirectory(prefix="kp2bw-open-") as tmp_dir:
        db_path = str(Path(tmp_dir) / "vault.kdbx")
        _seed(db_path)

        try:
            _converter(db_path, WRONG_PASSWORD).load_keepass_data()
        except CredentialsError as exc:
            raise AssertionError(
                "a wrong password must not surface pykeepass' CredentialsError"
            ) from exc
        except ConversionError as exc:
            _check_message(exc, db_path)
            lowered = str(exc).lower()
            if "password" not in lowered:
                raise AssertionError(
                    f"message must point at the password, got {str(exc)!r}"
                ) from None
            if exc.__cause__ is not None or not exc.__suppress_context__:
                raise AssertionError(
                    "the chained parser exception must be suppressed"
                ) from None
        else:
            raise AssertionError("a wrong password must fail the load")


def assert_wrong_password_raises_conversion_error_for_uri_report() -> None:
    """The read-only URI report shares the guarded open path."""
    with tempfile.TemporaryDirectory(prefix="kp2bw-open-") as tmp_dir:
        db_path = str(Path(tmp_dir) / "vault.kdbx")
        _seed(db_path)

        try:
            _ = collect_keepass_uris(db_path, WRONG_PASSWORD, None)
        except ConversionError as exc:
            _check_message(exc, db_path)
        else:
            raise AssertionError("a wrong password must fail the URI report")


def assert_missing_database_raises_conversion_error() -> None:
    """A path that does not exist must fail the same way, not with a raw OSError."""
    with tempfile.TemporaryDirectory(prefix="kp2bw-open-") as tmp_dir:
        db_path = str(Path(tmp_dir) / "absent.kdbx")

        try:
            _converter(db_path, PASSWORD).load_keepass_data()
        except ConversionError as exc:
            _check_message(exc, db_path)
        else:
            raise AssertionError("a missing database must fail the load")


def assert_non_keepass_file_raises_conversion_error() -> None:
    """A file that is not a KeePass database must fail the same way."""
    with tempfile.TemporaryDirectory(prefix="kp2bw-open-") as tmp_dir:
        db_path = str(Path(tmp_dir) / "notes.kdbx")
        _ = Path(db_path).write_bytes(b"not a keepass database")

        try:
            _converter(db_path, PASSWORD).load_keepass_data()
        except ConversionError as exc:
            _check_message(exc, db_path)
        else:
            raise AssertionError("a non-KeePass file must fail the load")


def assert_correct_password_still_opens_the_database() -> None:
    """The guarded open must leave the success path untouched."""
    with tempfile.TemporaryDirectory(prefix="kp2bw-open-") as tmp_dir:
        db_path = str(Path(tmp_dir) / "vault.kdbx")
        _seed(db_path)

        converter = _converter(db_path, PASSWORD)
        converter.load_keepass_data()

        uris = collect_keepass_uris(db_path, PASSWORD, None)
        if uris != [ENTRY_URL]:
            raise AssertionError(f"expected the seeded URI, got {uris}")


def assert_cli_prints_one_error_line_for_wrong_password() -> None:
    """`--report-uris keepass` with a wrong password exits 1 with one ERROR line."""
    original_cwd = Path.cwd()
    original_argv = sys.argv
    original_handlers = list(logging.getLogger().handlers)
    original_log_dir = os.environ.get("KP2BW_LOG_DIR")

    with tempfile.TemporaryDirectory(prefix="kp2bw-open-") as tmp_dir:
        db_path = str(Path(tmp_dir) / "vault.kdbx")
        _seed(db_path)

        try:
            os.chdir(tmp_dir)
            os.environ["KP2BW_LOG_DIR"] = tmp_dir
            sys.argv = [
                "kp2bw",
                db_path,
                "-k",
                WRONG_PASSWORD,
                "--report-uris",
                "keepass",
            ]
            exit_code: object = None
            with (
                mock.patch.object(cli, "ensure_bw_available", lambda: None),
                console.capture() as captured,
            ):
                try:
                    cli.main()
                except SystemExit as exc:
                    exit_code = exc.code
        finally:
            sys.argv = original_argv
            os.chdir(original_cwd)
            if original_log_dir is None:
                _ = os.environ.pop("KP2BW_LOG_DIR", None)
            else:
                os.environ["KP2BW_LOG_DIR"] = original_log_dir
            root = logging.getLogger()
            for handler in list(root.handlers):
                root.removeHandler(handler)
            for handler in original_handlers:
                root.addHandler(handler)

        output = captured.get()
        if exit_code != 1:
            raise AssertionError(f"expected exit code 1, got {exit_code!r}")
        if "Traceback" in output:
            raise AssertionError(f"CLI output must not contain a traceback:\n{output}")
        error_lines = [
            line for line in output.splitlines() if line.strip().startswith("ERROR:")
        ]
        if len(error_lines) != 1:
            raise AssertionError(f"expected exactly one ERROR line, got:\n{output}")
        if db_path not in error_lines[0]:
            raise AssertionError(f"ERROR line must name the database: {error_lines[0]}")
        for secret in (PASSWORD, WRONG_PASSWORD, "entry-secret"):
            if secret in output:
                raise AssertionError(f"CLI output leaked a secret:\n{output}")


def main() -> None:
    """Run the script-style assertions and report success."""
    assert_wrong_password_raises_conversion_error()
    assert_wrong_password_raises_conversion_error_for_uri_report()
    assert_missing_database_raises_conversion_error()
    assert_non_keepass_file_raises_conversion_error()
    assert_correct_password_still_opens_the_database()
    assert_cli_prints_one_error_line_for_wrong_password()
    print("convert keepass open test passed")


if __name__ == "__main__":
    main()
