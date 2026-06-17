import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import ClassVar
from unittest import mock

from kp2bw import cli

# Environment kp2bw reads; every key is saved and restored around the run.
_MANAGED_ENV = (
    "KP2BW_KEEPASS_FILE",
    "KP2BW_KEEPASS_PASSWORD",
    "KP2BW_BITWARDEN_PASSWORD",
    "KP2BW_CREATE_FOLDERS",
    "KP2BW_YES",
    "KP2BW_LOG_DIR",
)


class _CapturingConverter:
    """Stand-in for the real Converter that records its constructor kwargs."""

    captured: ClassVar[dict[str, object]] = {}

    def __init__(self, **kwargs: object) -> None:
        type(self).captured = dict(kwargs)

    def convert(self) -> int:
        return 0


def _reset_root_logging(keep: list[logging.Handler]) -> None:
    """Detach and close only the handlers ``main()`` added to the root logger.

    Snapshot the root handlers (*keep*) before ``cli.main()`` runs, then remove
    just the file handler it adds.  Handlers present beforehand -- notably
    pytest's log-capture handler -- are left intact so this teardown never
    strips a framework handler the test did not install.
    """
    root = logging.getLogger()
    kept = set(keep)
    for handler in list(root.handlers):
        if handler in kept:
            continue
        root.removeHandler(handler)
        handler.close()


def assert_dotenv_supplies_keepass_file() -> None:
    """A `.env` in the CWD auto-loads and its KP2BW_KEEPASS_FILE drives the run.

    Exercises the whole new path end to end through the public entry point:
    dotenv autoload -> KP2BW_KEEPASS_FILE -> optional positional fallback ->
    Converter(keepass_file_path=...).
    """
    original_cwd = Path.cwd()
    original_argv = sys.argv
    # Snapshot root handlers before main() adds its file handler, so teardown
    # removes only what main() installed and leaves pytest's capture intact.
    original_handlers = list(logging.getLogger().handlers)
    saved_env = {key: os.environ.get(key) for key in _MANAGED_ENV}

    tmp = tempfile.mkdtemp()
    try:
        # The db path comes ONLY from .env; secrets/flags go through the real
        # environment so getpass, the confirm prompt and the bw availability
        # check never block. KP2BW_KEEPASS_FILE must be absent so .env supplies it.
        _ = os.environ.pop("KP2BW_KEEPASS_FILE", None)
        os.environ["KP2BW_KEEPASS_PASSWORD"] = "kp-pw"
        os.environ["KP2BW_BITWARDEN_PASSWORD"] = "bw-pw"
        os.environ["KP2BW_CREATE_FOLDERS"] = "0"
        os.environ["KP2BW_YES"] = "1"
        os.environ["KP2BW_LOG_DIR"] = tmp  # keep the run's log inside the temp dir

        _ = (Path(tmp) / ".env").write_text(
            "KP2BW_KEEPASS_FILE=from-dotenv.kdbx\n", encoding="utf-8"
        )
        os.chdir(tmp)

        sys.argv = ["kp2bw"]
        # Neutralize the side-effecting downstream: no real bw, no real migration.
        # patch.object auto-restores both names when the block exits.
        with (
            mock.patch.object(cli, "ensure_bw_available", lambda: None),
            mock.patch.object(cli, "Converter", _CapturingConverter),
        ):
            cli.main()

        db_path = _CapturingConverter.captured.get("keepass_file_path")
        if db_path != "from-dotenv.kdbx":
            raise AssertionError(f"expected db path from .env, got {db_path!r}")
        if _CapturingConverter.captured.get("create_folders") is not False:
            raise AssertionError("KP2BW_CREATE_FOLDERS=0 should disable folders")
    finally:
        sys.argv = original_argv
        # Release the log file (so rmtree works on Windows) without stripping
        # the framework handlers present before the test.
        _reset_root_logging(original_handlers)
        os.chdir(original_cwd)
        shutil.rmtree(tmp, ignore_errors=True)
        for key, value in saved_env.items():
            if value is None:
                _ = os.environ.pop(key, None)
            else:
                os.environ[key] = value


def assert_empty_env_var_defers_to_dotenv() -> None:
    """An empty exported var must not shadow a .env value; a non-empty one wins.

    Regression: `KP2BW_KEEPASS_FILE=""` in the environment used to shadow the
    .env entry (load_dotenv override=False treats empty as "set"), producing a
    baffling "db required". `_load_dotenv` now fills keys that are unset *or
    empty* from the file while leaving non-empty exports untouched.
    """
    original_cwd = Path.cwd()
    saved = os.environ.get("KP2BW_KEEPASS_FILE")
    tmp = tempfile.mkdtemp()
    try:
        _ = (Path(tmp) / ".env").write_text(
            "KP2BW_KEEPASS_FILE=from-dotenv.kdbx\n", encoding="utf-8"
        )
        os.chdir(tmp)

        # Empty export -> .env wins.
        os.environ["KP2BW_KEEPASS_FILE"] = ""
        _ = cli._load_dotenv()
        if os.environ.get("KP2BW_KEEPASS_FILE") != "from-dotenv.kdbx":
            raise AssertionError(
                f"empty export should defer to .env, got "
                f"{os.environ.get('KP2BW_KEEPASS_FILE')!r}"
            )

        # Non-empty export -> still wins over .env.
        os.environ["KP2BW_KEEPASS_FILE"] = "/real/shell/override.kdbx"
        _ = cli._load_dotenv()
        if os.environ.get("KP2BW_KEEPASS_FILE") != "/real/shell/override.kdbx":
            raise AssertionError("non-empty export must win over .env")
    finally:
        os.chdir(original_cwd)
        if saved is None:
            _ = os.environ.pop("KP2BW_KEEPASS_FILE", None)
        else:
            os.environ["KP2BW_KEEPASS_FILE"] = saved
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> None:
    assert_dotenv_supplies_keepass_file()
    assert_empty_env_var_defers_to_dotenv()
    print("cli env test passed")


if __name__ == "__main__":
    main()
