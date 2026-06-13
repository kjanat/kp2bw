import os
import runpy
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).resolve().parent


def _run_script_main(script_name: str) -> None:
    module_globals = runpy.run_path(str(_TESTS_DIR / script_name))
    main = module_globals.get("main")
    if not callable(main):
        raise TypeError(f"{script_name} does not expose callable main()")
    main()


def test_bw_serve_sanitization_script() -> None:
    _run_script_main("bw_serve_sanitization_test.py")


def test_bw_serve_attachment_script() -> None:
    _run_script_main("bw_serve_attachment_test.py")


def test_bw_serve_bw_missing_script() -> None:
    _run_script_main("bw_serve_bw_missing_test.py")


def test_bw_serve_command_script() -> None:
    _run_script_main("bw_serve_command_test.py")


def test_bw_serve_batch_script() -> None:
    _run_script_main("bw_serve_batch_test.py")


def test_bw_serve_timeout_script() -> None:
    _run_script_main("bw_serve_timeout_test.py")


def test_strip_ids_script() -> None:
    _run_script_main("strip_ids_test.py")


def test_uri_mapping_script() -> None:
    _run_script_main("uri_mapping_test.py")


def test_migrate_uris_script() -> None:
    _run_script_main("migrate_uris_test.py")


def test_otp_script() -> None:
    _run_script_main("otp_test.py")


def test_cli_env_script() -> None:
    _run_script_main("cli_env_test.py")


def test_cli_logging_script() -> None:
    _run_script_main("cli_logging_test.py")


def test_cli_version_script() -> None:
    _run_script_main("cli_version_test.py")


def test_convert_ref_resolution_script() -> None:
    _run_script_main("convert_ref_resolution_test.py")


def test_convert_update_script() -> None:
    _run_script_main("convert_update_test.py")


def test_convert_resilience_script() -> None:
    _run_script_main("convert_resilience_test.py")


def test_windows_bw_cmd_smoke_script() -> None:
    if os.name != "nt":
        pytest.skip("windows bw .cmd smoke runs on Windows only")
    if os.environ.get("KP2BW_RUN_WIN_CMD_SMOKE") != "1":
        pytest.skip("set KP2BW_RUN_WIN_CMD_SMOKE=1 to run the Windows bw .cmd smoke")
    _run_script_main("windows_bw_cmd_smoke.py")


def test_smoke_script() -> None:
    if os.environ.get("KP2BW_RUN_PACKAGING_TESTS") != "1":
        pytest.skip("set KP2BW_RUN_PACKAGING_TESTS=1 to run packaging smoke tests")
    _run_script_main("smoke_test.py")


def test_stubs_smoke_script() -> None:
    if os.environ.get("KP2BW_RUN_PACKAGING_TESTS") != "1":
        pytest.skip("set KP2BW_RUN_PACKAGING_TESTS=1 to run packaging smoke tests")
    _run_script_main("stubs_smoke_test.py")


def test_e2e_vaultwarden_script() -> None:
    if os.environ.get("KP2BW_RUN_E2E_TESTS") != "1":
        pytest.skip("set KP2BW_RUN_E2E_TESTS=1 to run vaultwarden e2e")
    _run_script_main("e2e_vaultwarden_test.py")
