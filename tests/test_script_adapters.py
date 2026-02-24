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
