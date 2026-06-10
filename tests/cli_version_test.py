"""`kp2bw --version` must print the program name, not the launcher's argv.

Python 3.14's argparse computes the default ``prog`` via ``_prog_name``: when
``__main__`` has a module spec (a packaged / console-script / zipapp launch, as
uv's trampoline produces) it returns ``f"{basename(sys.executable)} {argv[0]}"``
(e.g. ``python.exe C:\\...\\Scripts\\kp2bw``), which leaked into ``--version``,
usage, and error messages. Pinning ``prog="kp2bw"`` fixes it. This reproduces
that launch condition and checks the user-facing output through the public
entry point.
"""

import contextlib
import importlib.machinery
import io
import sys

from kp2bw import __version__, cli


def assert_version_prints_program_name_only() -> None:
    out = io.StringIO()
    main_mod = sys.modules["__main__"]
    original_argv = sys.argv
    original_spec = main_mod.__spec__
    # A module spec on __main__ + a script-path argv[0] is exactly the packaged
    # launch where 3.14 argparse prefixes basename(sys.executable) into prog.
    main_mod.__spec__ = importlib.machinery.ModuleSpec("__main__", None)
    sys.argv = [r"C:\venv\Scripts\kp2bw", "--version"]
    try:
        with contextlib.redirect_stdout(out):
            cli.main()
    except SystemExit as exc:
        if exc.code not in (0, None):
            raise AssertionError(f"--version must exit 0, got {exc.code!r}") from None
    else:
        raise AssertionError("--version must exit via SystemExit")
    finally:
        sys.argv = original_argv
        main_mod.__spec__ = original_spec

    printed = out.getvalue().strip()
    if printed != f"kp2bw {__version__}":
        raise AssertionError(
            f"expected 'kp2bw {__version__}', got {printed!r} "
            "(argparse leaked the launcher argv into prog)"
        )


def main() -> None:
    assert_version_prints_program_name_only()
    print("cli version test passed")


if __name__ == "__main__":
    main()
