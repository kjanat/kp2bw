import subprocess
import sys
import sysconfig
from importlib.metadata import entry_points, files, version
from pathlib import Path


def assert_distribution_files() -> None:
    dist_files = files("kp2bw")
    if dist_files is None:
        raise AssertionError("Could not read installed distribution files for kp2bw")

    available = {str(path) for path in dist_files}
    required = {
        "kp2bw/__init__.py",
        "kp2bw/cli.py",
        "kp2bw/convert.py",
        "kp2bw/py.typed",
    }
    missing = sorted(required - available)
    if missing:
        raise AssertionError(f"Installed distribution is missing files: {missing}")


def assert_console_script() -> None:
    scripts = {ep.name: ep.value for ep in entry_points(group="console_scripts")}
    if scripts.get("kp2bw") != "kp2bw.cli:main":
        raise AssertionError(
            "Console script 'kp2bw' is missing or points to wrong entry point"
        )


def assert_imports() -> None:
    import kp2bw
    from kp2bw import cli, convert, exceptions

    _ = cli
    _ = convert
    _ = exceptions

    installed_version = version("kp2bw")
    if kp2bw.__version__ != installed_version:
        raise AssertionError(
            f"kp2bw.__version__ ({kp2bw.__version__}) != metadata version ({installed_version})"
        )


def assert_cli_help() -> None:
    script = Path(sysconfig.get_path("scripts")) / (
        "kp2bw.exe" if sys.platform == "win32" else "kp2bw"
    )
    for command in ([str(script)], [sys.executable, "-m", "kp2bw"]):
        result = subprocess.run(
            [*command, "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0 or "usage:" not in result.stdout.lower():
            raise AssertionError(
                f"{command} --help failed: "
                f"exit={result.returncode}, stderr={result.stderr.strip()}"
            )


def main() -> None:
    assert_distribution_files()
    assert_console_script()
    assert_imports()
    assert_cli_help()
    print("smoke test passed")


if __name__ == "__main__":
    main()
