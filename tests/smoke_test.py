import subprocess
import sys
from importlib.metadata import entry_points, files, version


def assert_distribution_files() -> None:
    dist_files = files("kp2bw")
    if dist_files is None:
        raise AssertionError("Could not read installed distribution files for kp2bw")

    available = {str(path) for path in dist_files}
    required = {
        "kp2bw/__init__.py",
        "kp2bw/bitwardenclient.py",
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
    from kp2bw import bitwardenclient, cli, convert, exceptions

    _ = bitwardenclient
    _ = cli
    _ = convert
    _ = exceptions

    installed_version = version("kp2bw")
    if kp2bw.__version__ != installed_version:
        raise AssertionError(
            f"kp2bw.__version__ ({kp2bw.__version__}) != metadata version ({installed_version})"
        )


def assert_cli_help() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "kp2bw", "-h"],
        check=False,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise AssertionError(
            "`python -m kp2bw -h` failed: "
            f"exit={result.returncode}, stderr={result.stderr.strip()}"
        )

    help_text = result.stdout.lower()
    if "usage:" not in help_text:
        raise AssertionError("CLI help output did not contain a usage section")


def main() -> None:
    assert_distribution_files()
    assert_console_script()
    assert_imports()
    assert_cli_help()
    print("smoke test passed")


if __name__ == "__main__":
    main()
