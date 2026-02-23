import pathlib
import subprocess
import tempfile
from importlib.metadata import files


def assert_distribution_files() -> None:
    dist_files = files("pykeepass-stubs")
    if dist_files is None:
        raise AssertionError(
            "Could not read installed distribution files for pykeepass-stubs"
        )

    available = {str(path) for path in dist_files}
    required = {
        "pykeepass-stubs/__init__.pyi",
        "pykeepass-stubs/attachment.pyi",
        "pykeepass-stubs/baseelement.pyi",
        "pykeepass-stubs/entry.pyi",
        "pykeepass-stubs/group.pyi",
        "pykeepass-stubs/pykeepass.pyi",
        "pykeepass-stubs/py.typed",
    }
    missing = sorted(required - available)
    if missing:
        raise AssertionError(f"Installed distribution is missing files: {missing}")


def assert_partial_marker() -> None:
    dist_files = files("pykeepass-stubs")
    if dist_files is None:
        raise AssertionError(
            "Could not read installed distribution files for pykeepass-stubs"
        )

    marker_path = next(
        (
            path.locate()
            for path in dist_files
            if str(path) == "pykeepass-stubs/py.typed"
        ),
        None,
    )
    if marker_path is None:
        raise AssertionError("Could not locate pykeepass-stubs/py.typed")

    marker = pathlib.Path(marker_path).read_text(encoding="utf8")

    if "partial" not in marker:
        raise AssertionError(
            "pykeepass-stubs/py.typed must contain the 'partial' marker"
        )


def assert_basedpyright_uses_stubs() -> None:
    sample = """# pyright: strict
from pykeepass import PyKeePass


def bad_return_type(db: PyKeePass) -> str:
    return db.entries
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        sample_path = pathlib.Path(tmpdir) / "sample.py"
        sample_path.write_text(sample, encoding="utf8")

        result = subprocess.run(
            ["basedpyright", str(sample_path)],
            check=False,
            capture_output=True,
            text=True,
            cwd=tmpdir,
        )

    output = f"{result.stdout}\n{result.stderr}"
    if result.returncode == 0:
        raise AssertionError(
            "basedpyright should fail for the deliberate return-type mismatch"
        )

    if 'Stub file not found for "pykeepass"' in output:
        raise AssertionError("basedpyright did not detect pykeepass-stubs")

    if "list[Entry]" not in output:
        raise AssertionError(
            "basedpyright output did not include expected typed detail from stubs"
        )


def main() -> None:
    assert_distribution_files()
    assert_partial_marker()
    assert_basedpyright_uses_stubs()
    print("stubs smoke test passed")


if __name__ == "__main__":
    main()
