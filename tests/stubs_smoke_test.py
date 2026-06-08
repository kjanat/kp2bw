import pathlib
import subprocess
import tempfile
from importlib.metadata import PackagePath, files


def _distribution_files() -> list[PackagePath]:
    dist_files = files("pykeepass-stubs")
    if dist_files is None:
        raise AssertionError(
            "Could not read installed distribution files for pykeepass-stubs"
        )

    return list(dist_files)


def _editable_source_roots(dist_files: list[PackagePath]) -> list[pathlib.Path]:
    source_roots: list[pathlib.Path] = []

    for dist_file in dist_files:
        if not str(dist_file).endswith(".pth"):
            continue

        pth_path = pathlib.Path(dist_file.locate())
        for raw_line in pth_path.read_text(encoding="utf8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", "import ")):
                continue

            source_root = pathlib.Path(line)
            if not source_root.is_absolute():
                source_root = pth_path.parent / source_root
            if source_root.is_dir():
                source_roots.append(source_root)

    return source_roots


def _available_files(dist_files: list[PackagePath]) -> set[str]:
    available = {str(path) for path in dist_files}

    for source_root in _editable_source_roots(dist_files):
        available.update(
            path.relative_to(source_root).as_posix()
            for path in source_root.rglob("*")
            if path.is_file()
        )

    return available


def _locate_distribution_file(file_name: str) -> pathlib.Path | None:
    dist_files = _distribution_files()

    for dist_file in dist_files:
        if str(dist_file) == file_name:
            located_file = pathlib.Path(dist_file.locate())
            if located_file.is_file():
                return located_file

    for source_root in _editable_source_roots(dist_files):
        located_file = source_root / file_name
        if located_file.is_file():
            return located_file

    return None


def assert_distribution_files() -> None:
    available = _available_files(_distribution_files())
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
    marker_path = _locate_distribution_file("pykeepass-stubs/py.typed")
    if marker_path is None:
        raise AssertionError("Could not locate pykeepass-stubs/py.typed")

    marker = marker_path.read_text(encoding="utf8")

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
