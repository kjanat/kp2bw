"""Stage, verify and finalize a release without rebuilding published artifacts."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def find_release() -> dict[str, Any] | None:
    tag = f"v{os.environ['VERSION']}"
    # GitHub's releases/tags endpoint returns 404 for draft releases.
    output = run(
        "gh",
        "api",
        "--paginate",
        f"repos/{os.environ['GITHUB_REPOSITORY']}/releases",
        "--jq",
        f".[] | select(.tag_name == {json.dumps(tag)})",
    )
    matches: list[dict[str, Any]] = [json.loads(line) for line in output.splitlines()]
    if len(matches) > 1:
        raise RuntimeError(f"Several releases use {tag}; keep one")
    return matches[0] if matches else None


def release() -> dict[str, Any]:
    current = find_release()
    if current is None:
        raise RuntimeError("Release is missing")
    return current


def upload(paths: list[Path]) -> None:
    """Never replace a release asset; retries must have identical bytes."""
    current = release()
    if not current["draft"]:
        raise RuntimeError("Refusing to change assets of a public release")
    names = {asset["name"] for asset in current["assets"]}
    for path in paths:
        if path.name in names:
            with tempfile.TemporaryDirectory() as directory:
                run(
                    "gh",
                    "release",
                    "download",
                    f"v{os.environ['VERSION']}",
                    "--pattern",
                    path.name,
                    "--dir",
                    directory,
                )
                if digest(Path(directory) / path.name) != digest(path):
                    raise RuntimeError(
                        f"Release asset differs: {path.name}; resume the original run"
                    )
        else:
            run("gh", "release", "upload", f"v{os.environ['VERSION']}", str(path))


def verify_tag() -> None:
    tag = f"v{os.environ['VERSION']}"
    refs = run(
        "git", "ls-remote", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"
    ).splitlines()
    if not refs or refs[-1].split()[0] != os.environ["GITHUB_SHA"]:
        raise RuntimeError("Release tag is missing or points to another commit")


def draft() -> None:
    version = os.environ["VERSION"]
    sha = os.environ["GITHUB_SHA"]
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?", version):
        raise RuntimeError("Unsupported release version")
    tag = f"v{version}"
    verify_tag()
    if find_release() is None:
        changelog = Path("CHANGELOG.md").read_text()
        marker = f"## [{version}] - "
        if marker not in changelog:
            raise RuntimeError("Versioned changelog section is missing")
        notes = (
            changelog
            .split(marker, 1)[1]
            .split("\n", 1)[1]
            .split("\n## [", 1)[0]
            .strip()
        )
        if not notes:
            raise RuntimeError("Release notes are empty")
        curated = Path(".github/release-notes") / f"{tag}.md"
        if curated.exists():
            notes = curated.read_text().strip()
        else:
            badge = (
                Path("README.md")
                .read_text()
                .split('<a href="https://pypi.org/project/kp2bw/">', 1)[1]
                .split("</a>", 1)[0]
            )
            badge = (
                '<a href="https://pypi.org/project/kp2bw/'
                + version
                + '/">'
                + badge
                + "</a>"
            )
            badge = badge.replace(
                "https://img.shields.io/pypi/v/kp2bw?",
                f"https://img.shields.io/badge/pypi-{version}-3775A9?",
            )
            generated = json.loads(
                run(
                    "gh",
                    "api",
                    "--method",
                    "POST",
                    f"repos/{os.environ['GITHUB_REPOSITORY']}/releases/generate-notes",
                    "-f",
                    f"tag_name={tag}",
                    "-f",
                    f"target_commitish={sha}",
                )
            )
            notes = (
                badge
                + "\n\n"
                + notes.replace("### ", "## ")
                + "\n\n"
                + generated["body"]
            )
        if not notes:
            raise RuntimeError("Release notes are empty")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "notes.md"
            path.write_text(notes + "\n")
            args = [
                "gh",
                "release",
                "create",
                tag,
                "--draft",
                "--target",
                sha,
                "--title",
                f"kp2bw {version}",
                "--notes-file",
                str(path),
            ]
            if os.environ["STABLE"] != "true":
                args.append("--prerelease")
            run(*args)
    current = release()
    if not current["draft"] or current["target_commitish"] != sha:
        raise RuntimeError("Release is public or belongs to another commit")
    if current["prerelease"] != (os.environ["STABLE"] != "true"):
        raise RuntimeError("Release stability does not match the requested version")
    path = Path("release-source.json")
    path.write_text(
        json.dumps(
            {"commit": sha, "version": version, "run": os.environ["GITHUB_RUN_ID"]},
            sort_keys=True,
        )
        + "\n"
    )
    upload([path])


def stage(directory: Path, manifest_name: str) -> None:
    files = sorted(
        p for p in directory.iterdir() if p.is_file() and p.name != manifest_name
    )
    manifest = directory / manifest_name
    manifest.write_text(
        json.dumps({p.name: digest(p) for p in files}, indent=2, sort_keys=True) + "\n"
    )
    upload([*files, manifest])


def check_pypi(directory: Path) -> None:
    """Reject a partial release with conflicting bytes before another upload."""
    try:
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/kp2bw/{os.environ['VERSION']}/json", timeout=30
        ) as response:
            metadata = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return
        raise
    remote = {
        entry["filename"]: entry["digests"]["sha256"] for entry in metadata["urls"]
    }
    for path in directory.iterdir():
        if path.name in remote and remote[path.name] != digest(path):
            raise RuntimeError(f"PyPI already contains different bytes for {path.name}")


def verify_pypi(directory: Path) -> None:
    """Verify anonymous downloads, including propagation delay after upload."""
    expected = {
        p.name: digest(p)
        for p in directory.iterdir()
        if p.suffix == ".whl" or p.name.endswith(".tar.gz")
    }
    if len(expected) != 2:
        raise RuntimeError("Expected a wheel and a source distribution")
    url = f"https://pypi.org/pypi/kp2bw/{os.environ['VERSION']}/json"
    for attempt in range(30):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                metadata = json.load(response)
            remote = {entry["filename"]: entry for entry in metadata["urls"]}
            if not expected.keys() <= remote.keys():
                raise LookupError("PyPI files are still propagating")
            for name, checksum in expected.items():
                if remote[name]["digests"]["sha256"] != checksum:
                    raise RuntimeError(f"PyPI has different bytes for {name}")
                with urllib.request.urlopen(
                    remote[name]["url"], timeout=60
                ) as response:
                    actual = hashlib.file_digest(response, "sha256").hexdigest()
                if actual != checksum:
                    raise RuntimeError(f"PyPI download differs: {name}")
            return
        except urllib.error.HTTPError as exc:
            if exc.code != 404 and exc.code < 500:
                raise
        except urllib.error.URLError, TimeoutError, LookupError:
            pass
        if attempt < 29:
            time.sleep(10)
    raise RuntimeError("PyPI files did not become publicly available")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=["draft", "stage", "verify-pypi", "check-pypi", "finalize"]
    )
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    parser.add_argument("--manifest", default="distribution-sha256.json")
    args = parser.parse_args()
    if args.command == "draft":
        draft()
    elif args.command == "stage":
        stage(args.directory, args.manifest)
    elif args.command == "check-pypi":
        check_pypi(args.directory)
    elif args.command == "verify-pypi":
        verify_pypi(args.directory)
    else:
        verify_tag()
        current = release()
        if current["target_commitish"] != os.environ["GITHUB_SHA"]:
            raise RuntimeError("Release commit changed")
        # An exact retry after publishing the draft is harmless.
        if current["draft"]:
            run(
                "gh",
                "release",
                "edit",
                f"v{os.environ['VERSION']}",
                "--draft=false",
                "--latest=" + os.environ["STABLE"],
            )


if __name__ == "__main__":
    main()
