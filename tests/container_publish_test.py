"""Exercise publication retries and alias promotion without registry writes."""

import importlib.util
import json
import os
import tempfile
from pathlib import Path
from types import ModuleType
from unittest.mock import patch


def load_script(name: str) -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    images = load_script("release_images")
    release = load_script("release")
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        # Identical partial publication is resumable; different version bytes fail.
        for previous in (None, "sha256:expected", "sha256:different"):

            def command(*args: str) -> str:
                return "sha256:expected" if args[:2] == ("crane", "digest") else ""

            with (
                patch.dict(
                    os.environ,
                    {"GITHUB_RUN_ID": "123", "GITHUB_OUTPUT": str(work / "output")},
                ),
                patch.object(images, "run", side_effect=command) as commands,
                patch.object(images, "remote_digest", return_value=previous),
                patch.object(images.Path, "write_text"),
            ):
                try:
                    images.publish(work, "ghcr.io/example/image", "3.9.0")
                except RuntimeError:
                    assert previous == "sha256:different"
                    assert not any(
                        c.args[:2] == ("crane", "tag") for c in commands.call_args_list
                    )
                else:
                    assert previous != "sha256:different"
                    promoted = [
                        c.args[-1]
                        for c in commands.call_args_list
                        if c.args[:2] == ("crane", "tag")
                    ]
                    assert promoted == (
                        ["3.9.0-vw", "3.9.0-bw", "3.9.0"] if previous is None else []
                    )
                    assert not any(
                        c.args[:2] == ("docker", "build")
                        for c in commands.call_args_list
                    )
        for stable in ("true", "false"):
            with (
                patch.dict(os.environ, {"STABLE": stable}),
                patch.object(images, "run") as commands,
                patch.object(images, "remote_digest", return_value=None),
            ):
                images.promote(
                    "ghcr.io/example/image",
                    "3.9.0",
                    {"vw": "sha256:vw", "bw": "sha256:bw"},
                )
                if stable == "false":
                    commands.assert_not_called()
                else:
                    targets = {c.args[-1]: c.args[-2] for c in commands.call_args_list}
                    assert targets["latest"] == "ghcr.io/example/image@sha256:vw"
                    assert targets["bw"] == "ghcr.io/example/image@sha256:bw"
                    assert set(targets) == {
                        "latest",
                        "vw",
                        "bw",
                        "3",
                        "3.9",
                        "3-vw",
                        "3.9-vw",
                        "3-bw",
                        "3.9-bw",
                    }
        with (
            patch.dict(os.environ, {"STABLE": "true"}),
            patch.object(images, "remote_digest", return_value="sha256:newer"),
            patch.object(
                images,
                "run",
                return_value=json.dumps({
                    "config": {"Labels": {"org.opencontainers.image.version": "4.0.0"}}
                }),
            ) as commands,
        ):
            try:
                images.promote(
                    "ghcr.io/example/image",
                    "3.9.0",
                    {"vw": "sha256:vw", "bw": "sha256:bw"},
                )
            except RuntimeError:
                pass
            else:
                raise AssertionError("Older version could replace latest")
            assert not any(
                c.args[:2] == ("crane", "tag") for c in commands.call_args_list
            )
        for remote, expected in (
            ("abc\trefs/tags/v3.9.0", True),
            ("different\trefs/tags/v3.9.0", False),
            ("", False),
        ):
            with (
                patch.dict(os.environ, {"VERSION": "3.9.0", "GITHUB_SHA": "abc"}),
                patch.object(release, "run", return_value=remote),
            ):
                try:
                    release.verify_tag()
                except RuntimeError:
                    assert not expected
                else:
                    assert expected
        # Existing draft assets may be reused but never silently clobbered.
        file = work / "package.whl"
        file.write_bytes(b"tested wheel")
        for identical in (True, False):

            def download(*args: str, identical: bool = identical) -> str:
                Path(args[-1], file.name).write_bytes(
                    file.read_bytes() if identical else b"other wheel"
                )
                return ""

            with (
                patch.dict(os.environ, {"VERSION": "3.9.0"}),
                patch.object(
                    release,
                    "release",
                    return_value={"draft": True, "assets": [{"name": file.name}]},
                ),
                patch.object(release, "run", side_effect=download) as commands,
            ):
                try:
                    release.upload([file])
                except RuntimeError:
                    assert not identical
                else:
                    assert identical
                assert all(
                    c.args[:3] == ("gh", "release", "download")
                    for c in commands.call_args_list
                )
        with (
            patch.object(release, "release", return_value={"draft": False}),
            patch.object(release, "run") as commands,
        ):
            try:
                release.upload([file])
            except RuntimeError:
                pass
            else:
                raise AssertionError("Public release assets could be changed")
            commands.assert_not_called()
        draft_release: dict[str, object] = {
            "tag_name": "v3.9.0",
            "draft": True,
            "prerelease": False,
            "target_commitish": "abc",
            "assets": [],
        }
        lookups: dict[str, dict[str, object] | type[RuntimeError] | None] = {
            "": None,
            json.dumps(draft_release): draft_release,
            json.dumps(draft_release) + "\n" + json.dumps(draft_release): RuntimeError,
        }
        for output, expected in lookups.items():
            with (
                patch.dict(
                    os.environ,
                    {"VERSION": "3.9.0", "GITHUB_REPOSITORY": "example/repository"},
                ),
                patch.object(release, "run", return_value=output) as commands,
            ):
                try:
                    found = release.find_release()
                except RuntimeError:
                    assert expected is RuntimeError
                else:
                    assert found == expected
                assert commands.call_args.args[:5] == (
                    "gh",
                    "api",
                    "--paginate",
                    "repos/example/repository/releases",
                    "--jq",
                )
                assert '"v3.9.0"' in commands.call_args.args[5]
        source = work / "source"
        (source / ".github" / "release-notes").mkdir(parents=True)
        (source / "CHANGELOG.md").write_text("## [3.9.0] - 2026-10-31\n\n- Change\n")
        (source / ".github" / "release-notes" / "v3.9.0.md").write_text("Notes\n")
        original = Path.cwd()
        for existing in (draft_release, None):
            try:
                os.chdir(source)
                with (
                    patch.dict(
                        os.environ,
                        {
                            "VERSION": "3.9.0",
                            "GITHUB_SHA": "abc",
                            "GITHUB_REPOSITORY": "example/repository",
                            "GITHUB_RUN_ID": "123",
                            "STABLE": "true",
                        },
                    ),
                    patch.object(release, "verify_tag"),
                    patch.object(
                        release, "find_release", side_effect=[existing, draft_release]
                    ),
                    patch.object(release, "run") as commands,
                    patch.object(release, "upload") as uploads,
                ):
                    release.draft()
            finally:
                os.chdir(original)
            created = [
                c.args
                for c in commands.call_args_list
                if c.args[:3] == ("gh", "release", "create")
            ]
            assert len(created) == (0 if existing else 1)
            uploads.assert_called_once()
    print("publication retries, immutable assets and aliases passed")


if __name__ == "__main__":
    main()
