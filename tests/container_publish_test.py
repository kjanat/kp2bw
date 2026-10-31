"""Exercise publication retries and alias promotion without registry writes."""

import importlib.util
import json
import os
import subprocess
import sys
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
    root = Path(__file__).resolve().parents[1]
    images = load_script("release_images")
    release = load_script("release")
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        vw = work / "vw"
        vw.write_text(
            f'#!{sys.executable}\nimport json, os, sys\nprint(json.dumps([sys.argv[1:], os.environ.get("VW_APPDATA_DIR"), os.environ.get("VW_SESSION")]))\n'
        )
        vw.chmod(0o755)
        for noninteractive in ("true", "false"):
            result = subprocess.run(
                ["sh", str(root / "scripts/vw-bw.sh"), "login", "two words"],
                env={
                    **os.environ,
                    "PATH": f"{work}:{os.environ['PATH']}",
                    "BITWARDENCLI_APPDATA_DIR": str(work / "profile with spaces"),
                    "BW_SESSION": "synthetic-session",
                    "BW_NOINTERACTION": noninteractive,
                },
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            expected = (
                ["--nointeraction", "login", "two words"]
                if noninteractive == "true"
                else ["login", "two words"]
            )
            assert json.loads(result.stdout) == [
                expected,
                str(work / "profile with spaces"),
                "synthetic-session",
            ]
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
    print("publication retries, immutable assets, CLI adapters and aliases passed")


if __name__ == "__main__":
    main()
