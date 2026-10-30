"""Exercise the release shell with synthetic registry and Docker commands."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

import yaml


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = cast(
        dict[str, Any],
        yaml.safe_load((root / ".github/workflows/container.yml").read_text()),
    )
    script = next(
        step["run"]
        for step in workflow["jobs"]["publish"]["steps"]
        if step.get("name") == "Publish the tested architectures without rebuilding"
    )
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        stub = (
            f"#!{sys.executable}\n"
            + """
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
if Path(sys.argv[0]).name == "curl":
    print('{"token":"synthetic"}' if '/token?' in args[-1] else os.environ['REGISTRY_STATUS'], end='')
else:
    with open(os.environ['DOCKER_LOG'], 'a') as output:
        output.write(json.dumps(args) + '\\n')
    if args[0] == 'login':
        _ = sys.stdin.read()
"""
        )
        for name in ("docker", "curl"):
            executable = work / name
            executable.write_text(stub)
            executable.chmod(0o755)
        vw = work / "vw"
        vw.write_text(
            f"#!{sys.executable}\nimport json, os, sys\nprint(json.dumps([sys.argv[1:], os.environ.get('VW_APPDATA_DIR'), os.environ.get('VW_SESSION')]))\n"
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
            expected_args = (
                ["--nointeraction", "login", "two words"]
                if noninteractive == "true"
                else ["login", "two words"]
            )
            assert json.loads(result.stdout) == [
                expected_args,
                str(work / "profile with spaces"),
                "synthetic-session",
            ]
        for version, stable, status in (
            ("3.8.4", "true", "404"),
            ("3.9.0rc1", "false", "404"),
            ("3.8.4", "true", "200"),
            ("3.8.4", "true", "503"),
        ):
            log = work / "commands.jsonl"
            log.write_text("")
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", script],
                cwd=work,
                env={
                    **os.environ,
                    "PATH": f"{work}:{os.environ['PATH']}",
                    "GH_TOKEN": "synthetic",
                    "GITHUB_ACTOR": "synthetic",
                    "GITHUB_REPOSITORY": "Synthetic/Images",
                    "GITHUB_RUN_ID": "123",
                    "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_STEP_SUMMARY": str(work / "summary"),
                    "VERSION": version,
                    "STABLE": stable,
                    "REGISTRY_STATUS": status,
                    "DOCKER_LOG": str(log),
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            commands = cast(
                list[list[str]],
                [json.loads(line) for line in log.read_text().splitlines()],
            )
            if status != "404":
                assert result.returncode != 0
                assert not commands, (
                    "Publication began without a successful no-overwrite check"
                )
                continue
            assert result.returncode == 0, result.stderr
            image = "ghcr.io/synthetic/images"
            tags: dict[str, list[str]] = {}
            for command in commands:
                if command[:3] != ["buildx", "imagetools", "create"]:
                    continue
                for index, arg in enumerate(command):
                    if arg == "--tag":
                        tags[command[index + 1].removeprefix(image + ":")] = command
            expected = {version, version + "-vw", version + "-bw"}
            if stable == "true":
                expected.update({
                    "latest",
                    "vw",
                    "bw",
                    "3",
                    "3.8",
                    "3-vw",
                    "3.8-vw",
                    "3-bw",
                    "3.8-bw",
                })
            assert set(tags) == expected
            assert tags[version][-1] == f"{image}:{version}-vw"
            if stable == "true":
                assert tags["latest"][-1] == f"{image}:{version}-vw"
                assert tags["bw"][-1] == f"{image}:{version}-bw"
            assert len([command for command in commands if command[0] == "load"]) == 4
            assert not any(command[0] == "build" for command in commands)
    print("container release tags, CLI variants and overwrite protection passed")


if __name__ == "__main__":
    main()
