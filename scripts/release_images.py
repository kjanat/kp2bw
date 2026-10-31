"""Publish tested image archives, verify public access, then promote aliases."""

import argparse
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def remote_digest(reference: str) -> str | None:
    result = subprocess.run(
        ["crane", "digest", reference], capture_output=True, text=True, check=False
    )
    if result.returncode == 0:
        return result.stdout.strip()
    if "MANIFEST_UNKNOWN" in result.stderr or "404" in result.stderr:
        return None
    raise RuntimeError(f"Cannot inspect registry reference {reference}")


def publish(directory: Path, image: str, version: str) -> None:
    manifests = {}
    for cli in ("vw", "bw"):
        tags = []
        for arch in ("amd64", "arm64"):
            run(
                "docker",
                "load",
                "--input",
                str(directory / f"container-{cli}-{arch}.tar"),
            )
            tag = f"{image}:build-{os.environ['GITHUB_RUN_ID']}-{cli}-{arch}"
            run("docker", "tag", f"kp2bw-production:{cli}-{arch}", tag)
            run("docker", "push", tag)
            tags.append(tag)
        candidate = f"{image}:build-{os.environ['GITHUB_RUN_ID']}-{cli}"
        run("docker", "buildx", "imagetools", "create", "--tag", candidate, *tags)
        checksum = run("crane", "digest", candidate)
        target = f"{image}:{version}-{cli}"
        previous = remote_digest(target)
        if previous is not None and previous != checksum:
            raise RuntimeError(f"Refusing to overwrite different image {target}")
        if previous is None:
            run("crane", "tag", f"{image}@{checksum}", f"{version}-{cli}")
        manifests[cli] = checksum
    previous = remote_digest(f"{image}:{version}")
    if previous is not None and previous != manifests["vw"]:
        raise RuntimeError("Unsuffixed version already identifies a different image")
    if previous is None:
        run("crane", "tag", f"{image}@{manifests['vw']}", version)
    Path("image-digests.json").write_text(json.dumps(manifests, sort_keys=True) + "\n")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        for cli, checksum in manifests.items():
            output.write(f"{cli}={checksum}\n")


def verify(image: str, version: str, manifests: dict[str, str]) -> None:
    # Do not inherit the publication login: users must be able to pull publicly.
    with tempfile.TemporaryDirectory() as directory:
        env = {**os.environ, "DOCKER_CONFIG": directory}
        for suffix, checksum in [
            ("-vw", manifests["vw"]),
            ("-bw", manifests["bw"]),
            ("", manifests["vw"]),
        ]:
            reference = f"{image}:{version}{suffix}"
            for attempt in range(30):
                result = subprocess.run(
                    ["crane", "digest", reference],
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if result.returncode == 0:
                    if result.stdout.strip() != checksum:
                        raise RuntimeError(f"Published digest differs: {reference}")
                    break
                if attempt == 29:
                    raise RuntimeError(
                        f"Image is not publicly available: {reference}; check package visibility"
                    )
                time.sleep(10)
        for checksum in manifests.values():
            for arch in ("amd64", "arm64"):
                subprocess.run(
                    [
                        "docker",
                        "--config",
                        directory,
                        "pull",
                        "--platform",
                        f"linux/{arch}",
                        f"{image}@{checksum}",
                    ],
                    check=True,
                    timeout=300,
                )


def promote(image: str, version: str, manifests: dict[str, str]) -> None:
    if os.environ["STABLE"] != "true":
        return
    current = remote_digest(f"{image}:latest")
    if current is not None:
        config = json.loads(
            run("crane", "config", "--platform", "linux/amd64", f"{image}@{current}")
        )
        installed = config["config"]["Labels"]["org.opencontainers.image.version"]
        if tuple(map(int, installed.split("."))) > tuple(map(int, version.split("."))):
            raise RuntimeError("Refusing to move stable aliases to an older release")
    major, minor, _ = version.split(".")
    for cli, checksum in manifests.items():
        for tag in (cli, f"{major}-{cli}", f"{major}.{minor}-{cli}"):
            run("crane", "tag", f"{image}@{checksum}", tag)
    for tag in ("latest", major, f"{major}.{minor}"):
        run("crane", "tag", f"{image}@{manifests['vw']}", tag)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["publish", "verify", "promote"])
    parser.add_argument("--directory", type=Path, default=Path("images"))
    args = parser.parse_args()
    image = "ghcr.io/" + os.environ["GITHUB_REPOSITORY"].lower()
    version = os.environ["VERSION"]
    if args.command == "publish":
        publish(args.directory, image, version)
    else:
        manifests = json.loads(Path("image-digests.json").read_text())
        if args.command == "verify":
            verify(image, version, manifests)
        else:
            promote(image, version, manifests)


if __name__ == "__main__":
    main()
