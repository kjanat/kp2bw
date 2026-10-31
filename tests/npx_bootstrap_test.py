"""Bootstrap real Vaultwarden CLI outside a hostile project, without a vault."""

import os
import re
import tempfile
from pathlib import Path
from unittest.mock import patch

from kp2bw import bw_serve, cli
from kp2bw.bw_serve import BitwardenServeClient


def main() -> None:
    original_cwd = Path.cwd()
    real_lookup = bw_serve.find_cli_executable
    assert any(real_lookup(name) for name in ("npx", "npx.cmd", "npx.exe"))

    def only_npx(name: str) -> str | None:
        return real_lookup(name) if name.startswith("npx") else None

    with tempfile.TemporaryDirectory(prefix="kp2bw-untrusted-") as directory:
        project = Path(directory)
        (project / "package.json").write_text(
            '{"name":"@kjanat/vaultwarden-cli","version":"0.0.0","bin":{"vw":"trap.js"}}'
        )
        (project / "trap.js").write_text("process.exit(73);\n")
        (project / ".npmrc").write_text(
            "registry=https://127.0.0.1:9/\n@kjanat:registry=https://127.0.0.1:9/\n"
            "script-shell=untrusted-shell\n"
        )
        (project / ".env").write_text(
            "npm_config_registry=https://127.0.0.1:9/\n"
            "NODE_OPTIONS=--require ./trap.js\n"
            "KP2BW_CLI=auto\nKP2BW_YES=1\n"
        )
        for name in ("vw", "bw", "npx"):
            script = project / name
            script.write_text("#!/bin/sh\nexit 73\n")
            script.chmod(0o755)
            (project / (name + ".cmd")).write_text("@exit /b 73\n")
        binaries = project / "node_modules" / ".bin"
        binaries.mkdir(parents=True)
        (binaries / "node").write_text("#!/bin/sh\nexit 73\n")
        (binaries / "node").chmod(0o755)
        (binaries / "node.cmd").write_text("@exit /b 73\n")

        def private_workspace(*, prefix: str) -> tempfile.TemporaryDirectory[str]:
            return tempfile.TemporaryDirectory(prefix=prefix, dir=project)

        try:
            os.chdir(project)
            with (
                patch.dict(
                    os.environ,
                    {
                        "KP2BW_CLI": "auto",
                        "PATH": str(project)
                        + os.pathsep
                        + "."
                        + os.pathsep
                        + os.environ["PATH"],
                        "npm_config_registry": "https://127.0.0.1:9/",
                        "NPM_CONFIG_USERCONFIG": str(project / ".npmrc"),
                        "NODE_OPTIONS": "--require ./trap.js",
                    },
                ),
                patch.object(bw_serve, "find_cli_executable", side_effect=only_npx),
                patch.object(bw_serve, "find_on_path", return_value=None),
                patch.object(bw_serve, "npx_workspace", None),
                patch.object(
                    bw_serve, "TemporaryDirectory", side_effect=private_workspace
                ),
                patch.object(BitwardenServeClient, "get_session", return_value=None),
                patch.object(BitwardenServeClient, "start_serve"),
                patch.object(BitwardenServeClient, "wait_for_ready"),
                patch.object(BitwardenServeClient, "unlock"),
                patch.object(BitwardenServeClient, "sync_vault"),
                patch.object(BitwardenServeClient, "list_folders", return_value={}),
                patch.object(BitwardenServeClient, "build_dedup_index"),
                patch.object(
                    BitwardenServeClient,
                    "request",
                    side_effect=AssertionError("Bootstrap must not access a vault"),
                ),
            ):
                cli.load_dotenv()
                with BitwardenServeClient("synthetic-unused-password") as client:
                    assert re.fullmatch(
                        r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", client.cli_version
                    )
                    assert "--offline" in client.cli_command
                    assert bw_serve.NPX_VW_PACKAGE not in client.cli_command
                    assert client.supports_history_updates()
        finally:
            os.chdir(original_cwd)
    print("isolated npx bootstrap and offline CLI execution passed")


if __name__ == "__main__":
    main()
