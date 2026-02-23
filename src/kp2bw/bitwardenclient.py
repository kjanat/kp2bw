import base64
import json
import logging
import os
import platform
import shutil
from itertools import groupby
from subprocess import STDOUT, CalledProcessError, check_output
from typing import Any

from pykeepass import Attachment

from .exceptions import BitwardenClientError

logger = logging.getLogger(__name__)


class BitwardenClient:
    """Legacy Bitwarden CLI wrapper using one subprocess per operation."""

    TEMPORARY_ATTACHMENT_FOLDER: str = "attachment-temp"

    _orgId: str | None
    _key: str
    _folders: dict[str, str]
    _folder_entries: dict[str | None, list[str]]
    _colls: dict[str, str] | None

    def __init__(self, password: str, org_id: str | None) -> None:
        """Unlock the vault, sync state, and cache existing folders and entries."""
        # check for bw cli installation
        if "bitwarden" not in self._exec("bw"):
            raise BitwardenClientError(
                "Bitwarden Cli not installed! See https://help.bitwarden.com/article/cli/#download--install for help"
            )

        # save org
        self._orgId = org_id

        # login
        self._key = self._exec(f'bw unlock "{password}" --raw')
        if "error" in self._key:
            raise BitwardenClientError(
                "Could not unlock the Bitwarden db. Is the Master Password correct and are bw cli tools set up correctly?"
            )

        # make sure data is up to date
        if "Syncing complete." not in self._exec_with_session("bw sync"):
            raise BitwardenClientError(
                "Could not sync the local state to your Bitwarden server"
            )

        # get folder list
        self._folders = {
            folder["name"]: folder["id"]
            for folder in json.loads(self._exec_with_session("bw list folders"))
        }

        # get existing entries
        self._folder_entries = self._get_existing_folder_entries()

        # get existing collections
        if org_id:
            self._colls = {
                coll["name"]: coll["id"]
                for coll in json.loads(
                    self._exec_with_session(
                        f"bw list org-collections --organizationid {org_id}"
                    )
                )
            }
        else:
            self._colls = None

    def __del__(self) -> None:
        """Remove the temporary attachment directory on garbage collection."""
        # cleanup temp directory
        self._remove_temporary_attachment_folder()

    def _create_temporary_attachment_folder(self) -> None:
        """Create the temporary directory used to stage attachment files on disk."""
        if not os.path.isdir(self.TEMPORARY_ATTACHMENT_FOLDER):
            os.mkdir(self.TEMPORARY_ATTACHMENT_FOLDER)

    def _remove_temporary_attachment_folder(self) -> None:
        """Delete the temporary attachment staging directory if it exists."""
        if os.path.isdir(self.TEMPORARY_ATTACHMENT_FOLDER):
            shutil.rmtree(self.TEMPORARY_ATTACHMENT_FOLDER)

    def _exec(self, command: str) -> str:
        """Execute a ``bw`` CLI command via shell and return its decoded output."""
        output: bytes
        try:
            logger.debug("-- Executing Bitwarden CLI command")
            output = check_output(command, stderr=STDOUT, shell=True)
        except CalledProcessError as e:
            logger.debug(
                f"  |- Bitwarden CLI command failed with exit code {e.returncode}"
            )
            if isinstance(e.output, bytes):
                output = e.output
            else:
                output = str(e.output).encode("utf-8", "ignore")

        logger.debug(f"  |- Received {len(output)} bytes from Bitwarden CLI")
        return output.decode("utf-8", "ignore")

    def _get_existing_folder_entries(self) -> dict[str | None, list[str]]:
        """Build a mapping of folder name to list of item names already in the vault."""
        folder_id_lookup_helper: dict[str, str] = {
            folder_id: folder_name for folder_name, folder_id in self._folders.items()
        }
        items: list[dict[str, Any]] = json.loads(
            self._exec_with_session("bw list items")
        )

        # fix None folderIds for entries without folders
        for item in items:
            if not item["folderId"]:
                item["folderId"] = ""

        items.sort(key=lambda item: item["folderId"])
        return {
            folder_id_lookup_helper.get(folder_id): [entry["name"] for entry in entries]
            for folder_id, entries in groupby(items, key=lambda item: item["folderId"])
        }

    def _exec_with_session(self, command: str) -> str:
        """Execute a ``bw`` command with the session key appended."""
        return self._exec(f"{command} --session '{self._key}'")

    def has_folder(self, folder: str | None) -> bool:
        """Return whether the given folder name already exists in the vault."""
        return folder in self._folders

    def _get_platform_dependent_echo_str(self, string: str) -> str:
        """Return a platform-appropriate ``echo`` command for piping into ``bw``."""
        if platform.system() == "Windows":
            return f"echo {string}"
        else:
            return f"echo '{string}'"

    def create_folder(self, folder: str | None) -> None:
        """Create a folder in the vault if it does not already exist."""
        if not folder or self.has_folder(folder):
            return

        data: dict[str, str] = {"name": folder}
        data_b64 = base64.b64encode(json.dumps(data).encode("UTF-8")).decode("UTF-8")

        output = self._exec_with_session(
            f"{self._get_platform_dependent_echo_str(data_b64)} | bw create folder"
        )

        output_obj: dict[str, str] = json.loads(output)

        self._folders[output_obj["name"]] = output_obj["id"]

    def create_entry(self, folder: str | None, entry: dict[str, Any]) -> str:
        """Create a vault item in the given folder, skipping duplicates."""
        # check if already exists
        if (
            folder in self._folder_entries
            and entry["name"] in self._folder_entries[folder]
        ):
            logger.info(
                f"-- Entry {entry['name']} already exists in folder {folder}. skipping..."
            )
            return "skip"

        # create folder if exists
        if folder:
            self.create_folder(folder)

            # set id
            entry["folderId"] = self._folders[folder]

        json_str = json.dumps(entry)

        # convert string to base64
        json_b64 = base64.b64encode(json_str.encode("UTF-8")).decode("UTF-8")

        return self._exec_with_session(
            f"{self._get_platform_dependent_echo_str(json_b64)} | bw create item"
        )

    def create_attachment(
        self, item_id: str, attachment: tuple[str, str] | Attachment
    ) -> str:
        """Write an attachment to a temp file and upload it to the given vault item."""
        # store attachment on disk
        filename: str
        data: bytes
        if not isinstance(attachment, Attachment):
            # long custom property — tuple[str, str]
            filename = attachment[0] + ".txt"
            data = attachment[1].encode("UTF-8")
        else:
            # real kp attachment
            if attachment.filename is None:
                logger.warning("Attachment has no filename, using fallback")
                filename = "attachment"
            else:
                filename = attachment.filename
            data = attachment.data

        # make sure temporary attachment folder exists
        self._create_temporary_attachment_folder()

        path_to_file_on_disk = os.path.join(self.TEMPORARY_ATTACHMENT_FOLDER, filename)
        with open(path_to_file_on_disk, "wb") as f:
            _ = f.write(data)

        try:
            output = self._exec_with_session(
                f'bw create attachment --file "{path_to_file_on_disk}" --itemid {item_id}'
            )
        finally:
            os.remove(path_to_file_on_disk)

        return output

    def create_org_get_collection(self, collectionname: str | None) -> str | None:
        """Get or create an organisation collection and return its ID."""
        if not collectionname:
            return None

        if self._colls is None:
            self._colls = {}

        # check for existing
        if self._colls.get(collectionname):
            return self._colls.get(collectionname)

        # get template
        entry: dict[str, Any] = json.loads(
            self._exec_with_session("bw get template org-collection")
        )

        # set org and Name
        entry["name"] = collectionname
        entry["organizationId"] = self._orgId

        json_str = json.dumps(entry)

        # convert string to base64
        json_b64 = base64.b64encode(json_str.encode("UTF-8")).decode("UTF-8")

        output = self._exec_with_session(
            f"{self._get_platform_dependent_echo_str(json_b64)} | bw create  org-collection --organizationid {self._orgId}"
        )
        if not output:
            return None
        data: dict[str, Any] = json.loads(output)
        if not data["id"]:
            return None
        new_coll_id: str = data["id"]

        # store in cache
        self._colls[collectionname] = new_coll_id

        return new_coll_id
