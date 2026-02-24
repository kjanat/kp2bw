import getpass
import logging
import os
import sys
from argparse import ArgumentParser, BooleanOptionalAction, Namespace
from typing import NoReturn

from rich.logging import RichHandler

from . import VERBOSE, __version__
from ._console import console
from .convert import Converter


class MyArgParser(ArgumentParser):
    """Argument parser that prints help on error instead of just usage."""

    def error(self, message: str) -> NoReturn:
        """Print the error message followed by full help, then exit."""
        _ = sys.stderr.write(f"{self.prog}: {message}\n\n")
        self.print_help()
        sys.exit(2)


def _parse_bool_env(value: str | None, *, env_var: str) -> bool | None:
    """Parse an environment variable string into a boolean, or ``None`` if unset."""
    if value is None:
        return None

    normalized = value.strip().lower()
    true_values = {"1", "true", "yes", "y", "on"}
    false_values = {"0", "false", "no", "n", "off"}

    if normalized in true_values:
        return True
    if normalized in false_values:
        return False

    raise ValueError(
        f"Invalid boolean value for {env_var}: {value!r}. "
        "Use one of 1/0, true/false, yes/no, on/off."
    )


def _split_csv_env(value: str | None) -> list[str] | None:
    """Split a comma-separated environment variable into a list of trimmed strings."""
    if value is None:
        return None

    tags = [tag.strip() for tag in value.split(",") if tag.strip()]
    return tags or None


def _with_env[T](arg_value: T | None, env_var: str) -> T | str | None:
    """Return *arg_value* if set, otherwise fall back to the named environment variable."""
    if arg_value is not None:
        return arg_value
    return os.environ.get(env_var)


def _argparser() -> MyArgParser:
    """Build and return the CLI argument parser with all flags and env-var support."""
    parser = MyArgParser(description="KeePass to Bitwarden converter")

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    parser.add_argument(
        "keepass_file", metavar="FILE", help="Path to your KeePass 2.x db."
    )
    parser.add_argument(
        "-k",
        "--keepass-password",
        dest="kp_pw",
        metavar="PASSWORD",
        help="KeePass db password (env: KP2BW_KEEPASS_PASSWORD)",
        default=None,
    )
    parser.add_argument(
        "-K",
        "--keepass-keyfile",
        dest="kp_keyfile",
        metavar="FILE",
        help="KeePass db key file (env: KP2BW_KEEPASS_KEYFILE)",
        default=None,
    )
    parser.add_argument(
        "-b",
        "--bitwarden-password",
        dest="bw_pw",
        metavar="PASSWORD",
        help="Bitwarden password (env: KP2BW_BITWARDEN_PASSWORD)",
        default=None,
    )
    parser.add_argument(
        "-o",
        "--bitwarden-org",
        dest="bw_org",
        metavar="ID",
        help="Bitwarden Organization Id (env: KP2BW_BITWARDEN_ORG)",
        default=None,
    )
    parser.add_argument(
        "-t",
        "--import-tags",
        dest="import_tags",
        metavar="TAG",
        help="Only import tagged items (env: KP2BW_IMPORT_TAGS as comma-separated values)",
        nargs="+",
        default=None,
    )
    parser.add_argument(
        "-c",
        "--bitwarden-collection",
        dest="bw_coll",
        metavar="ID",
        help="Id of Org-Collection, or 'auto' for top-level folder names (env: KP2BW_BITWARDEN_COLLECTION)",
        default=None,
    )
    parser.add_argument(
        "--path-to-name",
        dest="path_to_name",
        help="Prepend folder path to each entry name (env: KP2BW_PATH_TO_NAME)",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--path-to-name-skip",
        dest="path_to_name_skip",
        metavar="N",
        help="Skip first N folders for path prefix (default: 1, env: KP2BW_PATH_TO_NAME_SKIP)",
        default=None,
        type=int,
    )
    parser.add_argument(
        "--skip-expired",
        dest="skip_expired",
        help="Skip expired KeePass entries (env: KP2BW_SKIP_EXPIRED)",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--include-recycle-bin",
        dest="include_recyclebin",
        help="Include KeePass Recycle Bin entries (env: KP2BW_INCLUDE_RECYCLE_BIN)",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--metadata",
        dest="migrate_metadata",
        help="Migrate KeePass metadata as custom fields (env: KP2BW_MIGRATE_METADATA)",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "-y",
        "--yes",
        dest="skip_confirm",
        help="Skip the bw CLI setup confirmation prompt (env: KP2BW_YES)",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        help="Verbose output (env: KP2BW_VERBOSE)",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "-d",
        "--debug",
        dest="debug",
        help="Debug output — includes third-party library logs (env: KP2BW_DEBUG)",
        action="store_true",
        default=None,
    )

    return parser


def _read_password(arg: str | None, prompt: str) -> str:
    """Return *arg* if provided, otherwise prompt interactively for a password."""
    if not arg:
        arg = getpass.getpass(prompt=prompt)

    return arg


def main() -> None:
    """Entry point: parse arguments, resolve env vars, and run the converter."""
    args: Namespace = _argparser().parse_args()

    # string options: CLI > env > None/default
    args.kp_pw = _with_env(args.kp_pw, "KP2BW_KEEPASS_PASSWORD")
    args.kp_keyfile = _with_env(args.kp_keyfile, "KP2BW_KEEPASS_KEYFILE")
    args.bw_pw = _with_env(args.bw_pw, "KP2BW_BITWARDEN_PASSWORD")
    args.bw_org = _with_env(args.bw_org, "KP2BW_BITWARDEN_ORG")
    args.bw_coll = _with_env(args.bw_coll, "KP2BW_BITWARDEN_COLLECTION")
    args.import_tags = args.import_tags or _split_csv_env(
        os.environ.get("KP2BW_IMPORT_TAGS")
    )

    # bool/int options: CLI > env > code default
    try:
        path_to_name = (
            args.path_to_name
            if args.path_to_name is not None
            else _parse_bool_env(
                os.environ.get("KP2BW_PATH_TO_NAME"), env_var="KP2BW_PATH_TO_NAME"
            )
        )
        skip_expired = (
            args.skip_expired
            if args.skip_expired is not None
            else _parse_bool_env(
                os.environ.get("KP2BW_SKIP_EXPIRED"), env_var="KP2BW_SKIP_EXPIRED"
            )
        )
        include_recyclebin = (
            args.include_recyclebin
            if args.include_recyclebin is not None
            else _parse_bool_env(
                os.environ.get("KP2BW_INCLUDE_RECYCLE_BIN"),
                env_var="KP2BW_INCLUDE_RECYCLE_BIN",
            )
        )
        migrate_metadata = (
            args.migrate_metadata
            if args.migrate_metadata is not None
            else _parse_bool_env(
                os.environ.get("KP2BW_MIGRATE_METADATA"),
                env_var="KP2BW_MIGRATE_METADATA",
            )
        )
        skip_confirm = (
            args.skip_confirm
            if args.skip_confirm is not None
            else _parse_bool_env(os.environ.get("KP2BW_YES"), env_var="KP2BW_YES")
        )
        verbose = (
            args.verbose
            if args.verbose is not None
            else _parse_bool_env(
                os.environ.get("KP2BW_VERBOSE"), env_var="KP2BW_VERBOSE"
            )
        )
        debug = (
            args.debug
            if args.debug is not None
            else _parse_bool_env(os.environ.get("KP2BW_DEBUG"), env_var="KP2BW_DEBUG")
        )
    except ValueError as exc:
        _ = sys.stderr.write(f"ERROR: {exc}\n\n")
        _argparser().print_help()
        sys.exit(2)

    path_to_name_skip = args.path_to_name_skip
    if path_to_name_skip is None:
        env_skip = os.environ.get("KP2BW_PATH_TO_NAME_SKIP")
        if env_skip is None:
            path_to_name_skip = 1
        else:
            try:
                path_to_name_skip = int(env_skip)
            except ValueError:
                _ = sys.stderr.write(
                    f"ERROR: Invalid integer value for KP2BW_PATH_TO_NAME_SKIP: {env_skip!r}\n\n"
                )
                _argparser().print_help()
                sys.exit(2)

    path_to_name = path_to_name if path_to_name is not None else False
    skip_expired = skip_expired if skip_expired is not None else False
    include_recyclebin = include_recyclebin if include_recyclebin is not None else False
    migrate_metadata = migrate_metadata if migrate_metadata is not None else True
    skip_confirm = skip_confirm if skip_confirm is not None else False
    verbose = verbose if verbose is not None else False
    debug = debug if debug is not None else False

    if args.bw_coll and not args.bw_org:
        _ = sys.stderr.write(
            "ERROR: --bitwarden-collection requires --bitwarden-org\n\n"
        )
        _argparser().print_help()
        sys.exit(2)

    # logging
    #   default : INFO via RichHandler  — httpx silenced, progress bar active
    #   -v      : VERBOSE for kp2bw     — httpx silenced, per-entry detail shown
    #   -d      : DEBUG for everything  — raw format, httpx included
    if debug:
        logging.basicConfig(
            format="%(levelname)s: %(name)s: %(message)s", level=logging.DEBUG
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(console=console, show_path=False, markup=False)],
        )
        logging.getLogger("httpx").setLevel(logging.WARNING)
        if verbose:
            logging.getLogger("kp2bw").setLevel(VERBOSE)

    # bw confirmation
    if not skip_confirm:
        confirm: str | None = None
        print("Do you have bw cli installed and is it set up?")
        print(
            "1) If you use an on premise installation, use bw config to set the url: bw config server <url>"
        )
        print(
            "2) execute bw login once, as this script uses bw unlock only: bw login <user>"
        )
        print(" ")

        while confirm not in {"y", "n"}:
            confirm = input("Confirm that you have set up bw cli [y/n]: ").lower()

        if confirm == "n":
            print("exiting...")
            sys.exit(2)

    # stdin password
    kp_pw: str = _read_password(
        args.kp_pw, "Please enter your KeePass 2.x db password: "
    )
    bw_pw: str = _read_password(args.bw_pw, "Please enter your Bitwarden password: ")

    # call converter
    c = Converter(
        keepass_file_path=args.keepass_file,
        keepass_password=kp_pw,
        keepass_keyfile_path=args.kp_keyfile,
        bitwarden_password=bw_pw,
        bitwarden_organization_id=args.bw_org,
        bitwarden_coll_id=args.bw_coll,
        path2name=path_to_name,
        path2nameskip=path_to_name_skip,
        import_tags=args.import_tags,
        skip_expired=skip_expired,
        include_recyclebin=include_recyclebin,
        migrate_metadata=migrate_metadata,
    )
    c.convert()

    print(" ")
    print("All done.")


if __name__ == "__main__":
    main()
