import getpass
import logging
import os
import sys
from argparse import ArgumentParser, BooleanOptionalAction, Namespace
from datetime import datetime
from pathlib import Path
from typing import NoReturn

from dotenv import find_dotenv, load_dotenv
from rich.logging import RichHandler
from rich.markup import escape

from . import VERBOSE, __title__, __version__
from ._console import console
from .bw_serve import KP2BW_ID_FIELD_NAME, BitwardenServeClient, ensure_bw_available
from .convert import Converter
from .exceptions import BitwardenClientError, ConversionError

logger = logging.getLogger(__name__)


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


def _resolve_bool_option(arg_val: bool | None, env_var: str, *, default: bool) -> bool:
    """Resolve a boolean option through CLI > env var > default precedence.

    Raises :exc:`ValueError` when the environment variable holds an unrecognised
    value, propagated up to the caller's ``except ValueError``.
    """
    if arg_val is not None:
        return arg_val
    parsed = _parse_bool_env(os.environ.get(env_var), env_var=env_var)
    return parsed if parsed is not None else default


def _load_dotenv() -> str | None:
    """Load a ``.env`` file (searched upward from the CWD) into ``os.environ``.

    Returns the path that was loaded, or ``None`` when no ``.env`` is found.
    ``usecwd=True`` anchors the search at the user's working directory rather
    than this module's install location, so an installed ``kp2bw`` still picks
    up the project ``.env``.  ``override`` is left at its default of ``False``
    so a real shell environment variable always wins over a file entry: a
    ``.env`` value simply occupies the env tier of the documented
    CLI flag > env var > default precedence.
    """
    dotenv_path = find_dotenv(usecwd=True)
    if not dotenv_path:
        return None
    _ = load_dotenv(dotenv_path)
    return dotenv_path


def _argparser() -> MyArgParser:
    """Build and return the CLI argument parser with all flags and env-var support."""
    # Pin prog to the package name (single source: pyproject [project].name,
    # surfaced as __title__). Python 3.14 argparse otherwise derives prog from
    # the launch (via _prog_name), which for a console-script invocation becomes
    # "python.exe <argv0>" and leaked the launcher path into --version, usage,
    # and error messages.
    parser = MyArgParser(prog=__title__, description="KeePass to Bitwarden converter")

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    parser.add_argument(
        "keepass_file",
        metavar="FILE",
        nargs="?",
        default=None,
        help="Path to your KeePass 2.x db (env: KP2BW_KEEPASS_FILE)",
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
        "--update",
        dest="update_existing",
        help=(
            "Sync changed KeePass content (and missing attachments) onto "
            "existing Bitwarden entries; --no-update leaves their content "
            "untouched (default: on, env: KP2BW_UPDATE)"
        ),
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--include-oversize-secrets",
        dest="include_oversize_secrets",
        help=(
            "Offload secret custom fields (hidden OTP secrets, passkey "
            "attributes, KeePass-protected fields) that exceed the inline size "
            "limit to a plaintext .txt attachment instead of dropping them; off "
            "by default so a "
            "secret is never written to a readable attachment without consent "
            "(env: KP2BW_INCLUDE_OVERSIZE_SECRETS)"
        ),
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "--strip-ids",
        dest="strip_ids",
        help=(
            "Finalize adoption: remove the KP2BW_ID dedup stamp kp2bw adds to "
            "every migrated item, then exit (no migration, no KeePass database "
            "needed). Run once you're satisfied the migration is complete and "
            "ready to fully adopt Bitwarden. Honors -o/--bitwarden-org and "
            "-c/--bitwarden-collection for scope (env: KP2BW_STRIP_IDS)"
        ),
        action="store_true",
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


def _fail(exc: BaseException) -> NoReturn:
    """Print an actionable error and exit non-zero, without a stack trace."""
    console.print(f"[red]ERROR:[/red] {escape(str(exc))}")
    sys.exit(1)


def _confirm(prompt: str) -> bool:
    """Prompt for a y/n answer, looping until valid; True only on explicit yes."""
    answer: str | None = None
    while answer not in {"y", "n"}:
        answer = input(prompt).strip().lower()
    return answer == "y"


def _describe_scope(org_id: str | None, collection_id: str | None) -> str:
    """Human-readable description of the vault scope a strip run will touch."""
    if collection_id:
        return f"collection {collection_id} (organization {org_id})"
    if org_id:
        return f"organization {org_id}"
    return "your personal vault"


def _run_strip_ids(
    *,
    bitwarden_password_arg: str | None,
    org_id: str | None,
    collection_id: str | None,
    skip_confirm: bool,
) -> None:
    """Remove kp2bw's ``KP2BW_ID`` dedup stamp from every migrated item, then stop.

    The finalize step for users who trust their migration and want clean
    Bitwarden items: no KeePass database is read.  Scope follows ``-o``/``-c``
    exactly as a migration would.  The mutation is gated behind a confirmation
    (skippable with ``-y``); answering ``n`` aborts without changes.  Errors
    surface as an actionable message rather than a traceback.
    """
    scope = _describe_scope(org_id, collection_id)
    if not skip_confirm:
        console.print(
            f"This removes the [bold]{KP2BW_ID_FIELD_NAME}[/bold] field from "
            f"every kp2bw-migrated item in [bold]{escape(scope)}[/bold]. Your "
            "other vault data is left untouched, but re-runs will no longer be "
            "matched by stamp (they fall back to folder + name)."
        )
        if not _confirm(f"Remove {KP2BW_ID_FIELD_NAME} stamps? [y/n]: "):
            console.print("[yellow]Aborted; nothing changed.[/yellow]")
            sys.exit(2)

    bw_pw = _read_password(
        bitwarden_password_arg, "Please enter your Bitwarden password: "
    )
    try:
        with BitwardenServeClient(
            bw_pw, org_id=org_id, collection_id=collection_id
        ) as bw:
            result = bw.strip_field_from_items(KP2BW_ID_FIELD_NAME)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except (BitwardenClientError, ConversionError) as exc:
        _fail(exc)

    if result.stripped:
        console.print(
            f"[green]Removed {KP2BW_ID_FIELD_NAME} from {result.stripped} of "
            f"{result.scanned} item(s).[/green]"
        )
    else:
        console.print(
            f"No items carried a {KP2BW_ID_FIELD_NAME} stamp in {scope} "
            f"({result.scanned} scanned); nothing to do."
        )


# Third-party loggers whose DEBUG/INFO chatter is valuable in the always-on file
# log but noise on the console. The loggers stay at DEBUG (so the file keeps
# everything); console handlers attach a ConsoleNoiseFilter to drop their
# sub-WARNING records, keeping file completeness and console verbosity decoupled.
_NOISY_LOGGERS: frozenset[str] = frozenset({"httpx", "httpcore"})


class ConsoleNoiseFilter(logging.Filter):
    """Drop sub-WARNING records of the *muted* loggers from a console handler.

    The muted loggers stay at DEBUG so the file handler still records them; this
    only keeps that detail off whichever console handler it is attached to.
    ``muted`` defaults to every noisy logger (the plain console); ``--debug``
    attaches it muting only ``httpcore``, so the debug console shows httpx
    request lines while httpcore connection spam stays file-only.
    """

    def __init__(self, muted: frozenset[str] = _NOISY_LOGGERS) -> None:
        super().__init__()
        self._muted = muted

    def filter(self, record: logging.LogRecord) -> bool:
        root_name = record.name.split(".", 1)[0]
        return not (root_name in self._muted and record.levelno < logging.WARNING)


def _resolve_log_path() -> Path:
    """Return the file path for this run's debug log.

    ``KP2BW_LOG_FILE`` overrides everything; otherwise ``KP2BW_LOG_DIR`` or a
    per-user, platform-appropriate location holds one timestamped file per run.
    """
    explicit = os.environ.get("KP2BW_LOG_FILE")
    if explicit:
        return Path(explicit)

    override_dir = os.environ.get("KP2BW_LOG_DIR")
    if override_dir:
        log_dir = Path(override_dir)
    elif os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        log_dir = Path(base) / "kp2bw" / "logs"
    elif sys.platform == "darwin":
        log_dir = Path.home() / "Library" / "Logs" / "kp2bw"
    else:
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(
            os.path.expanduser("~"), ".local", "state"
        )
        log_dir = Path(base) / "kp2bw" / "logs"

    # Local-time stamp for a human-friendly filename; .astimezone() makes it
    # tz-aware (naive datetime.now() is flagged as ambiguous).
    return log_dir / f"kp2bw-{datetime.now().astimezone():%Y%m%d-%H%M%S}.log"


def _configure_logging(*, verbose: bool, debug: bool) -> Path | None:
    """Configure console + always-on file logging; return the log path.

    Console verbosity follows the flags (INFO default, VERBOSE with ``-v``, full
    DEBUG with ``-d``).  A file handler is *always* attached at DEBUG, and the
    transport loggers (``httpx``/``httpcore``) are pinned to DEBUG too, so the
    file captures a complete trace -- per-entry detail plus full request and
    connection logs -- regardless of console verbosity.  The console stays clean
    because each console handler filters that noise out itself
    (see :class:`ConsoleNoiseFilter`), never by lowering the loggers (which
    would also starve the file).  Pinning the ``httpx``/``httpcore`` levels is a
    deliberate process-wide side effect that is not restored, so the file keeps
    capturing transport traces for the whole run.  Returns ``None`` when the log
    file cannot be opened, so a logging-setup failure never aborts a migration.
    """
    root = logging.getLogger()
    # Clean slate so a second main() invocation (e.g. in tests) does not stack
    # duplicate handlers; close each as it is removed so a prior run's file
    # handle is released rather than leaked.
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    root.setLevel(logging.DEBUG)

    # Pin the transport loggers to DEBUG in every mode so the always-on file
    # captures full httpx/httpcore traces -- the data that explains timeouts and
    # dropped connections (#24). Quieting is a console-handler concern (filters
    # below); doing it via logger level would also starve the file.
    logging.getLogger("httpx").setLevel(logging.DEBUG)
    logging.getLogger("httpcore").setLevel(logging.DEBUG)

    if debug:
        console_handler: logging.Handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter("%(levelname)s: %(name)s: %(message)s")
        )
        console_handler.setLevel(logging.DEBUG)
        # Debug console shows kp2bw + httpx detail; httpcore connection spam is
        # left to the file only.
        console_handler.addFilter(ConsoleNoiseFilter(frozenset({"httpcore"})))
    else:
        console_handler = RichHandler(
            console=console, show_path=False, markup=False, log_time_format="[%X]"
        )
        console_handler.setLevel(VERBOSE if verbose else logging.INFO)
        console_handler.addFilter(ConsoleNoiseFilter())
    root.addHandler(console_handler)

    try:
        log_path = _resolve_log_path()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
        root.addHandler(file_handler)
    except OSError as exc:
        logger.warning(f"Could not open log file; continuing without one ({exc})")
        return None

    return log_path


def main() -> None:
    """Entry point: parse arguments, resolve env vars, and run the converter."""
    # Load .env before reading any environment variable so file-provided values
    # are visible to the resolution below; a real shell env var still wins.
    dotenv_path = _load_dotenv()

    args: Namespace = _argparser().parse_args()

    # string options: CLI > env > None/default
    args.keepass_file = _with_env(args.keepass_file, "KP2BW_KEEPASS_FILE")
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
        path_to_name = _resolve_bool_option(
            args.path_to_name, "KP2BW_PATH_TO_NAME", default=False
        )
        skip_expired = _resolve_bool_option(
            args.skip_expired, "KP2BW_SKIP_EXPIRED", default=False
        )
        include_recyclebin = _resolve_bool_option(
            args.include_recyclebin, "KP2BW_INCLUDE_RECYCLE_BIN", default=False
        )
        migrate_metadata = _resolve_bool_option(
            args.migrate_metadata, "KP2BW_MIGRATE_METADATA", default=True
        )
        update_existing = _resolve_bool_option(
            args.update_existing, "KP2BW_UPDATE", default=True
        )
        include_oversize_secrets = _resolve_bool_option(
            args.include_oversize_secrets,
            "KP2BW_INCLUDE_OVERSIZE_SECRETS",
            default=False,
        )
        skip_confirm = _resolve_bool_option(
            args.skip_confirm, "KP2BW_YES", default=False
        )
        strip_ids = _resolve_bool_option(
            args.strip_ids, "KP2BW_STRIP_IDS", default=False
        )
        verbose = _resolve_bool_option(args.verbose, "KP2BW_VERBOSE", default=False)
        debug = _resolve_bool_option(args.debug, "KP2BW_DEBUG", default=False)
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

    # --strip-ids is a Bitwarden-only finalize step: no KeePass database is read,
    # so the path requirement (and the KeePass password prompt below) is skipped.
    if not strip_ids and not args.keepass_file:
        _ = sys.stderr.write(
            "ERROR: KeePass database path is required "
            "(positional FILE or KP2BW_KEEPASS_FILE)\n\n"
        )
        _argparser().print_help()
        sys.exit(2)

    if args.bw_coll and not args.bw_org:
        _ = sys.stderr.write(
            "ERROR: --bitwarden-collection requires --bitwarden-org\n\n"
        )
        _argparser().print_help()
        sys.exit(2)

    # logging
    #   default : INFO via RichHandler  — httpx quiet on console, file gets all
    #   -v      : VERBOSE for kp2bw     — per-entry detail on console
    #   -d      : DEBUG for everything  — raw format, httpx included on console
    # A full-detail DEBUG log is always written to a file regardless of the above.
    log_path = _configure_logging(verbose=verbose, debug=debug)
    if dotenv_path:
        logger.info(f"Loaded environment from {dotenv_path}")
    if log_path is not None:
        logger.info(f"Writing full debug log to {log_path}")

    # Verify the Bitwarden CLI is available before prompting for secrets, so the
    # user isn't asked for passwords only to hit a missing-`bw` failure later.
    try:
        ensure_bw_available()
    except BitwardenClientError as exc:
        _fail(exc)

    # --strip-ids short-circuits migration entirely: it only touches Bitwarden
    # (remove kp2bw's dedup stamps), so it needs neither the bw-setup spiel nor a
    # KeePass password. It handles its own confirmation and Bitwarden password.
    if strip_ids:
        _run_strip_ids(
            bitwarden_password_arg=args.bw_pw,
            org_id=args.bw_org,
            collection_id=args.bw_coll,
            skip_confirm=skip_confirm,
        )
        return

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

    # The CLI/env validation above guarantees a database path.
    assert args.keepass_file is not None

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
        update_existing=update_existing,
        include_oversize_secrets=include_oversize_secrets,
    )
    try:
        failures = c.convert()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except (BitwardenClientError, ConversionError) as exc:
        _fail(exc)

    # Exit non-zero on non-fatal failures (rejected updates/attachment uploads)
    # so wrappers and CI can tell a partial migration from a clean one.
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
