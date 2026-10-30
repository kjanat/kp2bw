import getpass
import json
import logging
import os
import platform
import sys
import textwrap
from argparse import ArgumentParser, BooleanOptionalAction, HelpFormatter, Namespace
from datetime import datetime
from pathlib import Path
from typing import NoReturn
from uuid import UUID

from dotenv import dotenv_values, find_dotenv
from rich.logging import RichHandler
from rich.markup import escape

from . import VERBOSE, __title__, __version__
from .bw_serve import (
    KP2BW_ID_FIELD_NAME,
    KP2BW_SYNC_FIELD_NAME,
    BitwardenServeClient,
    ensure_bw_available,
)
from .console import console
from .convert import COLLECTION_FOLDER_MODES, Converter, collect_keepass_uris
from .doctor import collect_report, redact_report, render_report
from .exceptions import BitwardenClientError, ConversionError
from .fixups import FixupOptions, run_fixups
from .ssh_mapping import parse_ssh_rules
from .templates import parse_template_overrides
from .uri_mapping import (
    UriMatchValue,
    collision_groups,
    match_value_names,
    parse_match_name,
    registrable_domain,
    uri_host,
)

logger = logging.getLogger(__name__)

CLI_DOCS_URL: str = "https://kjanat.github.io/kp2bw/docs/"


def cli_docs_link(*, terminal: bool) -> str:
    """Return clickable docs text for terminals and a plain URL for pipes."""
    if not terminal:
        return CLI_DOCS_URL
    return f"\x1b]8;;{CLI_DOCS_URL}\x1b\\CLI reference\x1b]8;;\x1b\\"


def supports_osc8() -> bool:
    """Return whether stdout is a terminal expected to render hyperlinks."""
    return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"


class MyArgParser(ArgumentParser):
    """Argument parser that prints help on error instead of just usage."""

    def error(self, message: str) -> NoReturn:
        """Print the error message followed by full help, then exit."""
        _ = sys.stderr.write(f"{self.prog}: {message}\n\n")
        self.print_help()
        sys.exit(2)


class NoBreakHelpFormatter(HelpFormatter):
    """Wrap help without splitting URLs or terminal escape sequences."""

    def _fill_text(self, text: str, width: int, indent: str) -> str:
        normalized = " ".join(text.split())
        if "\x1b]8;" in normalized:
            return f"{indent}{normalized}"
        return textwrap.fill(
            normalized,
            width,
            initial_indent=indent,
            subsequent_indent=indent,
            break_long_words=False,
            break_on_hyphens=False,
        )


def parse_bool_env(value: str | None, *, env_var: str) -> bool | None:
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


def split_csv_env(value: str | None) -> list[str] | None:
    """Split a comma-separated environment variable into a list of trimmed strings."""
    if value is None:
        return None

    tags = [tag.strip() for tag in value.split(",") if tag.strip()]
    return tags or None


def with_env[T](arg_value: T | None, env_var: str) -> T | str | None:
    """Return *arg_value* if set, otherwise fall back to the named environment variable."""
    if arg_value is not None:
        return arg_value
    return os.environ.get(env_var)


def resolve_bool_option(arg_val: bool | None, env_var: str, *, default: bool) -> bool:
    """Resolve a boolean option through CLI > env var > default precedence.

    Raises :exc:`ValueError` when the environment variable holds an unrecognised
    value, propagated up to the caller's ``except ValueError``.
    """
    if arg_val is not None:
        return arg_val
    parsed = parse_bool_env(os.environ.get(env_var), env_var=env_var)
    return parsed if parsed is not None else default


def load_dotenv() -> str | None:
    """Load a ``.env`` file (searched upward from the CWD) into ``os.environ``.

    Returns the path that was loaded, or ``None`` when no ``.env`` is found.
    ``usecwd=True`` anchors the search at the user's working directory rather
    than this module's install location, so an installed ``kp2bw`` still picks
    up the project ``.env``.

    A real, *non-empty* shell variable still wins over a file entry (the
    documented CLI flag > env var > default precedence). But a variable that is
    set to the **empty string** must not shadow a ``.env`` value: that is almost
    never intended and produces a baffling "X is required" when the file clearly
    has it. So unlike a plain ``load_dotenv(override=False)`` -- which treats an
    empty export as "set" and skips it -- this fills any key that is currently
    unset *or empty* from the file, leaving non-empty exports untouched.
    """
    dotenv_path = find_dotenv(usecwd=True)
    if not dotenv_path:
        return None
    for key, value in dotenv_values(dotenv_path).items():
        if value is not None and not os.environ.get(key):
            os.environ[key] = value
    return dotenv_path


def argparser() -> MyArgParser:
    """Build and return the CLI argument parser with all flags and env-var support."""
    # Pin prog to the package name (single source: pyproject [project].name,
    # surfaced as __title__). Python 3.14 argparse otherwise derives prog from
    # the launch (via _prog_name), which for a console-script invocation becomes
    # "python.exe <argv0>" and leaked the launcher path into --version, usage,
    # and error messages.
    parser = MyArgParser(
        prog=__title__,
        usage="%(prog)s [OPTIONS] [FILE]",
        description="Import KeePass into Bitwarden.",
        epilog=f"Documentation: {cli_docs_link(terminal=supports_osc8())}",
        formatter_class=NoBreakHelpFormatter,
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    parser.add_argument(
        "--doctor",
        dest="doctor",
        action="store_true",
        help="Check kp2bw, bw CLI, and server setup.",
    )

    parser.add_argument(
        "--redact",
        dest="redact",
        action="store_true",
        help="Redact paths and server URL from --doctor.",
    )

    parser.add_argument(
        "keepass_file",
        metavar="FILE",
        nargs="?",
        default=None,
        help="KeePass database.",
    )
    parser.add_argument(
        "-k",
        "--keepass-password",
        dest="kp_pw",
        metavar="PASSWORD",
        help="KeePass password.",
        default=None,
    )
    parser.add_argument(
        "-K",
        "--keepass-keyfile",
        dest="kp_keyfile",
        metavar="FILE",
        help="KeePass key file.",
        default=None,
    )
    parser.add_argument(
        "-b",
        "--bitwarden-password",
        dest="bw_pw",
        metavar="PASSWORD",
        help="Bitwarden password.",
        default=None,
    )
    parser.add_argument(
        "-o",
        "--bitwarden-org",
        dest="bw_org",
        metavar="ID",
        help="Target Bitwarden organization.",
        default=None,
    )
    parser.add_argument(
        "-t",
        "--import-tags",
        dest="import_tags",
        metavar="TAG",
        help="Import only entries with these tags.",
        nargs="+",
        default=None,
    )
    parser.add_argument(
        "-c",
        "--bitwarden-collection",
        dest="bw_coll",
        metavar="ID",
        help="Target collection ID, 'auto', or 'nested'.",
        default=None,
    )
    parser.add_argument(
        "--folder",
        dest="create_folders",
        help="Create personal folders from KeePass groups.",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--path-to-name",
        dest="path_to_name",
        help="Prepend the group path to entry names.",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--path-to-name-skip",
        dest="path_to_name_skip",
        metavar="N",
        help="Skip N groups in name prefixes (default: 1).",
        default=None,
        type=int,
    )
    parser.add_argument(
        "--skip-expired",
        dest="skip_expired",
        help="Skip expired entries.",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--include-recycle-bin",
        dest="include_recyclebin",
        help="Include Recycle Bin entries.",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--metadata",
        dest="migrate_metadata",
        help="Migrate tags and expiry metadata.",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--update",
        dest="update_existing",
        help="Update matching Bitwarden items (default: on).",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--entry-id",
        metavar="UUID",
        type=lambda value: str(UUID(value)),
        help="Sync only this KeePass entry UUID.",
    )
    parser.add_argument(
        "--item-id",
        metavar="UUID",
        type=lambda value: str(UUID(value)),
        help="Sync only this existing Bitwarden item UUID.",
    )
    parser.add_argument(
        "--force-update",
        dest="force_update",
        help="Overwrite items changed in Bitwarden.",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "--ssh-map",
        metavar="JSON",
        help="Explicit group, template or field mappings for native SSH items.",
        default=None,
    )
    parser.add_argument(
        "--map-templates",
        help="Map referenced KeePass templates to cards, identities and secure notes.",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--preview",
        choices=("text", "json"),
        nargs="?",
        const="text",
        help="Describe the source migration without Bitwarden credentials or writes.",
    )
    parser.add_argument(
        "--preview-target",
        action="store_true",
        help="With --preview: inspect the destination vault without modifying it.",
    )
    parser.add_argument(
        "--template-map",
        metavar="JSON",
        help="Template UUID and field overrides (requires --map-templates).",
        default=None,
    )
    parser.add_argument(
        "--include-oversize-secrets",
        dest="include_oversize_secrets",
        help="Store oversized secrets as plaintext attachments.",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "--archive-history",
        help="Archive full KeePass history, including historical secrets, as an attachment.",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "--password-history",
        help="Import up to five distinct previous KeePass passwords (default: on).",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--uri-match",
        dest="uri_match",
        metavar="MODE",
        choices=match_value_names(),
        help="Match mode for plain login URIs.",
        default=None,
    )
    parser.add_argument(
        "--totp-pps",
        dest="totp_pps",
        help="Read Pleasant Password Server TOTP fields.",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--interpret-uri-syntax",
        dest="interpret_uri_syntax",
        help="Interpret KeePassXC quoted and wildcard URLs.",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--checkpoint",
        metavar="PATH",
        default=None,
        help="Save verified attachment mappings for resumable migration.",
    )
    parser.add_argument(
        "--strip-ids",
        dest="strip_ids",
        help="Remove kp2bw tracking fields, then exit. Irreversible.",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "--fixup",
        action="store_true",
        default=None,
        help="Upgrade known legacy Bitwarden fields without KeePass.",
    )
    parser.add_argument(
        "--migrate-uris",
        dest="migrate_uris",
        help="Fold legacy URL fields into login URIs, then exit.",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "--report-uris",
        dest="report_uris",
        metavar="SOURCE",
        choices=("keepass", "bitwarden"),
        help="Report URI host collisions, then exit.",
        default=None,
    )
    parser.add_argument(
        "-y",
        "--yes",
        dest="skip_confirm",
        help="Skip confirmation prompts.",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        help="Show migration details.",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "-d",
        "--debug",
        dest="debug",
        help="Show debug and dependency logs.",
        action="store_true",
        default=None,
    )

    return parser


def read_password(arg: str | None, prompt: str) -> str:
    """Return *arg* if provided, otherwise prompt interactively for a password."""
    if not arg:
        arg = getpass.getpass(prompt=prompt)

    return arg


def fail(exc: BaseException) -> NoReturn:
    """Print an actionable error and exit non-zero, without a stack trace."""
    console.print(f"[red]ERROR:[/red] {escape(str(exc))}")
    sys.exit(1)


def confirm(prompt: str) -> bool:
    """Prompt for a y/n answer, looping until valid; True only on explicit yes."""
    answer: str | None = None
    while answer not in {"y", "n"}:
        answer = input(prompt).strip().lower()
    return answer == "y"


def describe_scope(org_id: str | None, collection_id: str | None) -> str:
    """Human-readable description of the vault scope a strip run will touch."""
    if collection_id:
        return f"collection {collection_id} (organization {org_id})"
    if org_id:
        return f"organization {org_id}"
    return "your personal vault"


def run_strip_ids(
    *,
    bitwarden_password_arg: str | None,
    org_id: str | None,
    collection_id: str | None,
    skip_confirm: bool,
) -> None:
    """Remove kp2bw's ``KP2BW_ID``/``KP2BW_SYNC`` stamps from every item, then stop.

    The finalize step for users ready to fully adopt Bitwarden: no KeePass
    database is read, and scope follows ``-o``/``-c`` exactly as a migration
    would.  Drops both the ``KP2BW_ID`` dedup key and the ``KP2BW_SYNC`` edit-
    protection signature.  The operation is **irreversible** -- the stamps cannot
    be recovered -- and makes future migration re-runs unreliable: without
    ``KP2BW_ID``, entries that share a folder + name (the very collision it
    disambiguates) can be duplicated or mismatched, and without ``KP2BW_SYNC``
    manual-edit protection no longer applies.  A loud confirmation states this
    before any change; ``-y``/``--yes`` skips it for callers who know what they
    want.  Errors surface as an actionable message rather than a traceback.
    """
    scope = describe_scope(org_id, collection_id)
    try:
        if not skip_confirm:
            console.print(
                f"[bold yellow]Warning:[/bold yellow] this removes the "
                f"[bold]{KP2BW_ID_FIELD_NAME}[/bold] and "
                f"[bold]{KP2BW_SYNC_FIELD_NAME}[/bold] fields and attachment associations from every "
                f"kp2bw-migrated item in [bold]{escape(scope)}[/bold]. Other "
                "vault data is untouched, but this [bold]cannot be undone[/bold] "
                "and makes future migration re-runs unreliable: without the "
                "stamps, entries sharing a folder + name can be duplicated or "
                "mismatched and manual-edit protection no longer applies. Only do "
                "this once you are finished migrating and ready to fully adopt "
                "Bitwarden."
            )
            if not confirm(
                f"Remove {KP2BW_ID_FIELD_NAME}/{KP2BW_SYNC_FIELD_NAME} stamps? [y/n]: "
            ):
                console.print("[yellow]Aborted; nothing changed.[/yellow]")
                sys.exit(0)

        bw_pw = read_password(
            bitwarden_password_arg, "Please enter your Bitwarden password: "
        )
        with BitwardenServeClient(
            bw_pw, org_id=org_id, collection_id=collection_id
        ) as bw:
            result = bw.strip_field_from_items(
                KP2BW_ID_FIELD_NAME, KP2BW_SYNC_FIELD_NAME
            )
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except (BitwardenClientError, ConversionError) as exc:
        fail(exc)

    if result.stripped:
        console.print(
            f"[green]Removed {KP2BW_ID_FIELD_NAME}/{KP2BW_SYNC_FIELD_NAME} from "
            f"{result.stripped} of {result.scanned} item(s).[/green]"
        )
    else:
        console.print(
            f"No items carried a {KP2BW_ID_FIELD_NAME}/{KP2BW_SYNC_FIELD_NAME} "
            f"stamp in {escape(scope)} ({result.scanned} scanned); nothing to do."
        )


def run_migrate_uris(
    *,
    bitwarden_password_arg: str | None,
    org_id: str | None,
    collection_id: str | None,
    skip_confirm: bool,
    uri_match: UriMatchValue,
    interpret_uri_syntax: bool,
) -> None:
    """Upgrade existing items: re-fold legacy URL/app custom fields into URIs.

    The Bitwarden-only counterpart of the new-import URL folding, for users who
    imported before it and do not want to re-import. No KeePass database is read;
    scope follows ``-o``/``-c``. The change is additive and idempotent (the
    field's data survives as a URI), so the confirmation is skippable with ``-y``.
    Errors surface as an actionable message rather than a traceback.
    """
    scope = describe_scope(org_id, collection_id)
    try:
        if not skip_confirm:
            console.print(
                "This re-folds legacy [bold]KP2A_URL*[/bold]/[bold]AndroidApp[/bold] "
                f"custom fields into login URIs on items in [bold]{escape(scope)}[/bold] "
                "(the field data is preserved as a URI, then the field removed)."
            )
            if not confirm("Migrate URL fields to URIs? [y/n]: "):
                console.print("[yellow]Aborted; nothing changed.[/yellow]")
                sys.exit(0)

        bw_pw = read_password(
            bitwarden_password_arg, "Please enter your Bitwarden password: "
        )
        with BitwardenServeClient(
            bw_pw, org_id=org_id, collection_id=collection_id
        ) as bw:
            result = bw.migrate_url_fields_to_uris(
                plain_match=uri_match, interpret_syntax=interpret_uri_syntax
            )
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except (BitwardenClientError, ConversionError) as exc:
        fail(exc)

    if result.migrated:
        console.print(
            f"[green]Migrated URL fields to URIs on {result.migrated} of "
            f"{result.scanned} item(s).[/green]"
        )
    if result.protected:
        console.print(
            f"[yellow]Preserved {result.protected} item(s) that could not be "
            "updated safely; "
            "their legacy URL fields were not changed.[/yellow]"
        )
    if not result.migrated and not result.protected:
        console.print(
            f"No items carried legacy URL fields in {escape(scope)} "
            f"({result.scanned} scanned); nothing to do."
        )


def run_fixup(
    password_arg: str | None,
    *,
    org_id: str | None,
    collection_id: str | None,
    skip_confirm: bool,
    uri_match: UriMatchValue,
    interpret_uri_syntax: bool,
) -> None:
    try:
        if not skip_confirm:
            console.print(
                f"Upgrade known legacy URL and metadata fields in {escape(describe_scope(org_id, collection_id))}."
            )
            if not confirm("Apply fixups? [y/n]: "):
                console.print("Aborted; nothing changed.")
                return
        password = read_password(password_arg, "Please enter your Bitwarden password: ")
        with BitwardenServeClient(
            password, org_id=org_id, collection_id=collection_id
        ) as bw:
            result = run_fixups(
                bw,
                org_id=org_id,
                collection_id=collection_id,
                options=FixupOptions(uri_match, interpret_uri_syntax),
            )
    except KeyboardInterrupt:
        console.print("Interrupted.")
        sys.exit(130)
    except (BitwardenClientError, ConversionError) as exc:
        fail(exc)
    console.print(
        f"Fixup: {result.scanned} scanned, {result.migrated} migrated, {result.skipped} skipped, {result.failed} failed."
    )
    if result.failed:
        sys.exit(1)


def print_uri_report(uris: list[str], source: str) -> None:
    """Print the read-only URI collision report to stdout (changes nothing).

    Groups hosts by registrable domain and lists the multi-host groups -- the
    logins that all surface together under Bitwarden's base-domain matching.
    The header goes through the Rich console; the data lines are plain ``print``
    so they copy/paste cleanly.
    """
    groups = collision_groups(uris)
    bases = {registrable_domain(host) for u in uris if (host := uri_host(u))}
    console.print(
        f"[bold]URI collision report ({source})[/bold]: {len(uris)} URIs across "
        f"{len(bases)} base domain(s); [bold]{len(groups)}[/bold] have multiple "
        "hosts (these all surface together under Bitwarden base-domain match -- "
        "switch them to Host match to separate them)."
    )
    if not groups:
        print("# no base-domain collisions")
        return
    for base, hosts in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"{base} ({len(hosts)}): " + ", ".join(hosts))


def run_report_uris_bitwarden(
    *,
    bitwarden_password_arg: str | None,
    org_id: str | None,
    collection_id: str | None,
) -> None:
    """Read the live Bitwarden vault and print the URI collision report.

    Read-only Bitwarden mode (no KeePass): lists in-scope items, gathers their
    login URIs, and reports the base-domain collisions. Scope follows ``-o``/``-c``.
    """
    bw_pw = read_password(
        bitwarden_password_arg, "Please enter your Bitwarden password: "
    )
    try:
        with BitwardenServeClient(
            bw_pw, org_id=org_id, collection_id=collection_id
        ) as bw:
            items = bw.list_items(organization_id=org_id, collection_id=collection_id)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except (BitwardenClientError, ConversionError) as exc:
        fail(exc)

    uris: list[str] = []
    for item in items:
        login = item.get("login")
        if login is None:
            continue
        for entry in login.get("uris") or []:
            value = entry.get("uri")
            if value:
                uris.append(value)
    print_uri_report(uris, "bitwarden")


# Third-party loggers whose DEBUG/INFO chatter is valuable in the always-on file
# log but noise on the console. The loggers stay at DEBUG (so the file keeps
# everything); console handlers attach a ConsoleNoiseFilter to drop their
# sub-WARNING records, keeping file completeness and console verbosity decoupled.
NOISY_LOGGERS: frozenset[str] = frozenset({"httpx", "httpcore"})


class ConsoleNoiseFilter(logging.Filter):
    """Drop sub-WARNING records of the *muted* loggers from a console handler.

    The muted loggers stay at DEBUG so the file handler still records them; this
    only keeps that detail off whichever console handler it is attached to.
    ``muted`` defaults to every noisy logger (the plain console); ``--debug``
    attaches it muting only ``httpcore``, so the debug console shows httpx
    request lines while httpcore connection spam stays file-only.
    """

    def __init__(self, muted: frozenset[str] = NOISY_LOGGERS) -> None:
        super().__init__()
        self.muted = muted

    def filter(self, record: logging.LogRecord) -> bool:
        root_name = record.name.split(".", 1)[0]
        return not (root_name in self.muted and record.levelno < logging.WARNING)


def resolve_log_path() -> Path:
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


def configure_logging(*, verbose: bool, debug: bool) -> Path | None:
    """Configure console + always-on file logging; return the log path.

    Console verbosity follows the flags (INFO default, VERBOSE with ``-v``, full
    DEBUG with ``-d``).  A file handler is *always* attached at DEBUG, and the
    transport loggers (``httpx``/``httpcore``) use DEBUG too, so the
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
        log_path = resolve_log_path()
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
    dotenv_path = load_dotenv()

    args: Namespace = argparser().parse_args()

    if (args.entry_id or args.item_id) and args.doctor:
        argparser().error("Item selection cannot be combined with --doctor")
    if args.doctor:
        report = collect_report()
        if args.redact:
            report = redact_report(report)
        for line in render_report(report):
            console.print(line, markup=False, highlight=False)
        sys.exit(0 if report.healthy else 1)

    # string options: CLI > env > None/default
    args.keepass_file = with_env(args.keepass_file, "KP2BW_KEEPASS_FILE")
    args.kp_pw = with_env(args.kp_pw, "KP2BW_KEEPASS_PASSWORD")
    args.kp_keyfile = with_env(args.kp_keyfile, "KP2BW_KEEPASS_KEYFILE")
    args.bw_pw = with_env(args.bw_pw, "KP2BW_BITWARDEN_PASSWORD")
    args.bw_org = with_env(args.bw_org, "KP2BW_BITWARDEN_ORG")
    args.bw_coll = with_env(args.bw_coll, "KP2BW_BITWARDEN_COLLECTION")
    args.import_tags = args.import_tags or split_csv_env(
        os.environ.get("KP2BW_IMPORT_TAGS")
    )

    # bool/int options: CLI > env > code default
    try:
        path_to_name = resolve_bool_option(
            args.path_to_name, "KP2BW_PATH_TO_NAME", default=False
        )
        skip_expired = resolve_bool_option(
            args.skip_expired, "KP2BW_SKIP_EXPIRED", default=False
        )
        include_recyclebin = resolve_bool_option(
            args.include_recyclebin, "KP2BW_INCLUDE_RECYCLE_BIN", default=False
        )
        migrate_metadata = resolve_bool_option(
            args.migrate_metadata, "KP2BW_MIGRATE_METADATA", default=True
        )
        update_existing = resolve_bool_option(
            args.update_existing, "KP2BW_UPDATE", default=True
        )
        force_update = resolve_bool_option(
            args.force_update, "KP2BW_FORCE_UPDATE", default=False
        )
        ssh_rules = ()
        if ssh_map_path := with_env(args.ssh_map, "KP2BW_SSH_MAP"):
            try:
                ssh_rules = parse_ssh_rules(
                    json.loads(Path(ssh_map_path).read_text(encoding="utf-8"))
                )
            except OSError, UnicodeError, json.JSONDecodeError:
                raise ValueError("Could not read SSH map as UTF-8 JSON") from None
            except ConversionError as exc:
                raise ValueError(str(exc)) from None
        map_templates = resolve_bool_option(
            args.map_templates, "KP2BW_MAP_TEMPLATES", default=False
        )
        template_map = {}
        template_map_path = with_env(args.template_map, "KP2BW_TEMPLATE_MAP")
        if template_map_path:
            if not map_templates:
                raise ValueError("--template-map requires --map-templates")
            try:
                template_map = parse_template_overrides(
                    json.loads(Path(template_map_path).read_text(encoding="utf-8"))
                )
            except OSError, UnicodeError, json.JSONDecodeError:
                raise ValueError("Could not read template map as UTF-8 JSON") from None
            except ConversionError as exc:
                raise ValueError(str(exc)) from None
        include_oversize_secrets = resolve_bool_option(
            args.include_oversize_secrets,
            "KP2BW_INCLUDE_OVERSIZE_SECRETS",
            default=False,
        )
        archive_history = resolve_bool_option(
            args.archive_history, "KP2BW_ARCHIVE_HISTORY", default=False
        )
        migrate_password_history = resolve_bool_option(
            args.password_history, "KP2BW_PASSWORD_HISTORY", default=True
        )
        # Personal folders are a personal-vault concept; under --bitwarden-org
        # they duplicate the collection tree, so default them off there. Explicit
        # --folder/--no-folder or KP2BW_CREATE_FOLDERS still wins (issue #33).
        create_folders = resolve_bool_option(
            args.create_folders,
            "KP2BW_CREATE_FOLDERS",
            default=not args.bw_org,
        )
        skip_confirm = resolve_bool_option(
            args.skip_confirm, "KP2BW_YES", default=False
        )
        strip_ids = resolve_bool_option(
            args.strip_ids, "KP2BW_STRIP_IDS", default=False
        )
        fixup = resolve_bool_option(args.fixup, "KP2BW_FIXUP", default=False)
        migrate_uris = resolve_bool_option(
            args.migrate_uris, "KP2BW_MIGRATE_URIS", default=False
        )
        raw_report = with_env(args.report_uris, "KP2BW_REPORT_URIS")
        report_uris = raw_report.strip().lower() if raw_report else None
        if report_uris not in (None, "keepass", "bitwarden"):
            raise ValueError(
                f"Invalid KP2BW_REPORT_URIS={raw_report!r}; use 'keepass' or 'bitwarden'"
            )
        interpret_uri_syntax = resolve_bool_option(
            args.interpret_uri_syntax, "KP2BW_INTERPRET_URI_SYNTAX", default=True
        )
        totp_pps = resolve_bool_option(args.totp_pps, "KP2BW_TOTP_PPS", default=False)
        uri_match: UriMatchValue = parse_match_name(
            with_env(args.uri_match, "KP2BW_URI_MATCH") or "default"
        )
        verbose = resolve_bool_option(args.verbose, "KP2BW_VERBOSE", default=False)
        debug = resolve_bool_option(args.debug, "KP2BW_DEBUG", default=False)
    except ValueError as exc:
        _ = sys.stderr.write(f"ERROR: {exc}\n\n")
        argparser().print_help()
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
                argparser().print_help()
                sys.exit(2)

    # Bitwarden-only modes read no KeePass database, so the path requirement
    # (and the KeePass password prompt below) is skipped for them.
    if args.preview_target and not args.preview:
        argparser().error("--preview-target requires --preview")
    if args.preview and (fixup or strip_ids or migrate_uris or report_uris):
        argparser().error(
            "--preview cannot be combined with maintenance or URI reports"
        )
    if args.preview and args.item_id and not args.preview_target:
        argparser().error("--item-id requires --preview-target when previewing")
    if (args.entry_id or args.item_id) and (
        fixup or strip_ids or migrate_uris or report_uris
    ):
        argparser().error("Item selection is only available for migration")
    if fixup and (strip_ids or migrate_uris or report_uris):
        argparser().error("--fixup cannot be combined with another maintenance mode")
    if fixup and args.bw_coll in {"auto", "nested"}:
        argparser().error("--fixup requires a fixed collection ID")
    bitwarden_only = fixup or strip_ids or migrate_uris or report_uris == "bitwarden"
    if not bitwarden_only and not args.keepass_file:
        _ = sys.stderr.write(
            "ERROR: KeePass database path is required "
            "(positional FILE or KP2BW_KEEPASS_FILE)\n\n"
        )
        argparser().print_help()
        sys.exit(2)

    if args.bw_coll and not args.bw_org:
        _ = sys.stderr.write(
            "ERROR: --bitwarden-collection requires --bitwarden-org\n\n"
        )
        argparser().print_help()
        sys.exit(2)

    # logging
    #   default : INFO via RichHandler  — httpx quiet on console, file gets all
    #   -v      : VERBOSE for kp2bw     — per-entry detail on console
    #   -d      : DEBUG for everything  — raw format, httpx included on console
    # A full-detail DEBUG log is always written to a file regardless of the above.
    log_path = configure_logging(verbose=verbose, debug=debug)
    if dotenv_path:
        logger.info(f"Loaded environment from {dotenv_path}")
    if log_path is not None:
        logger.info(f"Writing full debug log to {log_path}")
    logger.log(
        VERBOSE,
        f"{__title__} {__version__} on Python {platform.python_version()} "
        f"({sys.platform})",
    )

    # --report-uris keepass reads only the KeePass database (no Bitwarden, no bw
    # CLI), so it short-circuits before the bw availability check.
    if report_uris == "keepass":
        kp_pw = read_password(args.kp_pw, "Please enter your KeePass 2.x db password: ")
        assert args.keepass_file is not None
        try:
            uris = collect_keepass_uris(
                args.keepass_file,
                kp_pw,
                args.kp_keyfile,
                uri_match=uri_match,
                interpret_uri_syntax=interpret_uri_syntax,
            )
        except (ConversionError, OSError, ValueError) as exc:
            fail(exc)
        print_uri_report(uris, "keepass")
        return

    # Verify the Bitwarden CLI is available before prompting for secrets, so the
    # user isn't asked for passwords only to hit a missing-`bw` failure later.
    if not args.preview or args.preview_target:
        try:
            ensure_bw_available()
        except BitwardenClientError as exc:
            fail(exc)

    # --report-uris bitwarden reads the live vault (no KeePass) and prints a
    # read-only collision report.
    if report_uris == "bitwarden":
        run_report_uris_bitwarden(
            bitwarden_password_arg=args.bw_pw,
            org_id=args.bw_org,
            collection_id=args.bw_coll,
        )
        return

    if fixup:
        run_fixup(
            args.bw_pw,
            org_id=args.bw_org,
            collection_id=args.bw_coll,
            skip_confirm=skip_confirm,
            uri_match=uri_match,
            interpret_uri_syntax=interpret_uri_syntax,
        )
        return

    # --strip-ids short-circuits migration entirely: it only touches Bitwarden
    # (remove kp2bw's dedup stamps), so it needs neither the bw-setup spiel nor a
    # KeePass password. It handles its own confirmation and Bitwarden password.
    if strip_ids:
        run_strip_ids(
            bitwarden_password_arg=args.bw_pw,
            org_id=args.bw_org,
            collection_id=args.bw_coll,
            skip_confirm=skip_confirm,
        )
        return

    # --migrate-uris is likewise a Bitwarden-only upgrade pass (no KeePass).
    if migrate_uris:
        run_migrate_uris(
            bitwarden_password_arg=args.bw_pw,
            org_id=args.bw_org,
            collection_id=args.bw_coll,
            skip_confirm=skip_confirm,
            uri_match=uri_match,
            interpret_uri_syntax=interpret_uri_syntax,
        )
        return

    # bw confirmation
    if not skip_confirm and not args.preview:
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
    kp_pw: str = read_password(
        args.kp_pw, "Please enter your KeePass 2.x db password: "
    )
    bw_pw: str = (
        ""
        if args.preview and not args.preview_target
        else read_password(args.bw_pw, "Please enter your Bitwarden password: ")
    )

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
        force_update=force_update,
        include_oversize_secrets=include_oversize_secrets,
        map_templates=map_templates,
        template_map=template_map,
        ssh_rules=ssh_rules,
        archive_history=archive_history,
        migrate_password_history=migrate_password_history,
        create_folders=create_folders,
        uri_match=uri_match,
        interpret_uri_syntax=interpret_uri_syntax,
        totp_pps=totp_pps,
        checkpoint_path=with_env(args.checkpoint, "KP2BW_CHECKPOINT"),
        entry_id=args.entry_id,
        item_id=args.item_id,
    )
    try:
        if args.preview:
            from .preview import format_preview

            if args.preview_target:
                with BitwardenServeClient(
                    bw_pw,
                    org_id=args.bw_org,
                    collection_id=None
                    if args.bw_coll in COLLECTION_FOLDER_MODES
                    else args.bw_coll,
                ) as target:
                    preview = c.preview(target)
            else:
                preview = c.preview()
            print(
                json.dumps(preview.to_dict(), indent=2)
                if args.preview == "json"
                else format_preview(preview)
            )
            failures = int(
                bool(preview.blockers or any(e.blockers for e in preview.entries))
            )
        else:
            failures = c.convert()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except (BitwardenClientError, ConversionError) as exc:
        fail(exc)

    # Exit non-zero on non-fatal failures (rejected updates/attachment uploads)
    # so wrappers and CI can tell a partial migration from a clean one.
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
