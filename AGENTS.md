# AGENTS.md — Coding Agent Guidelines for kp2bw

## Project Overview

KeePass 2.x to Bitwarden converter CLI tool. Fork of
[jampe/kp2bw](https://github.com/jampe/kp2bw). Migrates entries, folders,
attachments, custom properties, TOTP, passkeys, and metadata via the `bw` CLI.

## Project Structure

```tree
src/kp2bw/
├── __init__.py           # Package version via importlib.metadata
├── __main__.py           # python -m kp2bw support
├── py.typed              # PEP 561 marker
├── bitwardenclient.py    # Wraps `bw` CLI (subprocess)
├── cli.py                # Argument parsing, entry point
├── convert.py            # Core migration logic
└── exceptions.py         # BitwardenClientError, ConversionError

packages/pykeepass-stubs/ # uv workspace member — PEP 561 type stubs
├── pyproject.toml
└── src/pykeepass-stubs/
    ├── py.typed
    ├── __init__.pyi
    ├── attachment.pyi
    ├── baseelement.pyi
    ├── entry.pyi
    ├── exceptions.pyi
    ├── group.pyi
    └── pykeepass.pyi
```

- **src layout** — all source under `src/kp2bw/`
- **Workspace** — root `pyproject.toml` declares `packages/pykeepass-stubs` as a
  workspace member; stubs are installed as an editable dev dependency
- Entry point: `kp2bw.cli:main`
- No tests exist yet

## Build / Lint / Check Commands

All commands use `uv` as the package manager and task runner.

```bash
# Install dependencies
uv sync

# Run the tool
uv run kp2bw <keepass_file>

# Lint (ruff with preview mode, targeting py314)
uv run ruff check              # check only
uv run ruff check --fix        # auto-fix what's possible

# Format
uv run ruff format             # Python files
uv run tombi fmt pyproject.toml  # TOML formatting (run via dprint if configured)

# Type checking
uv run ty check                # primary type checker (Astral)
uv run basedpyright            # secondary type checker

# Run a single check on one file
uv run ruff check src/kp2bw/convert.py
uv run ty check src/kp2bw/convert.py
```

**Always run `uv run ty check` and `uv run ruff check` before finishing work.**
Both must pass with zero errors.

## Python Version

- **Requires Python >= 3.14** (set in `.python-version` and `pyproject.toml`)

## Code Style

### Imports

Standard isort ordering enforced by ruff (`I001`):

```python
import base64  # 1. stdlib (alphabetical)
import logging

from pykeepass import PyKeePass  # 2. third-party

from .bitwardenclient import BitwardenClient  # 3. relative imports
from .exceptions import ConversionError
```

Use **relative imports** for intra-package references (`from .module import X`).

### Naming Conventions

| Kind              | Style              | Example                        |
| ----------------- | ------------------ | ------------------------------ |
| Classes           | PascalCase         | `BitwardenClient`, `Converter` |
| Functions/methods | snake_case         | `create_entry`, `_load_data`   |
| Private members   | leading underscore | `self._entries`, `_exec`       |
| Constants         | UPPER_SNAKE_CASE   | `MAX_BW_ITEM_LENGTH`           |

### String Formatting

Use **f-strings exclusively**. No `str.format()` or `%` formatting.

```python
logger.info(f"Found {total} entries in KeePass DB. Parsing now...")
```

### Docstrings

One-line imperative style on non-trivial methods. No multi-line docstrings.

```python
def _is_in_recyclebin(self, entry, recyclebin_group):
    """Check if an entry is inside the recycle bin group."""
```

### Logging

Each module creates its own logger. Never use the root `logging.xxx()` calls.

```python
logger = logging.getLogger(__name__)

# Usage:
logger.debug(...)  # command execution details
logger.info(...)  # progress reporting
logger.warning(...)  # non-fatal issues
logger.error(...)  # operation failures
```

### Error Handling

Use the project's custom exceptions, never bare `Exception`:

```python
from .exceptions import BitwardenClientError  # for bw CLI failures
from .exceptions import ConversionError  # for migration logic errors
```

Catch specific exceptions with **tuple syntax** (not comma-separated):

```python
# CORRECT
except (ConversionError, KeyError, AttributeError):

# WRONG — this is Python 2 syntax and a runtime bug
except ConversionError, KeyError, AttributeError:
```

For non-fatal errors during batch processing, log a warning and continue:

```python
except (ConversionError, KeyError):
    logger.warning(f"!! Could not resolve entry for {title} !!")
```

### Type Hints

All source modules have type annotations. Both `ty` and `basedpyright` are
configured as dev dependencies. New code should include type hints.

### Keyword-Only Arguments

New optional parameters on `Converter.__init__` go after the `*` separator:

```python
def __init__(self, ..., import_tags, *, skip_expired=False, new_flag=False):
```

## Ruff Configuration

From `pyproject.toml`:

```toml
[tool.ruff]
preview        = true
target-version = "py314"
```

Preview mode is enabled — all preview rules are active. No rules are explicitly
selected or ignored, so the **default rule set** applies.

## Architecture Notes

- `BitwardenClient` wraps the `bw` CLI via `subprocess.check_output(shell=True)`
- All data flows through Python dicts (no dataclasses/Pydantic)
- Entries are stored as tuples: `(folder, bw_item_object)` or
  `(folder, bw_item_object, attachments)`
- KeePassXC passkey attributes (`KPEX_PASSKEY_*`) are converted to Bitwarden
  `fido2Credentials` and excluded from regular custom fields
- The `convert()` method is the main orchestrator: `_load_keepass_data()` →
  `_resolve_entries_with_references()` → `_create_bitwarden_items_for_entries()`

## Dependencies

| Package        | Purpose                  |
| -------------- | ------------------------ |
| `pykeepass`    | Read KeePass .kdbx files |
| `ruff`         | Linter + formatter (dev) |
| `ty`           | Type checker (dev)       |
| `basedpyright` | Type checker (dev)       |
| `lxml`         | XML processing (dev)     |
| `types-lxml`   | lxml type stubs (dev)    |
| `tombi`        | TOML formatter (dev)     |
