# DiskLens (`disklens`)

> High-Performance Disk Usage, APFS Intelligence, Duplicates & Safe Storage Cleanup

[![CI](https://github.com/VinitSurve/disklens/actions/workflows/ci.yml/badge.svg)](https://github.com/VinitSurve/disklens/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-brightgreen.svg)](https://www.python.org/)

`disklens` is a fast, local-first CLI utility for macOS and POSIX systems that provides storage intelligence, APFS container and volume breakdown, fast iterative directory analysis, multi-stage duplicate file detection, and preview-first safe developer cleanup.

---

## Features

- **APFS Storage Intelligence:** Native macOS APFS container and volume analysis via `diskutil apfs list` and `diskutil info`. Correctly distinguishes APFS container capacity ceiling from individual volume usage, reports shared free capacity **only once**, and breaks down all container volumes (System, Data, Preboot, Recovery, VM).
- **Fast Iterative Scanner:** Traverses 100k+ file directory hierarchies without recursion limits using an iterative post-order stack.
- **Two-Stage Duplicate Finder:** Fast deduplication grouping by byte size, partial header hashing (64 KiB), and streaming full SHA-256 with hard-link deduplication.
- **Preview-First Cleanup:** Identifies disposable developer artifacts (`node_modules`, `.pytest_cache`, `.venv`, `target/`, `build/`, `dist/`). Requires explicit interactive confirmation or `--force`/`--yes` before deleting.
- **Protected Path Guards:** Refuses to delete or mutate macOS system roots, `/Library`, `/System`, `$HOME`, or credential directories (`~/.ssh`, `~/.aws`, `~/.gnupg`).
- **Exporting & Reporting:** Generates structured reports in JSON and RFC 4180 CSV formats.
- **Zero Telemetry:** No analytics, no network daemons, no cloud requirements.

---

## Installation

### Using pipx (Recommended for standalone CLI use)

```bash
pipx install git+https://github.com/VinitSurve/disklens.git
```

Or install from a local checkout:

```bash
git clone https://github.com/VinitSurve/disklens.git
cd disklens
pipx install .
```

### Using pip (in an active virtual environment)

```bash
pip install .
```

---

## Quick Start

```bash
# View APFS container and volume storage breakdown
disklens info

# Analyze current directory tree and top consumers
disklens analyze .

# Find top 20 largest files larger than 50MB
disklens largest ~/Downloads --limit 20 --min-size 50MB

# Detect true duplicate files using 2-stage chunk hashing
disklens duplicates ~/Documents

# Preview reclaimable build artifacts and dependencies (dry-run)
disklens cleanup ~/Projects --preview

# Export scanned file records to CSV
disklens export ~/Documents --format csv --output ~/Documents/storage.csv
```

---

## APFS Storage Reporting Semantics

On Apple Silicon and modern macOS systems, APFS volumes inside a container dynamically share free space. Standard tools like `df` can misleadingly imply that every mounted volume has its own independent free capacity, artificially multiplying available free space.

`disklens info` fixes this by:
1. Identifying the APFS container reference (e.g. `disk3`) for the target directory.
2. Reporting container capacity ceiling, total allocated space, and **shared free space only once** at the container level.
3. Breaking down capacity consumed by every volume in the container (System snapshot, Data, Preboot, Recovery, VM).
4. Clearly reporting target path context separately from container-level metrics.
5. Providing automatic fallback to standard POSIX volume metrics on non-APFS filesystems and Linux.

---

## Command Reference

| Command | Description |
|---|---|
| `disklens` / `disklens info [PATH]` | Show volume storage overview and APFS container breakdown. |
| `disklens analyze [PATH]` | Iteratively scan directory usage, tree hierarchy to `--depth`, largest folders, and categories. |
| `disklens largest [PATH]` | List largest regular files (`--limit N`, `--min-size SIZE`). |
| `disklens duplicates [PATH]` | Detect duplicate files via 2-stage content hashing; separates hard links. |
| `disklens cleanup [PATH]` | Preview or delete (`--delete`) safe disposable build artifacts. |
| `disklens report [PATH]` | Generate comprehensive storage report (`--json` or `--output FILE`). |
| `disklens export [PATH]` | Export scanned entries to RFC 4180 CSV or JSON (`--format csv\|json`). |
| `disklens config` | View, set, or reset `disklens` configuration (`show`, `set`, `reset`). |

### Global Flags

All commands support the following global flags:

- `--json`: Output machine-readable JSON on `stdout`.
- `--quiet`: Suppress decorative banners, headings, and progress indicators.
- `--verbose`: Print diagnostic debugging details to `stderr`.
- `--no-color`: Disable ANSI color escapes (respects `NO_COLOR=1`).
- `--help`, `-h`: Show usage assistance.
- `--version`: Display `disklens` version.

---

## Configuration

`disklens` stores its configuration in standard platform directories:
- **Config & Data:** `~/Library/Application Support/devtoolkit/disklens/config.json`
- **Logs:** `~/Library/Logs/devtoolkit/disklens/disklens.log`

Override with `DEVTOOLKIT_HOME=/custom/path`.

Example configuration management:
```bash
# View configuration
disklens config show

# Set default depth for analysis
disklens config set default_depth 3

# Reset configuration to defaults
disklens config reset --yes
```

---

## Safety Considerations

- **Non-Destructive Defaults:** `disklens cleanup` defaults to preview mode. No file is deleted unless `--delete` is passed along with explicit user confirmation.
- **Symlink Protection:** Symlinks are never traversed or followed during recursive scanning or cleanup, preventing traversal loops and accidental deletions outside target trees.
- **Protected Paths:** `disklens` refuses to analyze or delete protected paths including `/`, `/System`, `/Library`, `/Applications`, `~/.ssh`, `~/.gnupg`, and `~/.aws`.

---

## Development Setup

```bash
git clone https://github.com/VinitSurve/disklens.git
cd disklens
make dev
make test
make check
```

---

## Running Tests

```bash
# Run full pytest suite
pytest -v

# Run fast unit tests
pytest -m "not slow" -q
```

---

## Known Limitations

- **APFS Snapshots:** Read-only system snapshots (`/dev/disk3s1s1`) report capacity consumed as sealed snapshots.
- **Permission Denied Paths:** System files protected by macOS System Integrity Protection (SIP) or TCC (e.g. `~/Library/Containers`) cannot be read without Full Disk Access granted to Terminal.

---

## License

This project is licensed under the [MIT License](LICENSE).
