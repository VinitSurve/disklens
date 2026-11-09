"""Command line interface for disklens."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated

import typer

from disklens.cleanup import (
    CleanupExecutionResult,
    discover_cleanup_candidates,
    execute_cleanup,
)
from disklens.common.cli import add_config_commands, create_app, exit_with, get_ctx, run_app
from disklens.common.exceptions import ExitCode, SafetyError, UsageError
from disklens.common.fsutil import parse_size
from disklens.common.output import dumps_json
from disklens.common.safety import require_confirmation
from disklens.config import SCHEMA, load_config
from disklens.duplicates import find_duplicates
from disklens.export import (
    build_report,
    format_export_csv,
    format_export_json,
    format_report_text,
    write_output_file,
)
from disklens.render import (
    render_cleanup_execution,
    render_cleanup_plan,
    render_duplicates,
    render_largest_files,
    render_report,
    render_scan_result,
    render_storage_overview,
)
from disklens.scanner import get_storage_overview, scan_directory

TOOL = "disklens"


def _default_info(ctx: typer.Context) -> None:
    """Run volume storage overview when ``disklens`` is invoked without a subcommand."""
    tctx = get_ctx(ctx)
    overview = get_storage_overview(".")
    tctx.out.emit(overview, lambda o: render_storage_overview(o, overview))


app = create_app(
    TOOL,
    "Analyze disk usage, find large files and duplicates, and plan safe cleanups.",
    default=_default_info,
)
add_config_commands(app, TOOL, SCHEMA)


@app.command("info")
def info_cmd(
    ctx: typer.Context,
    path: Annotated[
        Path,
        typer.Argument(help="Path whose backing volume should be inspected."),
    ] = Path(),
) -> None:
    """Show volume storage overview (total, used, available, and mounted volumes)."""
    tctx = get_ctx(ctx)
    overview = get_storage_overview(path)
    tctx.out.emit(overview, lambda o: render_storage_overview(o, overview))


@app.command("analyze")
def analyze_cmd(
    ctx: typer.Context,
    path: Annotated[
        Path,
        typer.Argument(help="Directory to analyze recursively."),
    ] = Path(),
    depth: Annotated[
        int | None,
        typer.Option("--depth", "-d", help="Directory display depth for tree/table."),
    ] = None,
    hidden: Annotated[
        bool | None,
        typer.Option(
            "--hidden/--no-hidden",
            help="Include or exclude dotfiles and hidden directories.",
        ),
    ] = None,
    cross_device: Annotated[
        bool,
        typer.Option("--cross-device", help="Traverse across filesystem mount boundaries."),
    ] = False,
    limit: Annotated[
        int | None,
        typer.Option("--limit", "-n", help="Number of largest files and folders to retain."),
    ] = None,
) -> None:
    """Recursively analyze directory usage, categories, largest items, and hard links."""
    tctx = get_ctx(ctx)
    cfg = load_config(tctx.paths)
    eff_depth = cfg.default_depth if depth is None else depth
    eff_hidden = cfg.include_hidden if hidden is None else hidden
    eff_limit = cfg.top_n if limit is None else limit
    threshold_bytes = cfg.large_project_threshold_mb * 1000 * 1000

    with tctx.out.progress("Scanning directory tree...") as prog:
        result = scan_directory(
            path,
            depth=eff_depth,
            include_hidden=eff_hidden,
            cross_device=cross_device,
            top_n=eff_limit,
            large_project_threshold_bytes=threshold_bytes,
            extra_cleanup_names=cfg.extra_cleanup_names,
            progress=prog,
        )

    tctx.out.emit(result, lambda o: render_scan_result(o, result))


@app.command("largest")
def largest_cmd(
    ctx: typer.Context,
    path: Annotated[
        Path,
        typer.Argument(help="Directory to search for largest files."),
    ] = Path(),
    limit: Annotated[
        int | None,
        typer.Option("--limit", "-n", help="Maximum number of files to return."),
    ] = None,
    min_size: Annotated[
        str,
        typer.Option("--min-size", help="Minimum file size (e.g. 10MB, 512KiB, 1024)."),
    ] = "0B",
    hidden: Annotated[
        bool | None,
        typer.Option("--hidden/--no-hidden", help="Include or exclude hidden files."),
    ] = None,
    cross_device: Annotated[
        bool,
        typer.Option("--cross-device", help="Traverse across filesystem boundaries."),
    ] = False,
) -> None:
    """List the largest regular files under PATH."""
    tctx = get_ctx(ctx)
    cfg = load_config(tctx.paths)
    eff_limit = cfg.top_n if limit is None else limit
    eff_hidden = cfg.include_hidden if hidden is None else hidden
    min_size_bytes = parse_size(min_size)

    with tctx.out.progress("Scanning for largest files...") as prog:
        scan = scan_directory(
            path,
            depth=0,
            include_hidden=eff_hidden,
            cross_device=cross_device,
            top_n=eff_limit,
            min_file_size=min_size_bytes,
            extra_cleanup_names=cfg.extra_cleanup_names,
            progress=prog,
        )

    payload = {
        "root": scan.root,
        "limit": eff_limit,
        "min_size_bytes": min_size_bytes,
        "count": len(scan.largest_files),
        "unreadable_count": scan.unreadable_count,
        "files": scan.largest_files,
    }
    tctx.out.emit(
        payload,
        lambda o: render_largest_files(
            o,
            scan.root,
            scan.largest_files,
            limit=eff_limit,
            min_size_bytes=min_size_bytes,
            unreadable_count=scan.unreadable_count,
        ),
    )


@app.command("duplicates")
def duplicates_cmd(
    ctx: typer.Context,
    path: Annotated[
        Path,
        typer.Argument(help="Directory to scan for duplicate files."),
    ] = Path(),
    min_size: Annotated[
        str,
        typer.Option("--min-size", help="Minimum file size to consider (e.g. 1KB, 10MB)."),
    ] = "1B",
    include_empty: Annotated[
        bool,
        typer.Option("--include-empty", help="Include 0-byte empty files in duplicate groups."),
    ] = False,
    hidden: Annotated[
        bool | None,
        typer.Option("--hidden/--no-hidden", help="Include or exclude hidden files."),
    ] = None,
    cross_device: Annotated[
        bool,
        typer.Option("--cross-device", help="Traverse across filesystem boundaries."),
    ] = False,
) -> None:
    """Find duplicate files using two-stage SHA-256 hashing and separate hard links."""
    tctx = get_ctx(ctx)
    cfg = load_config(tctx.paths)
    eff_hidden = cfg.include_hidden if hidden is None else hidden
    min_bytes = parse_size(min_size)

    with tctx.out.progress("Finding duplicate files...") as prog:
        result = find_duplicates(
            path,
            min_size_bytes=min_bytes,
            include_empty=include_empty,
            include_hidden=eff_hidden,
            cross_device=cross_device,
            partial_kib=cfg.hash_partial_kib,
            progress=prog,
        )

    tctx.out.emit(result, lambda o: render_duplicates(o, result))


@app.command("cleanup")
def cleanup_cmd(
    ctx: typer.Context,
    path: Annotated[
        Path | None,
        typer.Argument(help="Directory to inspect for cleanup candidates (default: .)."),
    ] = None,
    path_opt: Annotated[
        Path | None,
        typer.Option("--path", "-p", help="Directory to inspect for cleanup candidates."),
    ] = None,
    preview: Annotated[
        bool,
        typer.Option("--preview", help="Preview cleanup candidates without deleting (default)."),
    ] = False,
    delete: Annotated[
        bool,
        typer.Option("--delete", help="Delete discovered candidates after confirmation."),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Simulate deletion without modifying the filesystem."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Confirm deletion non-interactively."),
    ] = False,
    category: Annotated[
        str | None,
        typer.Option(
            "--category",
            "-c",
            help="Filter by category (build_artifacts, dependencies, caches, temp, logs).",
        ),
    ] = None,
    older_than: Annotated[
        int | None,
        typer.Option("--older-than", help="Minimum age in days for log files."),
    ] = None,
    hidden: Annotated[
        bool | None,
        typer.Option("--hidden/--no-hidden", help="Include or exclude hidden entries."),
    ] = None,
    cross_device: Annotated[
        bool,
        typer.Option("--cross-device", help="Traverse across filesystem boundaries."),
    ] = False,
) -> None:
    """Identify safe cleanup candidates (preview by default; --delete to remove)."""
    if preview and delete:
        raise UsageError("--preview and --delete cannot be combined.")
    if path is not None and path_opt is not None and path != path_opt:
        raise UsageError("Specify either positional PATH or --path, not both.")
    target_path = path_opt if path_opt is not None else (path if path is not None else Path())

    tctx = get_ctx(ctx)
    cfg = load_config(tctx.paths)
    eff_age = cfg.cleanup_age_days if older_than is None else older_than
    eff_hidden = cfg.include_hidden if hidden is None else hidden
    mode = "dry_run" if dry_run else ("delete" if delete else "preview")

    with tctx.out.progress("Discovering cleanup candidates...") as prog:
        plan = discover_cleanup_candidates(
            target_path,
            category=category,
            older_than_days=eff_age,
            include_hidden=eff_hidden,
            cross_device=cross_device,
            extra_cleanup_names=cfg.extra_cleanup_names,
            mode=mode,
            progress=prog,
        )

    if not delete and not dry_run:
        tctx.out.emit(plan, lambda o: render_cleanup_plan(o, plan))
        return

    if dry_run:
        exec_res = execute_cleanup(plan, dry_run=True)
        tctx.out.emit(exec_res, lambda o: render_cleanup_execution(o, exec_res))
        return

    # --delete without --dry-run
    if not plan.candidates:
        empty_res = CleanupExecutionResult(
            root=plan.root,
            dry_run=False,
            deleted_count=0,
            skipped_count=0,
            failed_count=0,
            bytes_freed=0,
            bytes_freed_human="0 B",
            outcomes=[],
            plan=plan,
        )
        tctx.out.emit(empty_res, lambda o: render_cleanup_execution(o, empty_res))
        return

    if not tctx.options.json:
        render_cleanup_plan(tctx.out, plan)

    prompt_msg = (
        f"Delete {plan.candidate_count} candidate(s) "
        f"({plan.total_reclaimable_human}) under {plan.root}?"
    )
    require_confirmation(tctx.out, prompt_msg, assume_yes=yes)

    exec_res = execute_cleanup(plan, dry_run=False)
    if tctx.options.json:
        tctx.out.emit_json(exec_res)
    else:
        no_dup_plan = CleanupExecutionResult(
            root=exec_res.root,
            dry_run=exec_res.dry_run,
            deleted_count=exec_res.deleted_count,
            skipped_count=exec_res.skipped_count,
            failed_count=exec_res.failed_count,
            bytes_freed=exec_res.bytes_freed,
            bytes_freed_human=exec_res.bytes_freed_human,
            outcomes=exec_res.outcomes,
            plan=None,
        )
        render_cleanup_execution(tctx.out, no_dup_plan)

    if exec_res.failed_count > 0:
        exit_with(ExitCode.ERROR)


@app.command("report")
def report_cmd(
    ctx: typer.Context,
    path: Annotated[
        Path,
        typer.Argument(help="Directory to generate a storage report for."),
    ] = Path(),
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the report to a file (atomic)."),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Allow overwriting an existing --output file."),
    ] = False,
    depth: Annotated[
        int | None,
        typer.Option("--depth", "-d", help="Directory tree depth for the report."),
    ] = None,
    hidden: Annotated[
        bool | None,
        typer.Option("--hidden/--no-hidden", help="Include or exclude hidden entries."),
    ] = None,
    cross_device: Annotated[
        bool,
        typer.Option("--cross-device", help="Traverse across filesystem boundaries."),
    ] = False,
) -> None:
    """Generate a comprehensive human or JSON storage analysis report."""
    tctx = get_ctx(ctx)
    cfg = load_config(tctx.paths)
    eff_depth = cfg.default_depth if depth is None else depth
    eff_hidden = cfg.include_hidden if hidden is None else hidden
    threshold_bytes = cfg.large_project_threshold_mb * 1000 * 1000

    with tctx.out.progress("Building storage report...") as prog:
        scan = scan_directory(
            path,
            depth=eff_depth,
            include_hidden=eff_hidden,
            cross_device=cross_device,
            top_n=cfg.top_n,
            large_project_threshold_bytes=threshold_bytes,
            extra_cleanup_names=cfg.extra_cleanup_names,
            progress=prog,
        )
        overview = get_storage_overview(scan.root)
        try:
            cleanup_plan = discover_cleanup_candidates(
                scan.root,
                older_than_days=cfg.cleanup_age_days,
                include_hidden=eff_hidden,
                cross_device=cross_device,
                extra_cleanup_names=cfg.extra_cleanup_names,
                progress=prog,
            )
        except SafetyError:
            cleanup_plan = None

    report = build_report(scan, overview.primary, cleanup_plan)

    written_path: Path | None = None
    if output is not None:
        is_json_file = tctx.options.json or output.suffix.lower() == ".json"
        file_content = dumps_json(report) + "\n" if is_json_file else format_report_text(report)
        written_path = write_output_file(output, file_content, force=force)

    def _render(o: object) -> None:
        render_report(tctx.out, report)
        if written_path is not None:
            tctx.out.success(f"Report written to {written_path}")

    tctx.out.emit(report, _render)


@app.command("export")
def export_cmd(
    ctx: typer.Context,
    path: Annotated[
        Path,
        typer.Argument(help="Directory to scan and export."),
    ] = Path(),
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Export format: csv or json."),
    ] = "csv",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Destination file path (defaults to stdout)."),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite --output if it already exists."),
    ] = False,
    hidden: Annotated[
        bool | None,
        typer.Option("--hidden/--no-hidden", help="Include or exclude hidden entries."),
    ] = None,
    cross_device: Annotated[
        bool,
        typer.Option("--cross-device", help="Traverse across filesystem boundaries."),
    ] = False,
) -> None:
    """Export scanned paths, sizes, types, categories, and confidence to CSV or JSON."""
    norm_fmt = fmt.strip().lower()
    if norm_fmt not in ("csv", "json"):
        raise UsageError(
            f"Unsupported export format: {fmt!r}",
            hint="Use --format csv or --format json.",
        )

    tctx = get_ctx(ctx)
    cfg = load_config(tctx.paths)
    eff_hidden = cfg.include_hidden if hidden is None else hidden
    threshold_bytes = cfg.large_project_threshold_mb * 1000 * 1000

    with tctx.out.progress("Scanning directory for export...") as prog:
        scan = scan_directory(
            path,
            depth=cfg.default_depth,
            include_hidden=eff_hidden,
            cross_device=cross_device,
            top_n=cfg.top_n,
            large_project_threshold_bytes=threshold_bytes,
            extra_cleanup_names=cfg.extra_cleanup_names,
            collect_records=True,
            progress=prog,
        )

    content = (
        format_export_csv(scan.export_records) if norm_fmt == "csv" else format_export_json(scan)
    )

    if output is not None:
        written = write_output_file(output, content, force=force)
        payload = {
            "root": scan.root,
            "format": norm_fmt,
            "output": str(written),
            "rows": len(scan.export_records),
        }
        tctx.out.emit(
            payload,
            lambda o: o.success(
                f"Exported {len(scan.export_records)} records ({norm_fmt.upper()}) to {written}"
            ),
        )
        return

    if norm_fmt == "json" or tctx.options.json:
        if norm_fmt == "json":
            sys.stdout.write(content)
            sys.stdout.flush()
        else:
            tctx.out.emit_json(
                {
                    "root": scan.root,
                    "format": "csv",
                    "rows": len(scan.export_records),
                    "records": scan.export_records,
                }
            )
    else:
        sys.stdout.write(content)
        sys.stdout.flush()


def main(argv: Sequence[str] | None = None) -> int:
    """Console-script entry point; returns the process exit code."""
    return run_app(app, tool=TOOL, argv=argv)
