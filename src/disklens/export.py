"""Structured reporting and CSV/JSON export helpers for disklens."""

from __future__ import annotations

import csv
import datetime as dt
import io
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from disklens.cleanup import CleanupCandidate, CleanupPlan
from disklens.common.exceptions import SafetyError, UsageError
from disklens.common.fsutil import atomic_write_text
from disklens.common.output import dumps_json
from disklens.common.paths import ensure_not_protected, resolve_user_path
from disklens.scanner import ExportRecord, ScanResult, VolumeInfo

CSV_COLUMNS: tuple[str, ...] = ("path", "size_bytes", "type", "category", "confidence")


@dataclass(frozen=True)
class DiskReport:
    """Comprehensive storage analysis report for ``disklens report``."""

    generated_at: str
    root: str
    volume: VolumeInfo
    scan: ScanResult
    cleanup_candidate_count: int
    cleanup_reclaimable_bytes: int
    cleanup_reclaimable_human: str
    cleanup_candidates: list[CleanupCandidate]


def build_report(
    scan: ScanResult,
    volume: VolumeInfo,
    cleanup_plan: CleanupPlan | None,
) -> DiskReport:
    """Combine scan, volume usage, and cleanup summary into a :class:`DiskReport`."""
    candidates = cleanup_plan.candidates if cleanup_plan is not None else []
    reclaim_b = cleanup_plan.total_reclaimable_bytes if cleanup_plan is not None else 0
    reclaim_h = cleanup_plan.total_reclaimable_human if cleanup_plan is not None else "0 B"
    return DiskReport(
        generated_at=dt.datetime.now(dt.UTC).isoformat(),
        root=scan.root,
        volume=volume,
        scan=scan,
        cleanup_candidate_count=len(candidates),
        cleanup_reclaimable_bytes=reclaim_b,
        cleanup_reclaimable_human=reclaim_h,
        cleanup_candidates=candidates,
    )


def format_export_csv(records: Sequence[ExportRecord]) -> str:
    """Serialize :class:`ExportRecord` items to RFC 4180 CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for rec in records:
        writer.writerow([rec.path, rec.size_bytes, rec.type, rec.category, rec.confidence])
    return buf.getvalue()


def format_export_json(scan: ScanResult) -> str:
    """Serialize scan summary and export records as formatted JSON."""
    payload = {
        "root": scan.root,
        "total_bytes": scan.total_bytes,
        "total_human": scan.total_human,
        "file_count": scan.file_count,
        "dir_count": scan.dir_count,
        "symlink_count": scan.symlink_count,
        "special_count": scan.special_count,
        "hardlink_count": scan.hardlink_count,
        "unreadable_count": scan.unreadable_count,
        "records": scan.export_records,
    }
    return dumps_json(payload) + "\n"


def format_report_text(report: DiskReport) -> str:
    """Render a plain-text / Markdown storage report suitable for ``--output FILE``."""
    scan = report.scan
    vol = report.volume
    lines = [
        f"# DiskLens Report: {report.root}",
        f"Generated: {report.generated_at}",
        "",
        "## Volume Summary",
        f"- Mount Point: {vol.mount_point}",
        f"- Total: {vol.total_human} ({vol.total_bytes} B)",
        f"- Used: {vol.used_human} ({vol.used_bytes} B, {vol.percent_used:.1f}%)",
        f"- Available: {vol.available_human} ({vol.available_bytes} B)",
        "",
        "## Directory Scan Summary",
        f"- Root: {scan.root}",
        f"- Total Size: {scan.total_human} ({scan.total_bytes} B)",
        f"- Files: {scan.file_count}",
        f"- Directories: {scan.dir_count}",
        f"- Symlinks: {scan.symlink_count} ({scan.symlink_bytes} B)",
        f"- Special Files: {scan.special_count}",
        f"- Hard Links Deduplicated: {scan.hardlink_count} ({scan.hardlink_saved_human} saved)",
        f"- Unreadable Paths: {scan.unreadable_count} paths unreadable",
        "",
        "## Storage Categories",
    ]
    if scan.categories:
        for cat in scan.categories:
            lines.append(
                f"- {cat.label} ({cat.category}): {cat.size_human} "
                f"({cat.percent_of_total:.1f}%, {cat.file_count} items, "
                f"confidence={cat.confidence})"
            )
    else:
        lines.append("- (no categorized files)")

    lines.extend(["", "## Largest Files"])
    if scan.largest_files:
        for f in scan.largest_files[:10]:
            lines.append(f"- {f.size_human}  {f.path}  [{f.category}, {f.confidence}]")
    else:
        lines.append("- (none)")

    reclaim_line = (
        f"- Potential Reclaimable Space: {report.cleanup_reclaimable_human} "
        f"({report.cleanup_reclaimable_bytes} B)"
    )
    lines.extend(
        [
            "",
            "## Cleanup Candidates Summary",
            f"- Candidates Found: {report.cleanup_candidate_count}",
            reclaim_line,
        ]
    )
    for cand in report.cleanup_candidates[:15]:
        lines.append(
            f"- {cand.size_human}  {cand.path}  "
            f"[{cand.category}, {cand.status}, confidence={cand.confidence}] — {cand.explanation}"
        )

    return "\n".join(lines) + "\n"


def write_output_file(
    output_path: str | os.PathLike[str],
    content: str,
    *,
    force: bool = False,
) -> Path:
    """Atomically write ``content`` to ``output_path``, refusing overwrite unless ``force``."""
    resolved = resolve_user_path(output_path)
    ensure_not_protected(resolved, "write output to")
    if resolved.exists() and resolved.is_dir():
        raise UsageError(
            f"Output path is an existing directory: {resolved}",
            hint="Provide a file path for --output.",
        )
    if os.path.lexists(resolved) and not force:
        raise SafetyError(
            f"Refusing to overwrite existing file: {resolved}",
            hint="Re-run with --force to overwrite the existing file.",
        )
    atomic_write_text(resolved, content, mode=0o644)
    return resolved
