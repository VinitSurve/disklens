"""Human-friendly terminal rendering for all disklens commands via Output."""

from __future__ import annotations

import os
from collections.abc import Sequence

from rich.tree import Tree

from disklens.cleanup import CleanupExecutionResult, CleanupPlan
from disklens.common.output import Output
from disklens.duplicates import DuplicatesResult
from disklens.export import DiskReport
from disklens.scanner import DirEntry, FileEntry, ScanResult, StorageOverview


def render_storage_overview(out: Output, overview: StorageOverview) -> None:
    """Render ``disklens`` / ``disklens info`` output."""
    out.banner()
    if overview.apfs:
        apfs = overview.apfs
        target_kv: list[tuple[str, str]] = [
            ("Target Path", overview.target_path),
        ]
        if overview.target_volume_name and overview.target_mount_point:
            target_kv.append(
                (
                    "Target Volume",
                    f"{overview.target_volume_name} (mounted on {overview.target_mount_point})",
                )
            )
        out.kv(target_kv, title="Target Storage Context")

        out.kv(
            [
                ("Container Reference", apfs.container_id),
                ("Container Capacity", f"{apfs.total_human} ({apfs.total_bytes:,} B)"),
                ("Used by All Volumes", f"{apfs.used_human} ({apfs.percent_used:.1f}%)"),
                (
                    "Shared Free Space",
                    f"{apfs.free_human} ({apfs.free_bytes:,} B) [shared dynamically across all container volumes]",
                ),
            ],
            title="APFS Container Overview",
        )

        if apfs.volumes:
            out.table(
                ["Volume", "Role", "Mount Point", "Capacity Consumed", "% of Container"],
                [
                    (
                        v.name,
                        v.role,
                        v.mount_point,
                        v.used_human,
                        f"{v.percent_of_container:.1f}%",
                    )
                    for v in apfs.volumes
                ],
                title=f"Container Volumes (Shared Free Space: {apfs.free_human})",
                right_align=("Capacity Consumed", "% of Container"),
            )
    else:
        prim = overview.primary
        out.kv(
            [
                ("Target path", overview.target_path),
                ("Total", f"{prim.total_human} ({prim.total_bytes:,} B)"),
                ("Used", f"{prim.used_human} ({prim.percent_used:.1f}%)"),
                ("Available", f"{prim.available_human} ({prim.available_bytes:,} B)"),
            ],
            title="Volume Storage Overview",
        )

        if overview.volumes:
            out.table(
                ["Mount Point", "Filesystem", "Total", "Used", "Available", "Use%"],
                [
                    (
                        v.mount_point,
                        v.filesystem,
                        v.total_human,
                        v.used_human,
                        v.available_human,
                        f"{v.percent_used:.1f}%",
                    )
                    for v in overview.volumes
                ],
                title="Mounted Volumes",
                right_align=("Total", "Used", "Available", "Use%"),
            )

    out.next_steps(
        [
            "disklens analyze .",
            "disklens largest . --limit 20",
            "disklens cleanup --preview",
        ]
    )


def _build_directory_tree(scan: ScanResult) -> Tree:
    """Construct a Rich Tree up to ``scan.depth`` sorted by size descending."""
    tree = Tree(f"{scan.root} ({scan.total_human})")
    if scan.depth <= 0 or not scan.tree_entries:
        return tree

    nodes: dict[str, Tree] = {scan.root: tree}
    by_parent: dict[str, list[DirEntry]] = {}
    for entry in scan.tree_entries:
        parent_str = os.path.dirname(entry.path)
        by_parent.setdefault(parent_str, []).append(entry)

    for children in by_parent.values():
        children.sort(key=lambda c: (-c.size_bytes, c.path))

    # Iterative BFS/DFS by depth so parents exist before children
    for d_level in range(1, scan.depth + 1):
        for entry in scan.tree_entries:
            if entry.depth != d_level:
                continue
            parent_str = os.path.dirname(entry.path)
            parent_node = nodes.get(parent_str, tree)
            conf_tag = (
                f" [{entry.category}, {entry.confidence}]" if entry.category != "other" else ""
            )
            child_node = parent_node.add(f"{entry.name}/ — {entry.size_human}{conf_tag}")
            nodes[entry.path] = child_node

    return tree


def render_scan_result(out: Output, scan: ScanResult) -> None:
    """Render ``disklens analyze`` output."""
    out.banner()
    rows = [
        ("Root", scan.root),
        ("Total size", f"{scan.total_human} ({scan.total_bytes:,} B)"),
        ("Files", f"{scan.file_count:,}"),
        ("Directories", f"{scan.dir_count:,}"),
        ("Symlinks", f"{scan.symlink_count:,} ({scan.symlink_bytes:,} B, not followed)"),
        ("Special files", f"{scan.special_count:,}"),
        (
            "Hard links deduplicated",
            f"{scan.hardlink_count:,} ({scan.hardlink_saved_human} saved from double-counting)",
        ),
        ("Unreadable", f"{scan.unreadable_count} paths unreadable"),
    ]
    out.kv(rows, title="Storage Analysis Summary")

    if scan.unreadable_count > 0:
        out.warn(
            f"{scan.unreadable_count} paths unreadable due to permissions or OS errors.",
            hint="Re-run on accessible folders or check permissions.",
        )

    if scan.top_children:
        out.table(
            ["Directory", "Size", "Category", "Confidence"],
            [
                (
                    d.name,
                    d.size_human,
                    d.category,
                    d.confidence,
                )
                for d in scan.top_children[:20]
            ],
            title="Top-Level Subdirectories",
            right_align=("Size",),
        )

    if scan.depth > 0 and scan.tree_entries:
        out.heading(f"Directory Tree (depth <= {scan.depth})")
        out.render(_build_directory_tree(scan))

    if scan.categories:
        out.table(
            ["Category", "Size", "Share", "Items", "Confidence"],
            [
                (
                    f"{c.label} ({c.category})",
                    c.size_human,
                    f"{c.percent_of_total:.1f}%",
                    str(c.file_count),
                    c.confidence,
                )
                for c in scan.categories
            ],
            title="Storage by Category",
            right_align=("Size", "Share", "Items"),
        )

    if scan.large_projects:
        out.table(
            ["Project Directory", "Size", "Manifests", "Confidence"],
            [
                (
                    lp.path,
                    lp.size_human,
                    ", ".join(lp.manifests),
                    lp.confidence,
                )
                for lp in scan.large_projects
            ],
            title="Large Project Directories",
            right_align=("Size",),
        )

    if scan.largest_dirs:
        out.table(
            ["Directory Path", "Size", "Category", "Confidence"],
            [
                (
                    d.path,
                    d.size_human,
                    d.category,
                    d.confidence,
                )
                for d in scan.largest_dirs[:10]
            ],
            title="Largest Folders",
            right_align=("Size",),
        )

    if scan.largest_files:
        out.table(
            ["File Path", "Size", "Category", "Confidence"],
            [
                (
                    f.path,
                    f.size_human,
                    f.category,
                    f.confidence,
                )
                for f in scan.largest_files[:10]
            ],
            title="Largest Files",
            right_align=("Size",),
        )

    out.next_steps(
        [
            f"disklens largest {scan.root}",
            f"disklens duplicates {scan.root}",
            f"disklens cleanup {scan.root} --preview",
        ]
    )


def render_largest_files(
    out: Output,
    root: str,
    files: Sequence[FileEntry],
    *,
    limit: int,
    min_size_bytes: int,
    unreadable_count: int = 0,
) -> None:
    """Render ``disklens largest`` output."""
    out.banner()
    out.kv(
        [
            ("Root", root),
            ("Files shown", f"{len(files)} (limit {limit}, min-size {min_size_bytes:,} B)"),
        ],
        title="Largest Files",
    )
    if unreadable_count > 0:
        out.warn(f"{unreadable_count} paths unreadable")

    if not files:
        out.info("No matching files found.")
        return

    out.table(
        ["Rank", "Size", "Bytes", "Category", "Confidence", "Path"],
        [
            (
                str(idx),
                f.size_human,
                f"{f.size_bytes:,}",
                f.category,
                f.confidence,
                f.path,
            )
            for idx, f in enumerate(files, start=1)
        ],
        title="Largest Files by Size",
        right_align=("Rank", "Size", "Bytes"),
    )


def render_duplicates(out: Output, result: DuplicatesResult) -> None:
    """Render ``disklens duplicates`` output."""
    out.banner()
    out.kv(
        [
            ("Root", result.root),
            ("Files scanned", f"{result.total_files_scanned:,}"),
            ("Duplicate groups", f"{result.duplicate_group_count:,}"),
            ("Duplicate files", f"{result.duplicate_file_count:,}"),
            (
                "Reclaimable space",
                f"{result.reclaimable_human} "
                f"({result.reclaimable_bytes:,} B, excluding hard links)",
            ),
            ("Hard-link groups", f"{result.hardlink_group_count:,} (0 B wasted)"),
            (
                "Hashes computed",
                f"{result.partial_hashes_computed:,} partial, "
                f"{result.full_hashes_computed:,} full SHA-256",
            ),
        ],
        title="Duplicate File Analysis",
    )
    if result.unreadable_count > 0:
        out.warn(f"{result.unreadable_count} paths unreadable")

    if result.duplicate_groups:
        rows = []
        for idx, grp in enumerate(result.duplicate_groups, start=1):
            rows.append(
                (
                    str(idx),
                    grp.size_human,
                    grp.reclaimable_human,
                    str(grp.inode_count),
                    grp.sha256[:12],
                    "\n".join(grp.paths),
                )
            )
        out.table(
            ["Group", "File Size", "Reclaimable", "Inodes", "SHA-256", "Paths"],
            rows,
            title="True Content Duplicates",
            right_align=("Group", "File Size", "Reclaimable", "Inodes"),
        )
    else:
        out.info("No duplicate files found.")

    if result.hardlinks:
        hl_rows = [
            (
                str(idx),
                hl.size_human,
                str(hl.inode),
                "0 B (shared inode)",
                "\n".join(hl.paths),
            )
            for idx, hl in enumerate(result.hardlinks, start=1)
        ]
        out.table(
            ["Group", "File Size", "Inode", "Wasted", "Hard-Linked Paths"],
            hl_rows,
            title="Hard-Link Groups (Not Wasted Space)",
            right_align=("Group", "File Size", "Inode", "Wasted"),
        )


def render_cleanup_plan(out: Output, plan: CleanupPlan) -> None:
    """Render ``disklens cleanup`` preview or pre-deletion candidate list."""
    out.banner()
    out.kv(
        [
            ("Root", plan.root),
            ("Mode", plan.mode),
            ("Category filter", plan.category_filter or "all"),
            ("Candidates", f"{plan.candidate_count:,}"),
            (
                "Total reclaimable",
                f"{plan.total_reclaimable_human} ({plan.total_reclaimable_bytes:,} B)",
            ),
        ],
        title="Cleanup Candidate Plan",
    )
    if plan.unreadable_count > 0:
        out.warn(f"{plan.unreadable_count} paths unreadable")

    if not plan.candidates:
        out.info("No cleanup candidates found.")
        return

    out.table(
        ["Path", "Kind", "Size", "Category", "Status", "Confidence", "Explanation"],
        [
            (
                c.path,
                c.kind,
                c.size_human,
                c.category,
                c.status,
                c.confidence,
                c.explanation,
            )
            for c in plan.candidates
        ],
        title="Cleanup Candidates",
        right_align=("Size",),
    )

    if plan.mode == "preview":
        out.info("Preview mode: no files or directories were deleted.")
        out.next_steps(
            [
                f"disklens cleanup {plan.root} --delete --dry-run",
                f"disklens cleanup {plan.root} --delete",
            ]
        )


def render_cleanup_execution(out: Output, exec_result: CleanupExecutionResult) -> None:
    """Render outcome of ``disklens cleanup --delete`` (or ``--delete --dry-run``)."""
    if exec_result.plan is not None:
        render_cleanup_plan(out, exec_result.plan)

    title = "Cleanup Dry-Run Summary" if exec_result.dry_run else "Cleanup Deletion Summary"
    action_label = "Would delete" if exec_result.dry_run else "Deleted"
    out.kv(
        [
            (action_label, f"{exec_result.deleted_count:,}"),
            ("Skipped", f"{exec_result.skipped_count:,}"),
            ("Failed", f"{exec_result.failed_count:,}"),
            (
                "Space freed" if not exec_result.dry_run else "Space reclaimable",
                f"{exec_result.bytes_freed_human} ({exec_result.bytes_freed:,} B)",
            ),
        ],
        title=title,
    )

    if exec_result.outcomes:
        out.table(
            ["Status", "Kind", "Size", "Path", "Message"],
            [
                (
                    o.status,
                    o.kind,
                    o.size_human,
                    o.path,
                    o.message,
                )
                for o in exec_result.outcomes
            ],
            title="Per-Item Cleanup Outcomes",
            right_align=("Size",),
        )


def render_report(out: Output, report: DiskReport) -> None:
    """Render ``disklens report`` output."""
    render_scan_result(out, report.scan)
    vol_used = (
        f"{report.volume.used_human} / {report.volume.total_human} "
        f"({report.volume.percent_used:.1f}%)"
    )
    cleanup_reclaim = f"{report.cleanup_reclaimable_human} ({report.cleanup_reclaimable_bytes:,} B)"
    out.kv(
        [
            ("Volume mount", report.volume.mount_point),
            ("Volume used", vol_used),
            ("Volume available", report.volume.available_human),
            ("Cleanup candidates", f"{report.cleanup_candidate_count:,}"),
            ("Cleanup reclaimable", cleanup_reclaim),
        ],
        title="Volume & Cleanup Summary",
    )
