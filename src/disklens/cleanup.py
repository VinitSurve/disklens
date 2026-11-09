"""Safe cleanup candidate discovery and validated deletion engine."""

from __future__ import annotations

import os
import shutil
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path

from disklens.categories import (
    BUILD_ARTIFACT_DIRS,
    DEPENDENCY_DIRS,
    EXACT_TEMP_FILENAMES,
    HEURISTIC_CACHE_DIRS,
    LOG_EXTENSIONS,
    PYTHON_MANIFESTS,
    TEMP_EXTENSIONS,
    Confidence,
    get_known_cache_roots,
    is_verified_cache_path,
    matching_manifests_for_build_dir,
    matching_manifests_for_dep_dir,
)
from disklens.common.exceptions import SafetyError, UsageError
from disklens.common.fsutil import human_size
from disklens.common.logging import get_logger
from disklens.common.output import NullProgress
from disklens.common.paths import ensure_not_protected, is_within, protected_reason
from disklens.scanner import MAX_RECORDED_ERRORS, validate_scan_root

CLEANUP_CATEGORY_ALIASES: dict[str, str] = {
    "build": "build_artifacts",
    "build_artifacts": "build_artifacts",
    "artifacts": "build_artifacts",
    "deps": "dependencies",
    "dep": "dependencies",
    "dependency": "dependencies",
    "dependencies": "dependencies",
    "cache": "caches",
    "caches": "caches",
    "temp": "temp",
    "tmp": "temp",
    "temporary": "temp",
    "log": "logs",
    "logs": "logs",
}

VALID_CLEANUP_CATEGORIES: tuple[str, ...] = (
    "build_artifacts",
    "dependencies",
    "caches",
    "temp",
    "logs",
)


@dataclass(frozen=True)
class CleanupCandidate:
    """A single file, directory, or symlink proposed for cleanup."""

    path: str
    name: str
    kind: str  # "dir" | "file" | "symlink"
    category: str
    confidence: Confidence
    status: str  # e.g. "verified", "regenerable", "cache", "temporary", "old_log"
    size_bytes: int
    size_human: str
    explanation: str


@dataclass
class CleanupPlan:
    """Result of cleanup candidate discovery (preview or pre-deletion plan)."""

    root: str
    category_filter: str | None
    older_than_days: int
    mode: str  # "preview" | "dry_run" | "delete"
    candidates: list[CleanupCandidate] = field(default_factory=list)
    candidate_count: int = 0
    total_reclaimable_bytes: int = 0
    total_reclaimable_human: str = "0 B"
    verified_bytes: int = 0
    heuristic_bytes: int = 0
    unreadable_count: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CleanupItemOutcome:
    """Outcome of deleting or dry-running a single cleanup candidate."""

    path: str
    kind: str
    status: str  # "deleted" | "dry_run" | "skipped" | "failed"
    bytes_freed: int
    size_human: str
    message: str


@dataclass
class CleanupExecutionResult:
    """Complete result of ``disklens cleanup --delete``."""

    root: str
    dry_run: bool
    deleted_count: int
    skipped_count: int
    failed_count: int
    bytes_freed: int
    bytes_freed_human: str
    outcomes: list[CleanupItemOutcome] = field(default_factory=list)
    plan: CleanupPlan | None = None


def normalize_cleanup_category(category: str | None) -> str | None:
    """Validate and normalize a ``--category`` filter string."""
    if category is None:
        return None
    key = category.strip().lower()
    if key not in CLEANUP_CATEGORY_ALIASES:
        allowed = ", ".join(VALID_CLEANUP_CATEGORIES)
        raise UsageError(
            f"Unknown cleanup category: {category!r}",
            hint=f"Allowed categories: {allowed}",
        )
    return CLEANUP_CATEGORY_ALIASES[key]


def _is_forbidden_cleanup_target(path: Path) -> str | None:
    """Return a refusal reason if ``path`` must never be proposed or deleted."""
    parts_lower = {p.lower() for p in path.parts}
    if "application support" in parts_lower:
        return "it is inside Application Support"
    if "keychains" in parts_lower:
        return "it is inside a Keychains directory"
    if not path.is_symlink():
        reason = protected_reason(path)
        if reason is not None:
            return reason
    return None


def _compute_subtree_size(
    dir_path_str: str,
    *,
    root_dev: int,
    cross_device: bool,
    seen_inodes: set[tuple[int, int]],
) -> tuple[int, int, list[str]]:
    """Iteratively compute the byte size of ``dir_path_str`` without following symlinks."""
    total = 0
    unreadable = 0
    errs: list[str] = []
    stack = [dir_path_str]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                entries = list(it)
        except OSError as exc:
            unreadable += 1
            if len(errs) < MAX_RECORDED_ERRORS:
                errs.append(f"{cur}: {exc.strerror or exc}")
            continue
        for entry in entries:
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                unreadable += 1
                if len(errs) < MAX_RECORDED_ERRORS:
                    errs.append(f"{entry.path}: {exc.strerror or exc}")
                continue
            if not cross_device and st.st_dev != root_dev:
                continue
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                total += max(int(st.st_size), 0)
            elif stat.S_ISDIR(mode):
                stack.append(entry.path)
            elif stat.S_ISREG(mode):
                ino_key = (st.st_dev, st.st_ino)
                if st.st_ino != 0 and ino_key in seen_inodes:
                    continue
                if st.st_ino != 0:
                    seen_inodes.add(ino_key)
                total += max(int(st.st_size), 0)
    return total, unreadable, errs


def _classify_dir_candidate(
    dir_name: str,
    dir_path_str: str,
    parent_dir_str: str,
    sibling_names: set[str],
    *,
    is_symlink: bool,
    has_ancestor_py_manifest: bool,
    cache_roots: tuple[str, ...],
    extra_cleanup_names: tuple[str, ...],
) -> tuple[str, Confidence, str, str] | None:
    """Determine if a directory (or symlink to directory/candidate name) is a cleanup candidate.

    Returns ``(category, confidence, status, explanation)`` or ``None``.
    """
    parent_name = Path(parent_dir_str).name

    # 1. Exact known user cache directories
    if parent_dir_str in cache_roots or is_verified_cache_path(dir_path_str, cache_roots):
        if dir_name == "devtoolkit":
            return None
        if dir_name == "Homebrew" and parent_name == "Caches":
            return (
                "caches",
                "verified",
                "verified",
                "Recognized Homebrew cache directory (~/Library/Caches/Homebrew)",
            )
        if dir_name == "pip" and parent_name == ".cache":
            return (
                "caches",
                "verified",
                "verified",
                "Recognized pip cache directory (~/.cache/pip)",
            )
        if dir_name == "_cacache" and parent_name == ".npm":
            return (
                "caches",
                "verified",
                "verified",
                "Recognized npm cache directory (~/.npm/_cacache)",
            )
        if dir_name == "DerivedData" and parent_name == "Xcode":
            return (
                "caches",
                "verified",
                "verified",
                "Recognized Xcode DerivedData cache directory",
            )
        if parent_dir_str in cache_roots:
            return (
                "caches",
                "verified",
                "verified",
                f"Recognized user cache directory ({dir_name})",
            )

    if dir_name == "_cacache" and parent_name == ".npm":
        return (
            "caches",
            "verified",
            "verified",
            "Recognized npm cache directory (.npm/_cacache)",
        )
    if dir_name == "pip" and parent_name == ".cache":
        return (
            "caches",
            "verified",
            "verified",
            "Recognized pip cache directory (.cache/pip)",
        )
    if dir_name == "Homebrew" and parent_name == "Caches":
        return (
            "caches",
            "verified",
            "verified",
            "Recognized Homebrew cache directory (Library/Caches/Homebrew)",
        )
    if dir_name == "DerivedData" and parent_name == "Xcode":
        return (
            "caches",
            "verified",
            "verified",
            "Recognized Xcode DerivedData directory",
        )

    # 2. Build outputs — ONLY when a matching project manifest sits next to it
    if dir_name in BUILD_ARTIFACT_DIRS:
        manifests = matching_manifests_for_build_dir(
            dir_name,
            sibling_names,
            has_ancestor_python_manifest=has_ancestor_py_manifest,
        )
        if manifests:
            return (
                "build_artifacts",
                "verified",
                "verified",
                f"Build output '{dir_name}' verified by adjacent {manifests[0]}",
            )
        return None

    # 3. Dependency directories — flagged "regenerable"
    if dir_name in DEPENDENCY_DIRS:
        manifests = matching_manifests_for_dep_dir(
            dir_name,
            sibling_names,
            dir_path=None if is_symlink else Path(dir_path_str),
        )
        if manifests:
            return (
                "dependencies",
                "verified",
                "regenerable",
                f"Regenerable dependency directory '{dir_name}' (verified by {manifests[0]})",
            )
        if dir_name in ("node_modules", ".venv", "Pods"):
            return (
                "dependencies",
                "heuristic",
                "regenerable",
                f"Regenerable dependency directory '{dir_name}' (heuristic: no adjacent manifest)",
            )
        return None

    # 4. Heuristic cache directories
    if dir_name in HEURISTIC_CACHE_DIRS and dir_name not in (".cache", "cache", "caches"):
        return (
            "caches",
            "heuristic",
            "cache",
            f"Cache directory '{dir_name}' (heuristic match by name)",
        )

    # 5. Extra configured cleanup names
    if extra_cleanup_names and dir_name in extra_cleanup_names:
        return (
            "temp",
            "heuristic",
            "temporary",
            f"Configured cleanup directory '{dir_name}' (heuristic)",
        )

    return None


def _classify_file_candidate(
    file_name: str,
    mtime: float,
    *,
    now: float,
    older_than_days: int,
    extra_cleanup_names: tuple[str, ...],
) -> tuple[str, Confidence, str, str] | None:
    """Determine if a file or symlink is a cleanup candidate."""
    if file_name in EXACT_TEMP_FILENAMES:
        return (
            "temp",
            "verified",
            "verified",
            f"OS metadata file ({file_name})",
        )

    if extra_cleanup_names and file_name in extra_cleanup_names:
        return (
            "temp",
            "heuristic",
            "temporary",
            f"Configured cleanup file ({file_name})",
        )

    dot_idx = file_name.rfind(".")
    ext = file_name[dot_idx:].lower() if dot_idx > 0 else ""

    if ext in TEMP_EXTENSIONS or file_name.endswith("~"):
        return (
            "temp",
            "heuristic",
            "temporary",
            f"Temporary file matching '{ext or '~'}' pattern (heuristic)",
        )

    if ext in LOG_EXTENSIONS or ".log." in file_name.lower():
        age_seconds = max(0.0, now - mtime)
        age_days = age_seconds / 86400.0
        if age_days >= float(older_than_days):
            return (
                "logs",
                "heuristic",
                "old_log",
                f"Log file older than {older_than_days} day(s) ({int(age_days)}d old, heuristic)",
            )

    return None


def discover_cleanup_candidates(
    path: str | os.PathLike[str] = ".",
    *,
    category: str | None = None,
    older_than_days: int = 30,
    include_hidden: bool = True,
    cross_device: bool = False,
    extra_cleanup_names: tuple[str, ...] = (),
    mode: str = "preview",
    progress: NullProgress | None = None,
) -> CleanupPlan:
    """Scan ``path`` for safe cleanup candidates without modifying the filesystem."""
    if older_than_days < 0:
        raise UsageError("--older-than must be >= 0.")

    norm_cat = normalize_cleanup_category(category)
    root_path = validate_scan_root(path)
    ensure_not_protected(root_path, "clean up")
    forbidden_root = _is_forbidden_cleanup_target(root_path)
    if forbidden_root:
        raise SafetyError(
            f"Refusing to clean up {root_path}: {forbidden_root}.",
            hint="Choose a project, Downloads, or cache directory instead.",
        )

    root_str = str(root_path)
    root_dev = root_path.lstat().st_dev
    home_path = Path(os.path.abspath(Path.home()))
    cache_roots = get_known_cache_roots(home_path)
    now = time.time()

    seen_inodes: set[tuple[int, int]] = set()
    candidates: list[CleanupCandidate] = []
    unreadable_count = 0
    errors: list[str] = []

    # Stack of (dir_str, has_ancestor_py_manifest)
    stack: list[tuple[str, bool]] = [(root_str, False)]

    while stack:
        cur_dir, ancestor_py = stack.pop()
        if progress is not None:
            progress.advance(1)

        cur_path = Path(cur_dir)
        if _is_forbidden_cleanup_target(cur_path) is not None:
            continue

        try:
            with os.scandir(cur_dir) as it:
                raw_entries = list(it)
        except OSError as exc:
            unreadable_count += 1
            if len(errors) < MAX_RECORDED_ERRORS:
                errors.append(f"{cur_dir}: {exc.strerror or exc}")
            continue

        dot_candidates = {
            ".DS_Store",
            ".venv",
            ".next",
            ".nuxt",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            ".gradle",
            ".cache",
            ".npm",
            ".tox",
            ".nox",
            ".turbo",
            ".parcel-cache",
        }
        visible = (
            raw_entries
            if include_hidden
            else [e for e in raw_entries if not e.name.startswith(".") or e.name in dot_candidates]
        )
        sibling_names = {e.name for e in raw_entries}
        has_py = ancestor_py or bool(sibling_names & PYTHON_MANIFESTS)
        sub_dirs: list[tuple[str, bool]] = []

        for entry in visible:
            entry_path_str = entry.path
            entry_path = Path(entry_path_str)
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                unreadable_count += 1
                if len(errors) < MAX_RECORDED_ERRORS:
                    errors.append(f"{entry_path_str}: {exc.strerror or exc}")
                continue

            if not cross_device and st.st_dev != root_dev:
                continue

            mode_bits = st.st_mode
            is_link = stat.S_ISLNK(mode_bits)

            if is_link:
                # Check if the symlink name matches a directory or file cleanup candidate.
                # Never follow the symlink!
                dir_match = _classify_dir_candidate(
                    entry.name,
                    entry_path_str,
                    cur_dir,
                    sibling_names,
                    is_symlink=True,
                    has_ancestor_py_manifest=has_py,
                    cache_roots=cache_roots,
                    extra_cleanup_names=extra_cleanup_names,
                )
                file_match = (
                    None
                    if dir_match is not None
                    else _classify_file_candidate(
                        entry.name,
                        float(st.st_mtime),
                        now=now,
                        older_than_days=older_than_days,
                        extra_cleanup_names=extra_cleanup_names,
                    )
                )
                chosen = dir_match or file_match
                if chosen is not None:
                    cat, conf, status, expl = chosen
                    if norm_cat is None or cat == norm_cat:
                        lsize = max(int(st.st_size), 0)
                        candidates.append(
                            CleanupCandidate(
                                path=entry_path_str,
                                name=entry.name,
                                kind="symlink",
                                category=cat,
                                confidence=conf,
                                status=status,
                                size_bytes=lsize,
                                size_human=human_size(lsize),
                                explanation=f"{expl} (symlink; target will not be followed)",
                            )
                        )
                continue

            if stat.S_ISDIR(mode_bits):
                if _is_forbidden_cleanup_target(entry_path) is not None:
                    continue
                dir_match = _classify_dir_candidate(
                    entry.name,
                    entry_path_str,
                    cur_dir,
                    sibling_names,
                    is_symlink=False,
                    has_ancestor_py_manifest=has_py,
                    cache_roots=cache_roots,
                    extra_cleanup_names=extra_cleanup_names,
                )
                if dir_match is not None:
                    cat, conf, status, expl = dir_match
                    if norm_cat is None or cat == norm_cat:
                        d_size, d_unread, d_errs = _compute_subtree_size(
                            entry_path_str,
                            root_dev=root_dev,
                            cross_device=cross_device,
                            seen_inodes=seen_inodes,
                        )
                        unreadable_count += d_unread
                        for err_msg in d_errs:
                            if len(errors) < MAX_RECORDED_ERRORS:
                                errors.append(err_msg)
                        candidates.append(
                            CleanupCandidate(
                                path=entry_path_str,
                                name=entry.name,
                                kind="dir",
                                category=cat,
                                confidence=conf,
                                status=status,
                                size_bytes=d_size,
                                size_human=human_size(d_size),
                                explanation=expl,
                            )
                        )
                    # Do not descend inside a directory that is already a cleanup candidate
                    continue

                sub_dirs.append((entry_path_str, has_py))

            elif stat.S_ISREG(mode_bits):
                file_match = _classify_file_candidate(
                    entry.name,
                    float(st.st_mtime),
                    now=now,
                    older_than_days=older_than_days,
                    extra_cleanup_names=extra_cleanup_names,
                )
                if file_match is not None:
                    cat, conf, status, expl = file_match
                    if norm_cat is None or cat == norm_cat:
                        fsize = max(int(st.st_size), 0)
                        candidates.append(
                            CleanupCandidate(
                                path=entry_path_str,
                                name=entry.name,
                                kind="file",
                                category=cat,
                                confidence=conf,
                                status=status,
                                size_bytes=fsize,
                                size_human=human_size(fsize),
                                explanation=expl,
                            )
                        )

        for sub_d, sub_py in sorted(sub_dirs, reverse=True):
            stack.append((sub_d, sub_py))

    candidates.sort(key=lambda c: (-c.size_bytes, c.path))
    total_reclaimable = sum(c.size_bytes for c in candidates)
    verified_b = sum(c.size_bytes for c in candidates if c.confidence == "verified")
    heuristic_b = sum(c.size_bytes for c in candidates if c.confidence == "heuristic")

    return CleanupPlan(
        root=root_str,
        category_filter=norm_cat,
        older_than_days=older_than_days,
        mode=mode,
        candidates=candidates,
        candidate_count=len(candidates),
        total_reclaimable_bytes=total_reclaimable,
        total_reclaimable_human=human_size(total_reclaimable),
        verified_bytes=verified_b,
        heuristic_bytes=heuristic_b,
        unreadable_count=unreadable_count,
        errors=errors,
    )


def _has_symlink_ancestor(candidate: Path, root: Path) -> bool:
    """True if any ancestor between ``root`` and ``candidate.parent`` is a symlink."""
    cur = candidate.parent
    root_abs = Path(os.path.abspath(root))
    while cur != root_abs and len(cur.parts) > len(root_abs.parts):
        if cur.is_symlink():
            return True
        cur = cur.parent
    return root_abs.is_symlink()


def execute_cleanup(
    plan: CleanupPlan,
    *,
    dry_run: bool = False,
) -> CleanupExecutionResult:
    """Execute or dry-run a :class:`CleanupPlan`, re-validating every path before deletion."""
    logger = get_logger("disklens")
    root_path = Path(plan.root)
    ensure_not_protected(root_path, "clean up")

    outcomes: list[CleanupItemOutcome] = []
    deleted_count = 0
    skipped_count = 0
    failed_count = 0
    bytes_freed = 0

    for cand in plan.candidates:
        cand_path = Path(cand.path)

        # 1. Re-validate existence without following symlinks
        if not os.path.lexists(cand_path):
            skipped_count += 1
            outcomes.append(
                CleanupItemOutcome(
                    path=cand.path,
                    kind=cand.kind,
                    status="skipped",
                    bytes_freed=0,
                    size_human="0 B",
                    message="Path no longer exists",
                )
            )
            logger.info("cleanup skipped (missing): %s", cand.path)
            continue

        # 2. Verify no ancestor between root and cand_path.parent was swapped with a symlink
        parent_escaped = not is_within(cand_path.parent, root_path)
        if _has_symlink_ancestor(cand_path, root_path) or parent_escaped:
            failed_count += 1
            outcomes.append(
                CleanupItemOutcome(
                    path=cand.path,
                    kind=cand.kind,
                    status="failed",
                    bytes_freed=0,
                    size_human="0 B",
                    message="Refused: parent path escapes scan root or contains symlink ancestor",
                )
            )
            logger.warning("cleanup refused (ancestor symlink/escape): %s", cand.path)
            continue

        try:
            st = cand_path.lstat()
        except OSError as exc:
            failed_count += 1
            outcomes.append(
                CleanupItemOutcome(
                    path=cand.path,
                    kind=cand.kind,
                    status="failed",
                    bytes_freed=0,
                    size_human="0 B",
                    message=f"Cannot lstat path: {exc.strerror or exc}",
                )
            )
            logger.error("cleanup lstat failed for %s: %s", cand.path, exc)
            continue

        mode_bits = st.st_mode
        is_link = stat.S_ISLNK(mode_bits)

        # 3. For non-symlinks, verify not protected and strictly within root_path
        if not is_link:
            forbidden = _is_off_limits_or_escaped(cand_path, root_path)
            if forbidden is not None:
                failed_count += 1
                outcomes.append(
                    CleanupItemOutcome(
                        path=cand.path,
                        kind=cand.kind,
                        status="failed",
                        bytes_freed=0,
                        size_human="0 B",
                        message=f"Refused: {forbidden}",
                    )
                )
                logger.warning("cleanup refused (%s): %s", forbidden, cand.path)
                continue

        if dry_run:
            outcomes.append(
                CleanupItemOutcome(
                    path=cand.path,
                    kind="symlink" if is_link else cand.kind,
                    status="dry_run",
                    bytes_freed=cand.size_bytes,
                    size_human=cand.size_human,
                    message="Would delete (dry-run)",
                )
            )
            bytes_freed += cand.size_bytes
            deleted_count += 1
            logger.info("cleanup dry-run: would delete %s (%d bytes)", cand.path, cand.size_bytes)
            continue

        # 4. Perform deletion:
        # - If symlink: unlink the symlink itself (never touch target, even if outside root)
        # - If real directory: shutil.rmtree
        # - If regular/special file: os.unlink
        try:
            if is_link or not stat.S_ISDIR(mode_bits):
                os.unlink(cand_path)
            else:
                shutil.rmtree(cand_path)
        except OSError as exc:
            failed_count += 1
            outcomes.append(
                CleanupItemOutcome(
                    path=cand.path,
                    kind="symlink" if is_link else cand.kind,
                    status="failed",
                    bytes_freed=0,
                    size_human="0 B",
                    message=f"Delete failed: {exc.strerror or exc}",
                )
            )
            logger.error("cleanup delete failed for %s: %s", cand.path, exc)
            continue

        deleted_count += 1
        bytes_freed += cand.size_bytes
        outcomes.append(
            CleanupItemOutcome(
                path=cand.path,
                kind="symlink" if is_link else cand.kind,
                status="deleted",
                bytes_freed=cand.size_bytes,
                size_human=cand.size_human,
                message="Deleted",
            )
        )
        logger.info(
            "cleanup deleted %s (%s, %d bytes)",
            cand.path,
            "symlink" if is_link else cand.kind,
            cand.size_bytes,
        )

    return CleanupExecutionResult(
        root=plan.root,
        dry_run=dry_run,
        deleted_count=deleted_count,
        skipped_count=skipped_count,
        failed_count=failed_count,
        bytes_freed=bytes_freed,
        bytes_freed_human=human_size(bytes_freed),
        outcomes=outcomes,
        plan=plan,
    )


def _is_off_limits_or_escaped(cand_path: Path, root_path: Path) -> str | None:
    """Check protection and root containment for a non-symlink candidate before deletion."""
    if not is_within(cand_path, root_path):
        return "path resolves outside the scanned root"
    return _is_forbidden_cleanup_target(cand_path)
