"""Two-stage content-based duplicate file finder with hard-link separation."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from disklens.common.exceptions import UsageError
from disklens.common.fsutil import human_size, sha256_file
from disklens.common.output import NullProgress
from disklens.scanner import MAX_RECORDED_ERRORS, validate_scan_root


@dataclass(frozen=True)
class DuplicateGroup:
    """A group of distinct files with identical content."""

    sha256: str
    size_bytes: int
    size_human: str
    reclaimable_bytes: int
    reclaimable_human: str
    inode_count: int
    paths: list[str]


@dataclass(frozen=True)
class HardlinkGroup:
    """Multiple directory entries pointing to the same physical inode (0 wasted bytes)."""

    dev: int
    inode: int
    size_bytes: int
    size_human: str
    paths: list[str]
    reclaimable_bytes: int = 0


@dataclass
class DuplicatesResult:
    """Result of ``disklens duplicates``."""

    root: str
    min_size_bytes: int
    include_empty: bool
    total_files_scanned: int
    duplicate_groups: list[DuplicateGroup] = field(default_factory=list)
    hardlinks: list[HardlinkGroup] = field(default_factory=list)
    duplicate_group_count: int = 0
    duplicate_file_count: int = 0
    hardlink_group_count: int = 0
    reclaimable_bytes: int = 0
    reclaimable_human: str = "0 B"
    partial_hashes_computed: int = 0
    full_hashes_computed: int = 0
    unreadable_count: int = 0
    errors: list[str] = field(default_factory=list)


def find_duplicates(
    path: str | os.PathLike[str] = ".",
    *,
    min_size_bytes: int = 1,
    include_empty: bool = False,
    include_hidden: bool = True,
    cross_device: bool = False,
    partial_kib: int = 64,
    progress: NullProgress | None = None,
) -> DuplicatesResult:
    """Find true duplicate files and separate hard-link groups under ``path``.

    Algorithm:
    1. Iterative ``os.scandir`` walk grouping files by ``size`` and ``(st_dev, st_ino)``.
    2. Separate hard-link groups (same ``(st_dev, st_ino)`` with >= 2 paths -> 0 wasted bytes).
    3. Skip any size with fewer than 2 distinct inodes.
    4. Stage 1: Hash first ``partial_kib`` KiB per distinct inode (cached by ``(dev, ino)``).
    5. Stage 2: Full streaming SHA-256 only for partial-hash collisions (cached by ``(dev, ino)``).
    """
    if min_size_bytes < 0:
        raise UsageError("--min-size must be >= 0.")
    if partial_kib < 1:
        raise UsageError("partial_kib must be >= 1.")

    root_path = validate_scan_root(path)
    root_str = str(root_path)
    root_dev = root_path.lstat().st_dev
    partial_bytes = partial_kib * 1024

    effective_min = 0 if (include_empty and min_size_bytes <= 1) else min_size_bytes

    # size_bytes -> {(dev, ino): [path_str, ...]}
    by_size: dict[int, dict[tuple[int, int], list[str]]] = {}
    total_files_scanned = 0
    unreadable_count = 0
    errors: list[str] = []

    stack: list[str] = [root_str]
    while stack:
        cur_dir = stack.pop()
        if progress is not None:
            progress.advance(1)
        try:
            with os.scandir(cur_dir) as it:
                entries = list(it)
        except OSError as exc:
            unreadable_count += 1
            if len(errors) < MAX_RECORDED_ERRORS:
                errors.append(f"{cur_dir}: {exc.strerror or exc}")
            continue

        sub_dirs: list[str] = []
        for entry in entries:
            if not include_hidden and entry.name.startswith("."):
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                unreadable_count += 1
                if len(errors) < MAX_RECORDED_ERRORS:
                    errors.append(f"{entry.path}: {exc.strerror or exc}")
                continue

            if not cross_device and st.st_dev != root_dev:
                continue

            mode = st.st_mode
            if stat.S_ISLNK(mode):
                continue
            if stat.S_ISDIR(mode):
                sub_dirs.append(entry.path)
            elif stat.S_ISREG(mode):
                total_files_scanned += 1
                fsize = max(int(st.st_size), 0)
                if fsize == 0 and not include_empty:
                    continue
                if fsize < effective_min:
                    continue
                ino_key = (st.st_dev, st.st_ino)
                size_map = by_size.setdefault(fsize, {})
                size_map.setdefault(ino_key, []).append(entry.path)

        for sub in sorted(sub_dirs, reverse=True):
            stack.append(sub)

    # Extract hardlink groups and candidate size buckets
    hardlinks: list[HardlinkGroup] = []
    for fsize, inode_map in by_size.items():
        for (dev, ino), paths in inode_map.items():
            if ino != 0 and len(paths) >= 2:
                sorted_paths = sorted(paths)
                hardlinks.append(
                    HardlinkGroup(
                        dev=dev,
                        inode=ino,
                        size_bytes=fsize,
                        size_human=human_size(fsize),
                        paths=sorted_paths,
                        reclaimable_bytes=0,
                    )
                )
    hardlinks.sort(key=lambda h: (-h.size_bytes, h.paths[0]))

    partial_cache: dict[tuple[int, int], str] = {}
    full_cache: dict[tuple[int, int], str] = {}
    partial_hashes_computed = 0
    full_hashes_computed = 0
    duplicate_groups: list[DuplicateGroup] = []

    for fsize in sorted(by_size.keys(), reverse=True):
        inode_map = by_size[fsize]
        if len(inode_map) < 2:
            continue

        # Stage 1: Partial hash of first N KiB
        by_partial: dict[str, list[tuple[int, int]]] = {}
        for ino_key, paths in inode_map.items():
            if ino_key in partial_cache:
                phash = partial_cache[ino_key]
            else:
                rep = Path(paths[0])
                try:
                    phash = sha256_file(rep, limit=partial_bytes)
                except OSError as exc:
                    unreadable_count += 1
                    if len(errors) < MAX_RECORDED_ERRORS:
                        errors.append(f"{rep}: {exc.strerror or exc}")
                    continue
                partial_cache[ino_key] = phash
                partial_hashes_computed += 1
                if fsize <= partial_bytes:
                    full_cache[ino_key] = phash
            by_partial.setdefault(phash, []).append(ino_key)

        # Stage 2: Full streaming SHA-256 only for partial-hash collisions
        for _phash, candidate_inos in by_partial.items():
            if len(candidate_inos) < 2:
                continue
            by_full: dict[str, list[tuple[int, int]]] = {}
            for ino_key in candidate_inos:
                if ino_key in full_cache:
                    fhash = full_cache[ino_key]
                else:
                    rep = Path(inode_map[ino_key][0])
                    try:
                        fhash = sha256_file(rep)
                    except OSError as exc:
                        unreadable_count += 1
                        if len(errors) < MAX_RECORDED_ERRORS:
                            errors.append(f"{rep}: {exc.strerror or exc}")
                        continue
                    full_cache[ino_key] = fhash
                    full_hashes_computed += 1
                by_full.setdefault(fhash, []).append(ino_key)

            for fhash, matched_inos in by_full.items():
                if len(matched_inos) < 2:
                    continue
                # Reclaimable bytes strictly exclude hard links: only (distinct_inodes - 1) * fsize
                reclaimable = (len(matched_inos) - 1) * fsize
                all_paths = sorted(p for ino_k in matched_inos for p in inode_map[ino_k])
                duplicate_groups.append(
                    DuplicateGroup(
                        sha256=fhash,
                        size_bytes=fsize,
                        size_human=human_size(fsize),
                        reclaimable_bytes=reclaimable,
                        reclaimable_human=human_size(reclaimable),
                        inode_count=len(matched_inos),
                        paths=all_paths,
                    )
                )

    duplicate_groups.sort(key=lambda g: (-g.reclaimable_bytes, -g.size_bytes, g.paths[0]))
    total_reclaimable = sum(g.reclaimable_bytes for g in duplicate_groups)
    total_dup_files = sum(len(g.paths) for g in duplicate_groups)

    return DuplicatesResult(
        root=root_str,
        min_size_bytes=effective_min,
        include_empty=include_empty,
        total_files_scanned=total_files_scanned,
        duplicate_groups=duplicate_groups,
        hardlinks=hardlinks,
        duplicate_group_count=len(duplicate_groups),
        duplicate_file_count=total_dup_files,
        hardlink_group_count=len(hardlinks),
        reclaimable_bytes=total_reclaimable,
        reclaimable_human=human_size(total_reclaimable),
        partial_hashes_computed=partial_hashes_computed,
        full_hashes_computed=full_hashes_computed,
        unreadable_count=unreadable_count,
        errors=errors,
    )
