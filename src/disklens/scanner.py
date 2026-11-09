"""Iterative filesystem scanner and volume storage inspector."""

from __future__ import annotations

import heapq
import os
import re
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path

from disklens.categories import (
    CATEGORY_LABELS,
    PYTHON_MANIFESTS,
    Classification,
    Confidence,
    classify_directory,
    classify_file,
    detect_manifests,
    get_known_cache_roots,
)
from disklens.common.exceptions import NotFoundError, UsageError
from disklens.common.fsutil import human_size
from disklens.common.output import NullProgress
from disklens.common.paths import resolve_user_path
from disklens.common.safety import run_command

MAX_RECORDED_ERRORS = 100


@dataclass(frozen=True)
class VolumeInfo:
    """Disk usage metrics for a single volume or mount point."""

    filesystem: str
    mount_point: str
    total_bytes: int
    used_bytes: int
    available_bytes: int
    percent_used: float
    total_human: str
    used_human: str
    available_human: str


@dataclass(frozen=True)
class APFSVolumeEntry:
    disk_id: str
    name: str
    role: str
    mount_point: str
    used_bytes: int
    used_human: str
    percent_of_container: float


@dataclass(frozen=True)
class APFSContainerInfo:
    container_id: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    percent_used: float
    total_human: str
    used_human: str
    free_human: str
    volumes: list[APFSVolumeEntry]


@dataclass(frozen=True)
class StorageOverview:
    """Result of ``disklens`` / ``disklens info``."""

    target_path: str
    primary: VolumeInfo
    volumes: list[VolumeInfo]
    apfs: APFSContainerInfo | None = None
    target_volume_name: str | None = None
    target_mount_point: str | None = None


@dataclass(frozen=True)
class FileEntry:
    """Metadata for a single scanned file."""

    path: str
    size_bytes: int
    size_human: str
    category: str
    confidence: Confidence
    mtime: float


@dataclass(frozen=True)
class DirEntry:
    """Metadata and recursive size for a scanned directory."""

    path: str
    name: str
    depth: int
    size_bytes: int
    size_human: str
    category: str
    confidence: Confidence


@dataclass(frozen=True)
class CategoryStat:
    """Aggregated storage metrics for a single category."""

    category: str
    label: str
    size_bytes: int
    size_human: str
    file_count: int
    percent_of_total: float
    confidence: Confidence
    verified_bytes: int
    heuristic_bytes: int


@dataclass(frozen=True)
class LargeProjectEntry:
    """A project directory containing a manifest and exceeding the size threshold."""

    path: str
    size_bytes: int
    size_human: str
    manifests: list[str]
    confidence: Confidence = "verified"


@dataclass(frozen=True)
class ExportRecord:
    """Flat row representation for CSV and JSON exports."""

    path: str
    size_bytes: int
    type: str
    category: str
    confidence: Confidence


@dataclass
class ScanResult:
    """Complete result of an iterative directory scan."""

    root: str
    depth: int
    include_hidden: bool
    cross_device: bool
    total_bytes: int
    total_human: str
    file_count: int
    dir_count: int
    symlink_count: int
    symlink_bytes: int
    special_count: int
    hardlink_count: int
    hardlink_bytes_saved: int
    hardlink_saved_human: str
    unreadable_count: int
    errors: list[str] = field(default_factory=list)
    top_children: list[DirEntry] = field(default_factory=list)
    tree_entries: list[DirEntry] = field(default_factory=list)
    largest_files: list[FileEntry] = field(default_factory=list)
    largest_dirs: list[DirEntry] = field(default_factory=list)
    categories: list[CategoryStat] = field(default_factory=list)
    large_projects: list[LargeProjectEntry] = field(default_factory=list)
    export_records: list[ExportRecord] = field(default_factory=list)


def get_storage_overview(path: str | os.PathLike[str] = ".") -> StorageOverview:
    """Return disk usage for ``path`` plus mounted local volumes."""
    resolved = resolve_user_path(path)
    if not os.path.lexists(resolved):
        raise NotFoundError(
            f"Path does not exist: {resolved}",
            hint="Check the path and try again.",
        )
    usage = shutil.disk_usage(resolved)
    total = int(usage.total)
    used = int(usage.used)
    free = int(usage.free)
    pct = round((used / total * 100.0), 1) if total > 0 else 0.0
    primary = VolumeInfo(
        filesystem="primary",
        mount_point=str(resolved),
        total_bytes=total,
        used_bytes=used,
        available_bytes=free,
        percent_used=pct,
        total_human=human_size(total),
        used_human=human_size(used),
        available_human=human_size(free),
    )
    volumes = _list_mounted_volumes()
    if not volumes:
        volumes = [primary]

    # Query native APFS container breakdown when available on macOS
    apfs_info = _get_apfs_info(str(resolved))
    target_vol_name: str | None = None
    target_mount: str | None = None
    if apfs_info:
        target_mount = _find_mount_for_path(str(resolved))
        if target_mount:
            for v in apfs_info.volumes:
                if v.mount_point == target_mount:
                    target_vol_name = v.name
                    break

    return StorageOverview(
        target_path=str(resolved),
        primary=primary,
        volumes=volumes,
        apfs=apfs_info,
        target_volume_name=target_vol_name,
        target_mount_point=target_mount,
    )


def _find_mount_for_path(path: str) -> str | None:
    """Determine the mount point for a given path using 'df -P'."""
    res = run_command(["df", "-P", path], timeout=2.0)
    if not res.ok or not res.stdout:
        return None
    lines = res.stdout.strip().splitlines()
    if len(lines) >= 2:
        parts = lines[1].split(None, 5)
        if len(parts) >= 6:
            return parts[5]
    return None


def _get_apfs_info(target_path: str) -> APFSContainerInfo | None:
    """Query native macOS diskutil for APFS container and volume breakdown."""
    mount_point = _find_mount_for_path(target_path) or target_path
    info_res = run_command(["diskutil", "info", mount_point], timeout=2.0)
    if not info_res.ok or not info_res.stdout:
        return None

    info: dict[str, str] = {}
    for line in info_res.stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()

    fs_type = info.get("File System Personality", "")
    if fs_type != "APFS":
        return None

    container_id = info.get("Part of Whole")
    if not container_id:
        return None

    apfs_res = run_command(["diskutil", "apfs", "list", container_id], timeout=3.0)
    if not apfs_res.ok or not apfs_res.stdout:
        return None

    text = apfs_res.stdout
    m_size = re.search(r"Size \(Capacity Ceiling\):\s+(\d+)\s+B", text)
    m_used = re.search(r"Capacity In Use By Volumes:\s+(\d+)\s+B", text)
    m_free = re.search(r"Capacity Not Allocated:\s+(\d+)\s+B", text)

    if not m_size or not m_used or not m_free:
        return None

    total_b = int(m_size.group(1))
    used_b = int(m_used.group(1))
    free_b = int(m_free.group(1))
    pct = round((used_b / total_b * 100.0), 1) if total_b > 0 else 0.0

    vol_blocks = re.split(r"\n\s*\+->\s*Volume\s+", text)
    vol_entries: list[APFSVolumeEntry] = []

    for vb in vol_blocks[1:]:
        name_m = re.search(r"Name:\s+(.*?)(?:\s+\(Case-[a-z]+\))?$", vb, re.M)
        role_m = re.search(r"APFS Volume Disk \(Role\):\s+(\S+)\s+\((.*?)\)", vb)
        mount_m = re.search(r"Mount Point:\s+(.*?)$", vb, re.M)
        snap_mount_m = re.search(r"Snapshot Mount Point:\s+(.*?)$", vb, re.M)
        cap_m = re.search(r"Capacity Consumed:\s+(\d+)\s+B", vb)

        vol_disk = role_m.group(1) if role_m else "unknown"
        role = role_m.group(2) if role_m else "None"
        name = name_m.group(1).strip() if name_m else "Unknown"
        mount = (
            snap_mount_m.group(1).strip()
            if snap_mount_m
            else (mount_m.group(1).strip() if mount_m else "Not Mounted")
        )
        cap = int(cap_m.group(1)) if cap_m else 0
        vol_pct = round((cap / total_b * 100.0), 1) if total_b > 0 else 0.0

        vol_entries.append(
            APFSVolumeEntry(
                disk_id=vol_disk,
                name=name,
                role=role,
                mount_point=mount,
                used_bytes=cap,
                used_human=human_size(cap),
                percent_of_container=vol_pct,
            )
        )

    return APFSContainerInfo(
        container_id=container_id,
        total_bytes=total_b,
        used_bytes=used_b,
        free_bytes=free_b,
        percent_used=pct,
        total_human=human_size(total_b),
        used_human=human_size(used_b),
        free_human=human_size(free_b),
        volumes=vol_entries,
    )


def _list_mounted_volumes() -> list[VolumeInfo]:
    """Parse ``df -kP`` into :class:`VolumeInfo` records when available."""
    res = run_command(["df", "-kP"], timeout=2.0)
    if not res.ok or not res.stdout:
        return []
    volumes: list[VolumeInfo] = []
    seen_mounts: set[str] = set()
    lines = res.stdout.splitlines()
    for line in lines[1:]:
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        fs_name, blocks_s, used_s, avail_s, _cap_s, mount = parts
        if fs_name in ("devfs", "none", "tmpfs") or fs_name.startswith("map "):
            continue
        ignored_mounts = (
            "/dev",
            "/System/Volumes/VM",
            "/System/Volumes/Preboot",
            "/System/Volumes/Update",
            "/System/Volumes/xarts",
            "/System/Volumes/iSCPreboot",
            "/System/Volumes/Hardware",
        )
        if mount.startswith(ignored_mounts):
            continue
        if mount in seen_mounts:
            continue
        try:
            total_b = int(blocks_s) * 1024
            used_b = int(used_s) * 1024
            avail_b = int(avail_s) * 1024
        except ValueError:
            continue
        if total_b <= 0:
            continue
        seen_mounts.add(mount)
        pct = round((used_b / total_b * 100.0), 1)
        volumes.append(
            VolumeInfo(
                filesystem=fs_name,
                mount_point=mount,
                total_bytes=total_b,
                used_bytes=used_b,
                available_bytes=avail_b,
                percent_used=pct,
                total_human=human_size(total_b),
                used_human=human_size(used_b),
                available_human=human_size(avail_b),
            )
        )
    return volumes


def validate_scan_root(path: str | os.PathLike[str]) -> Path:
    """Resolve and validate that ``path`` exists and is a directory."""
    resolved = resolve_user_path(path)
    if not os.path.lexists(resolved):
        raise NotFoundError(
            f"Directory does not exist: {resolved}",
            hint="Verify the directory path and try again.",
        )
    try:
        st = resolved.lstat()
    except OSError as exc:
        raise NotFoundError(
            f"Cannot inspect path {resolved}: {exc.strerror or exc}",
            hint="Check path permissions and try again.",
        ) from exc
    if not stat.S_ISDIR(st.st_mode):
        raise UsageError(
            f"Path is not a directory: {resolved}",
            hint="Provide a directory path (not a file or symlink).",
        )
    return resolved


def scan_directory(
    path: str | os.PathLike[str] = ".",
    *,
    depth: int = 2,
    include_hidden: bool = True,
    cross_device: bool = False,
    top_n: int = 20,
    min_file_size: int = 0,
    large_project_threshold_bytes: int = 100 * 1000 * 1000,
    extra_cleanup_names: tuple[str, ...] = (),
    collect_records: bool = False,
    progress: NullProgress | None = None,
) -> ScanResult:
    """Iteratively scan ``path`` with ``os.scandir`` without following symlinks."""
    if depth < 0:
        raise UsageError("--depth must be >= 0.")
    if top_n < 1:
        raise UsageError("--limit must be >= 1.")

    root_path = validate_scan_root(path)
    root_str = str(root_path)
    root_dev = root_path.lstat().st_dev

    home_path = Path(os.path.abspath(Path.home()))
    cache_roots = get_known_cache_roots(home_path)
    downloads_root = str(home_path / "Downloads")
    logs_root = str(home_path / "Library" / "Logs")

    root_cls = classify_directory(
        root_path.name,
        root_str,
        frozenset(),
        cache_roots=cache_roots,
        downloads_root=downloads_root,
        logs_root=logs_root,
        extra_cleanup_names=extra_cleanup_names,
    )

    seen_inodes: set[tuple[int, int]] = set()
    file_count = 0
    dir_count = 0
    symlink_count = 0
    symlink_bytes = 0
    special_count = 0
    hardlink_count = 0
    hardlink_bytes_saved = 0
    unreadable_count = 0
    errors: list[str] = []

    dir_own_bytes: dict[str, int] = {}
    dir_total_bytes: dict[str, int] = {}
    dir_children: dict[str, list[str]] = {}
    dir_meta: dict[str, tuple[str, int, str, Confidence]] = {}
    project_manifests: dict[str, tuple[str, ...]] = {}

    cat_bytes: dict[str, int] = {}
    cat_files: dict[str, int] = {}
    cat_verified_bytes: dict[str, int] = {}
    cat_heuristic_bytes: dict[str, int] = {}

    def _add_category(cls: Classification, size: int) -> None:
        cat = cls.category
        cat_bytes[cat] = cat_bytes.get(cat, 0) + size
        cat_files[cat] = cat_files.get(cat, 0) + 1
        if cls.confidence == "verified":
            cat_verified_bytes[cat] = cat_verified_bytes.get(cat, 0) + size
        else:
            cat_heuristic_bytes[cat] = cat_heuristic_bytes.get(cat, 0) + size

    # Min-heap of (size_bytes, path_str, category, confidence, mtime)
    largest_heap: list[tuple[int, str, str, Confidence, float]] = []
    non_dir_records: list[ExportRecord] = []

    # Stack elements: (dir_str, rel_depth, is_post, inherited_cls, has_ancestor_py_manifest)
    stack: list[tuple[str, int, bool, Classification | None, bool]] = [
        (root_str, 0, False, root_cls, False)
    ]

    root_cls_eff = root_cls or Classification("other", "verified")
    dir_meta[root_str] = (
        root_path.name or root_str,
        0,
        root_cls_eff.category,
        root_cls_eff.confidence,
    )

    while stack:
        cur_dir, cur_depth, is_post, inherited_cls, ancestor_py = stack.pop()
        if is_post:
            total_d = dir_own_bytes.get(cur_dir, 0)
            for child_d in dir_children.get(cur_dir, ()):
                total_d += dir_total_bytes.get(child_d, 0)
            dir_total_bytes[cur_dir] = total_d
            continue

        if progress is not None:
            progress.advance(1)

        try:
            with os.scandir(cur_dir) as it:
                raw_entries = list(it)
        except OSError as exc:
            unreadable_count += 1
            if len(errors) < MAX_RECORDED_ERRORS:
                errors.append(f"{cur_dir}: {exc.strerror or exc}")
            dir_own_bytes[cur_dir] = 0
            dir_children[cur_dir] = []
            dir_total_bytes[cur_dir] = 0
            continue

        visible = (
            raw_entries
            if include_hidden
            else [e for e in raw_entries if not e.name.startswith(".")]
        )
        sibling_names = {e.name for e in visible}
        manifests_here = detect_manifests(sibling_names)
        if manifests_here:
            project_manifests[cur_dir] = manifests_here
        has_py = ancestor_py or bool(sibling_names & PYTHON_MANIFESTS)

        direct_bytes = 0
        sub_dirs: list[tuple[str, str, Classification | None]] = []

        for entry in visible:
            entry_path = entry.path
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                unreadable_count += 1
                if len(errors) < MAX_RECORDED_ERRORS:
                    errors.append(f"{entry_path}: {exc.strerror or exc}")
                continue

            if not cross_device and st.st_dev != root_dev:
                continue

            mode = st.st_mode
            if stat.S_ISLNK(mode):
                symlink_count += 1
                lsize = max(int(st.st_size), 0)
                symlink_bytes += lsize
                direct_bytes += lsize
                cls = classify_file(
                    entry.name,
                    entry_path,
                    inherited=inherited_cls,
                    cache_roots=cache_roots,
                    downloads_root=downloads_root,
                    logs_root=logs_root,
                    extra_cleanup_names=extra_cleanup_names,
                )
                _add_category(cls, lsize)
                if collect_records:
                    non_dir_records.append(
                        ExportRecord(
                            path=entry_path,
                            size_bytes=lsize,
                            type="symlink",
                            category=cls.category,
                            confidence=cls.confidence,
                        )
                    )
            elif stat.S_ISDIR(mode):
                dir_count += 1
                child_cls = classify_directory(
                    entry.name,
                    entry_path,
                    sibling_names,
                    cache_roots=cache_roots,
                    downloads_root=downloads_root,
                    logs_root=logs_root,
                    has_ancestor_python_manifest=has_py,
                    extra_cleanup_names=extra_cleanup_names,
                )
                effective_child_cls = child_cls if child_cls is not None else inherited_cls
                cat_for_meta = (
                    effective_child_cls.category if effective_child_cls is not None else "other"
                )
                conf_for_meta: Confidence = (
                    effective_child_cls.confidence
                    if effective_child_cls is not None
                    else "verified"
                )
                dir_meta[entry_path] = (
                    entry.name,
                    cur_depth + 1,
                    cat_for_meta,
                    conf_for_meta,
                )
                sub_dirs.append((entry_path, entry.name, effective_child_cls))
            elif stat.S_ISREG(mode):
                file_count += 1
                fsize = max(int(st.st_size), 0)
                ino_key = (st.st_dev, st.st_ino)
                if st.st_ino != 0 and ino_key in seen_inodes:
                    hardlink_count += 1
                    hardlink_bytes_saved += fsize
                    effective_size = 0
                    is_dup_link = True
                else:
                    if st.st_ino != 0:
                        seen_inodes.add(ino_key)
                    effective_size = fsize
                    is_dup_link = False

                direct_bytes += effective_size
                cls = classify_file(
                    entry.name,
                    entry_path,
                    inherited=inherited_cls,
                    cache_roots=cache_roots,
                    downloads_root=downloads_root,
                    logs_root=logs_root,
                    extra_cleanup_names=extra_cleanup_names,
                )
                _add_category(cls, effective_size)

                if not is_dup_link and fsize >= min_file_size:
                    item = (fsize, entry_path, cls.category, cls.confidence, float(st.st_mtime))
                    if len(largest_heap) < top_n:
                        heapq.heappush(largest_heap, item)
                    elif fsize > largest_heap[0][0] or (
                        fsize == largest_heap[0][0] and entry_path < largest_heap[0][1]
                    ):
                        heapq.heapreplace(largest_heap, item)

                if collect_records:
                    non_dir_records.append(
                        ExportRecord(
                            path=entry_path,
                            size_bytes=fsize,
                            type="file",
                            category=cls.category,
                            confidence=cls.confidence,
                        )
                    )
            else:
                # Special files: FIFOs, sockets, block/character devices (never opened)
                special_count += 1
                if collect_records:
                    non_dir_records.append(
                        ExportRecord(
                            path=entry_path,
                            size_bytes=0,
                            type="special",
                            category="other",
                            confidence="verified",
                        )
                    )

        dir_own_bytes[cur_dir] = direct_bytes
        dir_children[cur_dir] = [d[0] for d in sub_dirs]
        stack.append((cur_dir, cur_depth, True, inherited_cls, has_py))
        for child_path, _child_name, child_cls in reversed(sub_dirs):
            stack.append((child_path, cur_depth + 1, False, child_cls, has_py))

    total_bytes = dir_total_bytes.get(root_str, 0)

    # Identify large project directories (manifest present and >= threshold)
    large_projects: list[LargeProjectEntry] = []
    for proj_dir, manifests in project_manifests.items():
        proj_size = dir_total_bytes.get(proj_dir, 0)
        if proj_size >= large_project_threshold_bytes:
            large_projects.append(
                LargeProjectEntry(
                    path=proj_dir,
                    size_bytes=proj_size,
                    size_human=human_size(proj_size),
                    manifests=list(manifests),
                    confidence="verified",
                )
            )
    large_projects.sort(key=lambda p: (-p.size_bytes, p.path))

    # Build directory entries
    all_sub_dirs: list[DirEntry] = []
    top_children: list[DirEntry] = []
    tree_entries: list[DirEntry] = []

    for d_path, (d_name, d_depth, d_cat, d_conf) in dir_meta.items():
        if d_path == root_str:
            continue
        d_size = dir_total_bytes.get(d_path, 0)
        entry_obj = DirEntry(
            path=d_path,
            name=d_name,
            depth=d_depth,
            size_bytes=d_size,
            size_human=human_size(d_size),
            category=d_cat,
            confidence=d_conf,
        )
        all_sub_dirs.append(entry_obj)
        if d_depth == 1:
            top_children.append(entry_obj)
        if 1 <= d_depth <= depth:
            tree_entries.append(entry_obj)

    top_children.sort(key=lambda d: (-d.size_bytes, d.path))
    tree_entries.sort(key=lambda d: (d.depth, -d.size_bytes, d.path))
    all_sub_dirs.sort(key=lambda d: (-d.size_bytes, d.path))
    largest_dirs = all_sub_dirs[:top_n]

    largest_files_sorted = sorted(largest_heap, key=lambda x: (-x[0], x[1]))
    largest_files = [
        FileEntry(
            path=f_path,
            size_bytes=f_size,
            size_human=human_size(f_size),
            category=f_cat,
            confidence=f_conf,
            mtime=f_mtime,
        )
        for f_size, f_path, f_cat, f_conf, f_mtime in largest_files_sorted
    ]

    categories: list[CategoryStat] = []
    for cat_key, size_b in cat_bytes.items():
        f_cnt = cat_files.get(cat_key, 0)
        if f_cnt == 0 and size_b == 0:
            continue
        ver_b = cat_verified_bytes.get(cat_key, 0)
        heur_b = cat_heuristic_bytes.get(cat_key, 0)
        conf: Confidence = "verified" if heur_b == 0 and ver_b >= 0 else "heuristic"
        if ver_b > 0 and heur_b == 0:
            conf = "verified"
        elif heur_b > 0:
            conf = "heuristic"
        pct = round((size_b / total_bytes * 100.0), 1) if total_bytes > 0 else 0.0
        categories.append(
            CategoryStat(
                category=cat_key,
                label=CATEGORY_LABELS.get(cat_key, cat_key),
                size_bytes=size_b,
                size_human=human_size(size_b),
                file_count=f_cnt,
                percent_of_total=pct,
                confidence=conf,
                verified_bytes=ver_b,
                heuristic_bytes=heur_b,
            )
        )
    if large_projects:
        lp_bytes = sum(lp.size_bytes for lp in large_projects)
        lp_pct = (
            round((min(lp_bytes, total_bytes) / total_bytes * 100.0), 1) if total_bytes > 0 else 0.0
        )
        categories.append(
            CategoryStat(
                category="large_project",
                label=CATEGORY_LABELS["large_project"],
                size_bytes=lp_bytes,
                size_human=human_size(lp_bytes),
                file_count=len(large_projects),
                percent_of_total=lp_pct,
                confidence="verified",
                verified_bytes=lp_bytes,
                heuristic_bytes=0,
            )
        )
    categories.sort(key=lambda c: (-c.size_bytes, c.category))

    export_records: list[ExportRecord] = []
    if collect_records:
        for d_path, (_d_name, _d_depth, d_cat, d_conf) in dir_meta.items():
            export_records.append(
                ExportRecord(
                    path=d_path,
                    size_bytes=dir_total_bytes.get(d_path, 0),
                    type="dir",
                    category=d_cat,
                    confidence=d_conf,
                )
            )
        export_records.extend(non_dir_records)
        export_records.sort(key=lambda r: r.path)

    return ScanResult(
        root=root_str,
        depth=depth,
        include_hidden=include_hidden,
        cross_device=cross_device,
        total_bytes=total_bytes,
        total_human=human_size(total_bytes),
        file_count=file_count,
        dir_count=dir_count,
        symlink_count=symlink_count,
        symlink_bytes=symlink_bytes,
        special_count=special_count,
        hardlink_count=hardlink_count,
        hardlink_bytes_saved=hardlink_bytes_saved,
        hardlink_saved_human=human_size(hardlink_bytes_saved),
        unreadable_count=unreadable_count,
        errors=errors,
        top_children=top_children,
        tree_entries=tree_entries,
        largest_files=largest_files,
        largest_dirs=largest_dirs,
        categories=categories,
        large_projects=large_projects,
        export_records=export_records,
    )
