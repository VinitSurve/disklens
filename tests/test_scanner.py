"""Unit and functional tests for disklens scanner and storage categorization."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from disklens.common.exceptions import NotFoundError, UsageError
from disklens.scanner import get_storage_overview, scan_directory


def test_storage_overview_basic(isolated_env: Path) -> None:
    overview = get_storage_overview(isolated_env)
    assert overview.target_path == str(isolated_env)
    assert overview.primary.total_bytes > 0
    assert overview.primary.available_bytes >= 0
    assert 0.0 <= overview.primary.percent_used <= 100.0
    assert len(overview.volumes) >= 1


def test_storage_overview_missing_path(isolated_env: Path) -> None:
    with pytest.raises(NotFoundError):
        get_storage_overview(isolated_env / "does_not_exist")


def test_scan_validation_errors(tmp_path: Path) -> None:
    with pytest.raises(NotFoundError):
        scan_directory(tmp_path / "missing")

    f = tmp_path / "file.txt"
    f.write_text("hello")
    with pytest.raises(UsageError):
        scan_directory(f)

    with pytest.raises(UsageError):
        scan_directory(tmp_path, depth=-1)

    with pytest.raises(UsageError):
        scan_directory(tmp_path, top_n=0)


def test_scan_empty_directory(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    res = scan_directory(empty)
    assert res.total_bytes == 0
    assert res.file_count == 0
    assert res.dir_count == 0
    assert res.symlink_count == 0
    assert res.special_count == 0
    assert res.hardlink_count == 0
    assert res.unreadable_count == 0
    assert res.top_children == []
    assert res.largest_files == []


def test_scan_depth_and_hidden_controls(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / "a" / "b" / "c").mkdir(parents=True)
    (root / "a" / "top.txt").write_bytes(b"x" * 100)
    (root / "a" / "b" / "mid.txt").write_bytes(b"y" * 200)
    (root / "a" / "b" / "c" / "deep.txt").write_bytes(b"z" * 300)
    (root / ".hidden_file").write_bytes(b"h" * 50)
    (root / ".hidden_dir").mkdir()
    (root / ".hidden_dir" / "sec.txt").write_bytes(b"s" * 75)

    # With hidden included and depth=1: total_bytes includes all depths + hidden
    res_d1 = scan_directory(root, depth=1, include_hidden=True)
    assert res_d1.total_bytes == 100 + 200 + 300 + 50 + 75
    assert res_d1.file_count == 5
    assert all(d.depth <= 1 for d in res_d1.tree_entries)
    assert any(d.name == "a" and d.size_bytes == 600 for d in res_d1.top_children)

    # With hidden excluded (--no-hidden): dotfiles and dotdirs are skipped
    res_no_hidden = scan_directory(root, depth=2, include_hidden=False)
    assert res_no_hidden.total_bytes == 600
    assert res_no_hidden.file_count == 3
    assert all(not d.name.startswith(".") for d in res_no_hidden.top_children)


def test_scan_never_follows_symlinks_or_loops(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "big.bin").write_bytes(b"O" * 10_000)

    root = tmp_path / "scan_root"
    sub = root / "sub"
    sub.mkdir(parents=True)
    (sub / "real.txt").write_bytes(b"R" * 128)

    # Symlink loop back to root and mutual loop
    (sub / "loop_to_root").symlink_to(root)
    (sub / "loop_a").symlink_to(sub / "loop_b")
    (sub / "loop_b").symlink_to(sub / "loop_a")
    # Symlink to outside directory
    (sub / "outside_link").symlink_to(outside)

    res = scan_directory(root)
    assert res.file_count == 1
    assert res.symlink_count == 4
    # Outside 10,000-byte file must NOT be included
    assert res.total_bytes == 128 + res.symlink_bytes
    assert res.total_bytes < 1_000


def test_scan_deduplicates_hard_links(tmp_path: Path) -> None:
    root = tmp_path / "hardlinks"
    root.mkdir()
    orig = root / "original.bin"
    orig.write_bytes(b"A" * 4096)
    link1 = root / "link1.bin"
    link2 = root / "link2.bin"
    os.link(orig, link1)
    os.link(orig, link2)

    other = root / "unique.bin"
    other.write_bytes(b"B" * 1024)

    res = scan_directory(root)
    # 4096 counted once + 1024 = 5120
    assert res.total_bytes == 4096 + 1024
    assert res.hardlink_count == 2
    assert res.hardlink_bytes_saved == 4096 * 2
    assert len(res.largest_files) == 2


def test_scan_handles_fifo_special_files_without_blocking(tmp_path: Path) -> None:
    root = tmp_path / "specials"
    root.mkdir()
    fifo_path = root / "test.fifo"
    os.mkfifo(fifo_path)
    (root / "normal.txt").write_bytes(b"ok")

    res = scan_directory(root)
    assert res.special_count == 1
    assert res.file_count == 1
    assert res.total_bytes == 2


def test_scan_handles_unreadable_directory_gracefully(tmp_path: Path) -> None:
    root = tmp_path / "perm_test"
    readable = root / "readable"
    secret = root / "secret"
    readable.mkdir(parents=True)
    secret.mkdir(parents=True)
    (readable / "ok.txt").write_bytes(b"12345")
    (secret / "hidden.txt").write_bytes(b"99999")

    secret.chmod(0o000)
    try:
        if os.access(secret, os.R_OK):
            pytest.skip("Running as root; chmod 000 does not restrict read")
        res = scan_directory(root)
        assert res.total_bytes == 5
        assert res.unreadable_count >= 1
        assert any("secret" in err for err in res.errors)
    finally:
        secret.chmod(0o755)


def test_scan_unicode_and_spaces_and_sparse_file(tmp_path: Path) -> None:
    root = tmp_path / "uni_root"
    weird_dir = root / "Café & Données 🚀" / "sub, folder"
    weird_dir.mkdir(parents=True)
    weird_file = weird_dir / "résumé (final) 'v2'.txt"
    weird_file.write_bytes(b"U" * 256)

    sparse = root / "sparse.img"
    sparse.write_bytes(b"")
    os.truncate(sparse, 50 * 1024 * 1024)  # 50 MiB sparse file

    res = scan_directory(root)
    assert res.file_count == 2
    assert res.total_bytes == 50 * 1024 * 1024 + 256
    assert res.largest_files[0].path == str(sparse)
    assert any("résumé" in f.path for f in res.largest_files)


def test_scan_cross_device_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "mounts"
    sub = root / "other_fs"
    sub.mkdir(parents=True)
    (root / "local.txt").write_bytes(b"L" * 100)
    (sub / "remote.txt").write_bytes(b"R" * 900)

    real_scandir = os.scandir

    class _FakeDirEntry:
        def __init__(self, inner: os.DirEntry[str], fake_dev: int | None) -> None:
            self._inner = inner
            self._fake_dev = fake_dev

        @property
        def name(self) -> str:
            return self._inner.name

        @property
        def path(self) -> str:
            return self._inner.path

        def stat(self, *, follow_symlinks: bool = True) -> object:
            st = self._inner.stat(follow_symlinks=follow_symlinks)
            if self._fake_dev is None:
                return st
            return SimpleNamespace(
                st_mode=st.st_mode,
                st_size=st.st_size,
                st_dev=self._fake_dev,
                st_ino=st.st_ino,
                st_mtime=st.st_mtime,
            )

    class _FakeScandir:
        def __init__(self, target: str) -> None:
            self._target = target
            self._cm = real_scandir(target)

        def __enter__(self) -> list[_FakeDirEntry]:
            entries = list(self._cm.__enter__())
            return [_FakeDirEntry(e, 999999 if e.name == "other_fs" else None) for e in entries]

        def __exit__(self, *args: object) -> None:
            self._cm.__exit__(*args)

    monkeypatch.setattr(os, "scandir", _FakeScandir)

    res_no_cross = scan_directory(root, cross_device=False)
    assert res_no_cross.total_bytes == 100

    res_cross = scan_directory(root, cross_device=True)
    assert res_cross.total_bytes == 1000


def test_scan_categories_and_confidence(isolated_env: Path) -> None:
    proj = isolated_env / "my_project"
    proj.mkdir()
    (proj / "package.json").write_text('{"name": "demo"}')
    (proj / "pyproject.toml").write_text('[project]\nname = "demo"\n')

    nm = proj / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_bytes(b"j" * 2000)

    dist = proj / "dist"
    dist.mkdir()
    (dist / "bundle.js").write_bytes(b"b" * 1500)

    media_dir = proj / "assets"
    media_dir.mkdir()
    (media_dir / "clip.mp4").write_bytes(b"m" * 3000)
    (media_dir / "archive.tar.gz").write_bytes(b"a" * 1200)
    (proj / "app.log").write_bytes(b"l" * 400)
    (proj / ".DS_Store").write_bytes(b"d" * 100)

    # Heuristic build dir without manifest
    unverified_parent = isolated_env / "plain_folder"
    (unverified_parent / "build").mkdir(parents=True)
    (unverified_parent / "build" / "out.bin").write_bytes(b"x" * 500)

    res = scan_directory(
        isolated_env,
        large_project_threshold_bytes=5000,
    )
    by_cat = {c.category: c for c in res.categories}

    assert "dependencies" in by_cat
    assert by_cat["dependencies"].confidence == "verified"

    assert "build_artifacts" in by_cat
    assert by_cat["build_artifacts"].verified_bytes == 1500
    assert by_cat["build_artifacts"].heuristic_bytes == 500
    assert by_cat["build_artifacts"].confidence == "heuristic"

    assert "media" in by_cat and by_cat["media"].confidence == "heuristic"
    assert "archives" in by_cat and by_cat["archives"].confidence == "heuristic"
    assert "logs" in by_cat and by_cat["logs"].confidence == "heuristic"
    assert "temp" in by_cat and by_cat["temp"].confidence == "verified"
    assert "large_project" in by_cat and by_cat["large_project"].confidence == "verified"
    assert len(res.large_projects) == 1
    assert res.large_projects[0].path == str(proj)


@pytest.mark.slow
def test_scan_20k_files_performance_sanity(tmp_path: Path) -> None:
    root = tmp_path / "perf_20k"
    root.mkdir()
    total_files = 20_000
    dirs_count = 40
    files_per_dir = total_files // dirs_count

    for d_idx in range(dirs_count):
        sub = root / f"dir_{d_idx:03d}"
        sub.mkdir()
        for f_idx in range(files_per_dir):
            (sub / f"f_{f_idx:04d}.dat").write_bytes(b"x" * 16)

    res = scan_directory(root, depth=1, top_n=10)
    assert res.file_count == total_files
    assert res.dir_count == dirs_count
    assert res.total_bytes == total_files * 16
    assert len(res.largest_files) == 10


def test_apfs_storage_reporting_semantics_mocked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from disklens.common.output import Output
    from disklens.render import render_storage_overview

    mock_diskutil_info = """
   Device Identifier:         disk3s5
   Device Node:               /dev/disk3s5
   Part of Whole:             disk3
   Volume Name:               Data
   Mount Point:               /System/Volumes/Data
   File System Personality:   APFS
   Volume Used Space:         150295199744 B (150.3 GB)
   Container Total Space:     494332366848 B (494.3 GB)
   Container Free Space:      312244441088 B (312.2 GB)
"""

    mock_diskutil_apfs_list = """
+-- Container disk3 B7032D5C-8D6A-4A28-BF60-141F651A41FC
    ====================================================
    APFS Container Reference:     disk3
    Size (Capacity Ceiling):      494332366848 B (494.3 GB)
    Capacity In Use By Volumes:   182087925760 B (182.1 GB) (36.8% used)
    Capacity Not Allocated:       312244441088 B (312.2 GB) (63.2% free)
    |
    +-> Volume disk3s1 F23386E9-1814-494D-AEE7-9F5FF2DABDB3
    |   ---------------------------------------------------
    |   APFS Volume Disk (Role):   disk3s1 (System)
    |   Name:                      Macintosh HD
    |   Mount Point:               /
    |   Capacity Consumed:         12569911296 B (12.6 GB)
    |
    +-> Volume disk3s2 F458DB50-7C73-4E36-B4B3-D062BE5F505E
    |   ---------------------------------------------------
    |   APFS Volume Disk (Role):   disk3s2 (Preboot)
    |   Name:                      Preboot
    |   Mount Point:               /System/Volumes/Preboot
    |   Capacity Consumed:         7750090752 B (7.8 GB)
    |
    +-> Volume disk3s5 B39370FF-A428-4B84-B5CE-DCE6585FBCAE
        ---------------------------------------------------
        APFS Volume Disk (Role):   disk3s5 (Data)
        Name:                      Data
        Mount Point:               /System/Volumes/Data
        Capacity Consumed:         150295199744 B (150.3 GB)
"""

    mock_df_p = """
Filesystem   512-blocks      Used Available Capacity Mounted on
/dev/disk3s5  965492904 293574248 609823488    33%   /System/Volumes/Data
"""

    def fake_run_command(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
        if cmd[:2] == ["diskutil", "info"]:
            return SimpleNamespace(ok=True, stdout=mock_diskutil_info, stderr="", exit_code=0)
        if cmd[:3] == ["diskutil", "apfs", "list"]:
            return SimpleNamespace(ok=True, stdout=mock_diskutil_apfs_list, stderr="", exit_code=0)
        if cmd[:2] == ["df", "-P"]:
            return SimpleNamespace(ok=True, stdout=mock_df_p, stderr="", exit_code=0)
        if cmd[:2] == ["df", "-kP"]:
            return SimpleNamespace(
                ok=True,
                stdout="/dev/disk3s5 482746452 146787124 304911720 33% /System/Volumes/Data\n",
                stderr="",
                exit_code=0,
            )
        return SimpleNamespace(ok=False, stdout="", stderr="", exit_code=1)

    monkeypatch.setattr("disklens.scanner.run_command", fake_run_command)

    overview = get_storage_overview(tmp_path)
    assert overview.apfs is not None
    assert overview.apfs.container_id == "disk3"
    assert overview.apfs.total_bytes == 494332366848
    assert overview.apfs.free_bytes == 312244441088
    assert overview.apfs.used_bytes == 182087925760
    assert len(overview.apfs.volumes) == 3
    assert overview.target_mount_point == "/System/Volumes/Data"
    assert overview.target_volume_name == "Data"

    # Test rendering APFS overview
    out = Output("disklens")
    render_storage_overview(out, overview)


def test_apfs_fallback_on_non_apfs_filesystem(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from disklens.common.output import Output
    from disklens.render import render_storage_overview

    def fake_run_command(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
        if cmd[:2] == ["diskutil", "info"]:
            return SimpleNamespace(
                ok=True, stdout="File System Personality: Ext4\n", stderr="", exit_code=0
            )
        if cmd[:2] == ["df", "-kP"]:
            return SimpleNamespace(
                ok=True,
                stdout="Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100000 50000 50000 50% /\n",
                stderr="",
                exit_code=0,
            )
        return SimpleNamespace(ok=False, stdout="", stderr="", exit_code=1)

    monkeypatch.setattr("disklens.scanner.run_command", fake_run_command)

    overview = get_storage_overview(tmp_path)
    assert overview.apfs is None
    assert overview.primary.total_bytes > 0
    assert len(overview.volumes) >= 1

    out = Output("disklens")
    render_storage_overview(out, overview)
