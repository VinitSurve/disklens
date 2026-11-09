"""Unit and functional tests for disklens two-stage duplicate detection."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from disklens.common.exceptions import UsageError
from disklens.duplicates import find_duplicates


def test_duplicates_unique_sizes_never_hashed(tmp_path: Path) -> None:
    (tmp_path / "f1.bin").write_bytes(b"a" * 100)
    (tmp_path / "f2.bin").write_bytes(b"b" * 200)
    (tmp_path / "f3.bin").write_bytes(b"c" * 300)

    res = find_duplicates(tmp_path)
    assert res.total_files_scanned == 3
    assert res.duplicate_group_count == 0
    assert res.partial_hashes_computed == 0
    assert res.full_hashes_computed == 0
    assert res.reclaimable_bytes == 0


def test_duplicates_same_filename_not_duplicate_and_different_names_matched(
    tmp_path: Path,
) -> None:
    d1 = tmp_path / "dir1"
    d2 = tmp_path / "dir2"
    d1.mkdir()
    d2.mkdir()

    # Same filename, same size, different content -> NOT duplicates
    (d1 / "config.yaml").write_bytes(b"A" * 512)
    (d2 / "config.yaml").write_bytes(b"B" * 512)

    # Different filenames, identical content -> duplicates
    payload = b"duplicated-payload-" * 50
    (d1 / "alpha.dat").write_bytes(payload)
    (d2 / "bravo.bin").write_bytes(payload)

    res = find_duplicates(tmp_path)
    assert res.duplicate_group_count == 1
    grp = res.duplicate_groups[0]
    assert grp.size_bytes == len(payload)
    assert grp.reclaimable_bytes == len(payload)
    assert grp.paths == sorted([str(d1 / "alpha.dat"), str(d2 / "bravo.bin")])


def test_duplicates_two_stage_partial_vs_full_sha256(tmp_path: Path) -> None:
    partial_kib = 4  # 4096 bytes prefix
    prefix = b"P" * 4096
    suffix_a = b"A" * 4096
    suffix_b = b"B" * 4096

    # Group 1: same size (8192), DIFFERENT in first 4 KiB -> Stage 1 filters out
    (tmp_path / "early_diff_1.bin").write_bytes(b"X" * 8192)
    (tmp_path / "early_diff_2.bin").write_bytes(b"Y" * 8192)

    # Now test in separate folder to verify exact hash counts
    stage1_only = tmp_path / "stage1_only"
    stage1_only.mkdir()
    (stage1_only / "a.bin").write_bytes(b"X" * 8192)
    (stage1_only / "b.bin").write_bytes(b"Y" * 8192)
    res_s1 = find_duplicates(stage1_only, partial_kib=partial_kib)
    assert res_s1.partial_hashes_computed == 2
    assert res_s1.full_hashes_computed == 0
    assert res_s1.duplicate_group_count == 0

    # Group 2: same 4 KiB prefix, DIFFERENT in second 4 KiB -> Stage 2 distinguishes
    stage2_diff = tmp_path / "stage2_diff"
    stage2_diff.mkdir()
    (stage2_diff / "c1.bin").write_bytes(prefix + suffix_a)
    (stage2_diff / "c2.bin").write_bytes(prefix + suffix_b)
    res_s2 = find_duplicates(stage2_diff, partial_kib=partial_kib)
    assert res_s2.partial_hashes_computed == 2
    assert res_s2.full_hashes_computed == 2
    assert res_s2.duplicate_group_count == 0

    # Group 3: identical across all 8 KiB -> Stage 1 and Stage 2 confirm duplicate
    stage2_match = tmp_path / "stage2_match"
    stage2_match.mkdir()
    (stage2_match / "m1.bin").write_bytes(prefix + suffix_a)
    (stage2_match / "m2.bin").write_bytes(prefix + suffix_a)
    (stage2_match / "m3.bin").write_bytes(prefix + suffix_a)
    res_s3 = find_duplicates(stage2_match, partial_kib=partial_kib)
    assert res_s3.partial_hashes_computed == 3
    assert res_s3.full_hashes_computed == 3
    assert res_s3.duplicate_group_count == 1
    assert res_s3.reclaimable_bytes == 8192 * 2


def test_duplicates_hardlinks_separated_and_excluded_from_reclaimable(tmp_path: Path) -> None:
    # 1. Pure hardlink group (1 inode, 3 paths): 0 wasted bytes, not in duplicate_groups
    hl_only = tmp_path / "hl_only"
    hl_only.mkdir()
    base = hl_only / "base.bin"
    base.write_bytes(b"H" * 2048)
    os.link(base, hl_only / "hl1.bin")
    os.link(base, hl_only / "hl2.bin")

    res_hl = find_duplicates(hl_only)
    assert res_hl.duplicate_group_count == 0
    assert res_hl.reclaimable_bytes == 0
    assert res_hl.hardlink_group_count == 1
    assert len(res_hl.hardlinks[0].paths) == 3
    assert res_hl.hardlinks[0].reclaimable_bytes == 0
    # Because all 3 paths share 1 inode, no hashes needed at all!
    assert res_hl.partial_hashes_computed == 0

    # 2. Mixed group: 2 distinct inodes with identical content, where inode 1 has 2 hardlinked paths
    mixed = tmp_path / "mixed"
    mixed.mkdir()
    ino1_a = mixed / "ino1_a.bin"
    ino1_b = mixed / "ino1_b.bin"
    ino2 = mixed / "ino2.bin"
    ino1_a.write_bytes(b"M" * 1024)
    os.link(ino1_a, ino1_b)
    ino2.write_bytes(b"M" * 1024)

    res_mixed = find_duplicates(mixed)
    assert res_mixed.hardlink_group_count == 1
    assert res_mixed.duplicate_group_count == 1
    # Only 2 distinct inodes exist, so reclaimable space is (2 - 1) * 1024 = 1024, NOT 2048!
    assert res_mixed.reclaimable_bytes == 1024
    assert res_mixed.duplicate_groups[0].inode_count == 2
    # And each distinct inode was hashed only once!
    assert res_mixed.partial_hashes_computed == 2


def test_duplicates_empty_files_and_min_size(tmp_path: Path) -> None:
    (tmp_path / "e1.txt").write_bytes(b"")
    (tmp_path / "e2.txt").write_bytes(b"")
    (tmp_path / "small1.txt").write_bytes(b"1234")
    (tmp_path / "small2.txt").write_bytes(b"1234")
    (tmp_path / "big1.txt").write_bytes(b"B" * 1000)
    (tmp_path / "big2.txt").write_bytes(b"B" * 1000)

    # Default: empty files skipped
    res_default = find_duplicates(tmp_path)
    assert res_default.duplicate_group_count == 2
    assert all(g.size_bytes > 0 for g in res_default.duplicate_groups)

    # With include_empty=True: empty files included
    res_empty = find_duplicates(tmp_path, include_empty=True)
    assert res_empty.duplicate_group_count == 3
    assert any(g.size_bytes == 0 for g in res_empty.duplicate_groups)

    # With min_size_bytes=500: only big1/big2 included
    res_min = find_duplicates(tmp_path, min_size_bytes=500)
    assert res_min.duplicate_group_count == 1
    assert res_min.duplicate_groups[0].size_bytes == 1000


def test_duplicates_validation(tmp_path: Path) -> None:
    with pytest.raises(UsageError):
        find_duplicates(tmp_path, min_size_bytes=-1)
    with pytest.raises(UsageError):
        find_duplicates(tmp_path, partial_kib=0)
