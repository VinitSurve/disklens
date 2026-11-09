"""Unit, functional, and security tests for disklens cleanup."""

from __future__ import annotations

import os
import shutil
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from disklens.cleanup import (
    discover_cleanup_candidates,
    execute_cleanup,
    normalize_cleanup_category,
)
from disklens.common.exceptions import ExitCode, SafetyError, UsageError


def _snapshot_tree(root: Path) -> dict[str, tuple[str, int]]:
    """Take a complete snapshot of paths, entry kinds, and sizes under ``root``."""
    snap: dict[str, tuple[str, int]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        for name in sorted(dirnames) + sorted(filenames):
            p = dp / name
            rel = str(p.relative_to(root))
            st = p.lstat()
            kind = "symlink" if p.is_symlink() else ("dir" if p.is_dir() else "file")
            snap[rel] = (kind, int(st.st_size) if kind != "dir" else 0)
    return snap


def test_cleanup_build_outputs_require_adjacent_manifest(isolated_env: Path) -> None:
    workspace = isolated_env / "workspace"
    # 1. Project WITH manifest -> dist, __pycache__, .pytest_cache are proposed as verified
    verified_proj = workspace / "verified_app"
    verified_proj.mkdir(parents=True)
    (verified_proj / "pyproject.toml").write_text('[project]\nname = "app"\n')
    (verified_proj / "dist").mkdir()
    (verified_proj / "dist" / "pkg.whl").write_bytes(b"W" * 500)
    (verified_proj / "__pycache__").mkdir()
    (verified_proj / "__pycache__" / "mod.cpython-311.pyc").write_bytes(b"P" * 200)
    (verified_proj / ".pytest_cache").mkdir()
    (verified_proj / ".pytest_cache" / "state").write_bytes(b"S" * 100)

    # 2. Folder WITHOUT manifest -> dist, build, target, out must NOT be proposed!
    no_manifest = workspace / "random_user_folder"
    for name in ("dist", "build", "target", "out"):
        d = no_manifest / name
        d.mkdir(parents=True)
        (d / "important_user_data.txt").write_bytes(b"U" * 1000)

    plan = discover_cleanup_candidates(workspace)
    cand_paths = {c.path: c for c in plan.candidates}

    assert str(verified_proj / "dist") in cand_paths
    assert cand_paths[str(verified_proj / "dist")].confidence == "verified"
    assert str(verified_proj / "__pycache__") in cand_paths
    assert str(verified_proj / ".pytest_cache") in cand_paths

    for name in ("dist", "build", "target", "out"):
        assert str(no_manifest / name) not in cand_paths


def test_cleanup_dependencies_regenerable_and_caches_and_temp_logs(isolated_env: Path) -> None:
    root = isolated_env / "dev_area"
    # Node project with node_modules
    node_proj = root / "web"
    node_proj.mkdir(parents=True)
    (node_proj / "package.json").write_text('{"name": "web"}')
    nm = node_proj / "node_modules" / "left-pad"
    nm.mkdir(parents=True)
    (nm / "index.js").write_bytes(b"N" * 800)

    # Python venv
    py_proj = root / "api"
    py_proj.mkdir(parents=True)
    (py_proj / "requirements.txt").write_text("pytest\n")
    venv = py_proj / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "site.py").write_bytes(b"V" * 600)

    # Recognized caches (.npm/_cacache and .cache/pip)
    npm_cache = root / ".npm" / "_cacache"
    npm_cache.mkdir(parents=True)
    (npm_cache / "blob").write_bytes(b"C" * 400)

    pip_cache = root / ".cache" / "pip"
    pip_cache.mkdir(parents=True)
    (pip_cache / "http").write_bytes(b"H" * 300)

    # Temp files & logs
    (root / ".DS_Store").write_bytes(b"D" * 64)
    (root / "scratch.tmp").write_bytes(b"T" * 128)

    old_log = root / "old.log"
    old_log.write_bytes(b"L" * 256)
    forty_days_ago = time.time() - (40 * 86400)
    os.utime(old_log, (forty_days_ago, forty_days_ago))

    fresh_log = root / "fresh.log"
    fresh_log.write_bytes(b"F" * 256)

    plan = discover_cleanup_candidates(root, older_than_days=30)
    by_path = {c.path: c for c in plan.candidates}

    assert str(node_proj / "node_modules") in by_path
    assert by_path[str(node_proj / "node_modules")].status == "regenerable"
    assert by_path[str(node_proj / "node_modules")].confidence == "verified"

    assert str(py_proj / ".venv") in by_path
    assert by_path[str(py_proj / ".venv")].status == "regenerable"

    assert str(npm_cache) in by_path
    assert by_path[str(npm_cache)].confidence == "verified"
    assert str(pip_cache) in by_path
    assert by_path[str(pip_cache)].confidence == "verified"

    assert str(root / ".DS_Store") in by_path
    assert by_path[str(root / ".DS_Store")].confidence == "verified"

    assert str(root / "scratch.tmp") in by_path
    assert by_path[str(root / "scratch.tmp")].confidence == "heuristic"

    assert str(old_log) in by_path
    assert by_path[str(old_log)].confidence == "heuristic"
    assert str(fresh_log) not in by_path

    # Category filtering
    deps_only = discover_cleanup_candidates(root, category="dependencies")
    assert {c.category for c in deps_only.candidates} == {"dependencies"}


def test_cleanup_preview_and_dry_run_leave_tree_untouched(
    isolated_env: Path, run: Callable[..., Any]
) -> None:
    proj = isolated_env / "untouched_proj"
    proj.mkdir()
    (proj / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (proj / "dist").mkdir()
    (proj / "dist" / "artifact.tar.gz").write_bytes(b"A" * 512)
    (proj / "keep.py").write_text("print('keep')\n")
    (proj / "temp.tmp").write_bytes(b"T" * 64)

    before = _snapshot_tree(proj)

    res1 = run("disklens", "cleanup", str(proj))
    assert res1.exit_code == 0
    assert _snapshot_tree(proj) == before

    res2 = run("disklens", "cleanup", str(proj), "--preview")
    assert res2.exit_code == 0
    assert _snapshot_tree(proj) == before

    res3 = run("disklens", "cleanup", str(proj), "--delete", "--dry-run")
    assert res3.exit_code == 0
    assert _snapshot_tree(proj) == before


def test_cleanup_delete_requires_confirmation_and_deletes_when_confirmed(
    isolated_env: Path, run: Callable[..., Any]
) -> None:
    proj = isolated_env / "del_proj"
    proj.mkdir()
    (proj / "package.json").write_text("{}")
    (proj / "dist").mkdir()
    (proj / "dist" / "app.js").write_bytes(b"J" * 256)
    (proj / "src.js").write_text("const x = 1;\n")

    # 1. Non-interactive without --yes -> REFUSED (exit code 3), nothing deleted
    res_refused = run("disklens", "cleanup", str(proj), "--delete")
    assert res_refused.exit_code == int(ExitCode.REFUSED)
    assert (proj / "dist" / "app.js").exists()

    # 2. Interactive with "n" -> REFUSED (exit code 3), nothing deleted
    res_declined = run("disklens", "cleanup", str(proj), "--delete", input="n\n", interactive=True)
    assert res_declined.exit_code == int(ExitCode.REFUSED)
    assert (proj / "dist" / "app.js").exists()

    # 3. With --yes -> deleted, source file preserved
    res_ok = run("disklens", "cleanup", str(proj), "--delete", "--yes", "--json")
    assert res_ok.exit_code == 0
    data = res_ok.json()
    assert data["deleted_count"] == 1
    assert not (proj / "dist").exists()
    assert (proj / "src.js").exists()


def test_cleanup_refuses_protected_paths(isolated_env: Path, run: Callable[..., Any]) -> None:
    app_support = isolated_env / "Library" / "Application Support"
    app_support.mkdir(parents=True)
    ssh_dir = isolated_env / ".ssh"
    ssh_dir.mkdir(parents=True)
    keychains = isolated_env / "Library" / "Keychains"
    keychains.mkdir(parents=True)

    protected_targets = [
        Path("/System"),
        Path("/Library"),
        isolated_env,  # HOME itself
        isolated_env / "Library",
        app_support,
        ssh_dir,
        keychains,
    ]
    for target in protected_targets:
        if not target.exists():
            continue
        res = run("disklens", "cleanup", str(target))
        assert res.exit_code == int(ExitCode.REFUSED), f"Expected REFUSED for {target}"


def test_cleanup_symlink_to_outside_dir_never_deletes_outside_target(
    isolated_env: Path, run: Callable[..., Any]
) -> None:
    outside = isolated_env / "precious_outside"
    outside.mkdir()
    precious_file = outside / "do_not_delete.txt"
    precious_file.write_text("vital data")

    proj = isolated_env / "symlink_proj"
    proj.mkdir()
    (proj / "package.json").write_text("{}")

    # Case 1: Candidate itself ('node_modules') is a symlink pointing to `outside`
    nm_link = proj / "node_modules"
    nm_link.symlink_to(outside)

    # Case 2: Real candidate directory ('dist') contains a symlink pointing to `outside`
    dist = proj / "dist"
    dist.mkdir()
    (dist / "escaped_link").symlink_to(outside)

    res = run("disklens", "cleanup", str(proj), "--delete", "--yes")
    assert res.exit_code == 0

    # Both the symlink `node_modules` and `dist` are removed
    assert not nm_link.exists() and not nm_link.is_symlink()
    assert not dist.exists()

    # The outside target directory and its file MUST remain completely untouched!
    assert outside.exists()
    assert precious_file.exists()
    assert precious_file.read_text() == "vital data"


def test_cleanup_toctou_ancestor_symlink_swap_refused(isolated_env: Path) -> None:
    outside = isolated_env / "outside_target"
    (outside / "dist").mkdir(parents=True)
    victim = outside / "dist" / "keep.txt"
    victim.write_text("safe")

    root = isolated_env / "scan_root"
    sub = root / "subproj"
    sub.mkdir(parents=True)
    (sub / "package.json").write_text("{}")
    (sub / "dist").mkdir()
    (sub / "dist" / "temp.js").write_bytes(b"x" * 50)

    plan = discover_cleanup_candidates(root)
    assert len(plan.candidates) == 1

    # Simulate TOCTOU attack: replace `subproj` with a symlink to `outside` before execute_cleanup
    shutil.rmtree(sub)
    sub.symlink_to(outside)

    exec_res = execute_cleanup(plan, dry_run=False)
    assert exec_res.failed_count == 1
    assert exec_res.deleted_count == 0
    assert victim.exists()
    assert victim.read_text() == "safe"


def test_cleanup_category_validation() -> None:
    assert normalize_cleanup_category("deps") == "dependencies"
    assert normalize_cleanup_category("BUILD") == "build_artifacts"
    with pytest.raises(UsageError):
        normalize_cleanup_category("invalid_cat")
    target = Path("/System") if Path("/System").exists() else Path("/")
    with pytest.raises(SafetyError):
        discover_cleanup_candidates(target)


def test_cleanup_recognized_macos_user_caches(isolated_env: Path) -> None:
    caches_dir = isolated_env / "Library" / "Caches"
    hb = caches_dir / "Homebrew"
    hb.mkdir(parents=True)
    (hb / "Formula.json").write_bytes(b"H" * 1024)

    xcode_dd = isolated_env / "Library" / "Developer" / "Xcode" / "DerivedData"
    xcode_dd.mkdir(parents=True)
    (xcode_dd / "Build").write_bytes(b"X" * 2048)

    plan_caches = discover_cleanup_candidates(caches_dir)
    by_path = {c.path: c for c in plan_caches.candidates}
    assert str(hb) in by_path
    assert by_path[str(hb)].confidence == "verified"
    assert "Homebrew" in by_path[str(hb)].explanation


def test_cleanup_cli_flags_and_edge_cases(isolated_env: Path, run: Callable[..., Any]) -> None:
    empty_dir = isolated_env / "empty_clean"
    empty_dir.mkdir()

    # --preview and --delete together -> UsageError (exit 64)
    res_bad = run("disklens", "cleanup", str(empty_dir), "--preview", "--delete")
    assert res_bad.exit_code == int(ExitCode.USAGE)

    # Conflicting positional PATH and --path -> UsageError (exit 64)
    other_dir = isolated_env / "other"
    other_dir.mkdir()
    res_conflict = run("disklens", "cleanup", str(empty_dir), "--path", str(other_dir))
    assert res_conflict.exit_code == int(ExitCode.USAGE)

    # --path option works standalone
    res_path_opt = run("disklens", "cleanup", "--path", str(empty_dir), "--json")
    assert res_path_opt.exit_code == 0
    assert res_path_opt.json()["candidate_count"] == 0

    # --delete --yes on empty directory with 0 candidates succeeds cleanly
    res_del_empty = run("disklens", "cleanup", str(empty_dir), "--delete", "--yes", "--json")
    assert res_del_empty.exit_code == 0
    assert res_del_empty.json()["deleted_count"] == 0
