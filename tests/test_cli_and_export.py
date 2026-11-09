"""CLI, report, export, config, and subprocess end-to-end tests for disklens."""

from __future__ import annotations

import csv
import io
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from disklens.common.exceptions import ExitCode


def test_cli_default_and_info(isolated_env: Path, run: Callable[..., Any]) -> None:
    res_default = run("disklens", cwd=isolated_env)
    assert res_default.exit_code == 0
    assert "Overview" in res_default.stdout

    res_json = run("disklens", "info", str(isolated_env), "--json")
    assert res_json.exit_code == 0
    data = res_json.json()
    assert data["target_path"] == str(isolated_env)
    assert data["primary"]["total_bytes"] > 0


def test_cli_analyze_and_largest_and_duplicates(
    isolated_env: Path, run: Callable[..., Any]
) -> None:
    proj = isolated_env / "sample"
    proj.mkdir()
    (proj / "package.json").write_text('{"name": "sample"}')
    (proj / "node_modules").mkdir()
    (proj / "node_modules" / "lib.js").write_bytes(b"J" * 4000)
    (proj / "dup1.bin").write_bytes(b"D" * 2048)
    (proj / "dup2.bin").write_bytes(b"D" * 2048)

    # Analyze human & JSON & quiet
    res_an = run("disklens", "analyze", str(proj), "--depth", "2")
    assert res_an.exit_code == 0
    assert "Storage Analysis Summary" in res_an.stdout

    res_an_q = run("disklens", "analyze", str(proj), "--quiet")
    assert res_an_q.exit_code == 0
    assert "D I S K L E N S" not in res_an_q.stdout

    res_an_json = run("disklens", "analyze", str(proj), "--json")
    assert res_an_json.exit_code == 0
    an_data = res_an_json.json()
    assert an_data["file_count"] == 4
    assert an_data["total_bytes"] >= 4000 + 4096

    # Largest
    res_lg = run("disklens", "largest", str(proj), "--limit", "2", "--min-size", "1KB", "--json")
    assert res_lg.exit_code == 0
    lg_data = res_lg.json()
    assert lg_data["count"] == 2
    assert lg_data["files"][0]["size_bytes"] == 4000

    # Duplicates
    res_dup = run("disklens", "duplicates", str(proj), "--min-size", "1KB", "--json")
    assert res_dup.exit_code == 0
    dup_data = res_dup.json()
    assert dup_data["duplicate_group_count"] == 1
    assert dup_data["reclaimable_bytes"] == 2048


def test_cli_unreadable_summary_message(isolated_env: Path, run: Callable[..., Any]) -> None:
    root = isolated_env / "unread_cli"
    secret = root / "locked"
    secret.mkdir(parents=True)
    (root / "ok.txt").write_bytes(b"abc")
    secret.chmod(0o000)
    try:
        if os.access(secret, os.R_OK):
            return
        res = run("disklens", "analyze", str(root))
        assert res.exit_code == 0
        assert "1 paths unreadable" in res.output
    finally:
        secret.chmod(0o755)


def test_cli_export_csv_properly_quotes_commas_quotes_newlines_unicode(
    isolated_env: Path, run: Callable[..., Any]
) -> None:
    root = isolated_env / "csv_weird"
    root.mkdir()
    tricky_names = [
        "file, with, commas.txt",
        'file "with" quotes.log',
        "file\nwith\nnewline.tmp",
        "Café_🚀_日本語.mp4",
    ]
    created_paths: set[str] = set()
    for name in tricky_names:
        p = root / name
        try:
            p.write_bytes(b"X" * 123)
            created_paths.add(str(p))
        except OSError:
            # In case a platform rejects newline in filenames
            continue

    res_csv = run("disklens", "export", str(root), "--format", "csv")
    assert res_csv.exit_code == 0

    reader = csv.DictReader(io.StringIO(res_csv.stdout))
    assert reader.fieldnames == ["path", "size_bytes", "type", "category", "confidence"]
    rows = list(reader)
    exported_paths = {r["path"] for r in rows}
    for cp in created_paths:
        assert cp in exported_paths

    for r in rows:
        assert r["type"] in ("file", "dir", "symlink", "special")
        assert r["confidence"] in ("verified", "heuristic")
        assert int(r["size_bytes"]) >= 0


def test_cli_export_and_report_output_file_and_overwrite_protection(
    isolated_env: Path, run: Callable[..., Any]
) -> None:
    src = isolated_env / "src_tree"
    src.mkdir()
    (src / "data.bin").write_bytes(b"Z" * 512)

    out_csv = isolated_env / "out.csv"
    res1 = run("disklens", "export", str(src), "--format", "csv", "--output", str(out_csv))
    assert res1.exit_code == 0
    assert out_csv.exists()

    # Without --force, overwriting existing file is refused (ExitCode.REFUSED = 3)
    res_refuse = run("disklens", "export", str(src), "--format", "csv", "--output", str(out_csv))
    assert res_refuse.exit_code == int(ExitCode.REFUSED)

    # With --force, overwrite succeeds
    res_force = run(
        "disklens", "export", str(src), "--format", "json", "--output", str(out_csv), "--force"
    )
    assert res_force.exit_code == 0
    parsed = json.loads(out_csv.read_text(encoding="utf-8"))
    assert parsed["root"] == str(src)

    # Report command (human, JSON, and --output)
    out_rep = isolated_env / "report.md"
    res_rep = run("disklens", "report", str(src), "--output", str(out_rep))
    assert res_rep.exit_code == 0
    assert "# DiskLens Report" in out_rep.read_text(encoding="utf-8")

    # Refuses overwrite without --force
    assert run("disklens", "report", str(src), "--output", str(out_rep)).exit_code == int(
        ExitCode.REFUSED
    )

    res_rep_json = run("disklens", "report", str(src), "--json")
    assert res_rep_json.exit_code == 0
    rep_doc = res_rep_json.json()
    assert rep_doc["root"] == str(src)
    assert "scan" in rep_doc and "volume" in rep_doc


def test_cli_config_commands(isolated_env: Path, run: Callable[..., Any]) -> None:
    res_show = run("disklens", "config", "--json")
    assert res_show.exit_code == 0
    assert res_show.json()["values"]["default_depth"] == 2

    assert run("disklens", "config", "set", "default_depth", "4").exit_code == 0
    assert run("disklens", "config", "get", "default_depth").stdout.strip() == "4"

    assert (
        run("disklens", "config", "set", "extra_cleanup_names", ". parcel, .custom_tmp").exit_code
        == 0
    )
    assert run("disklens", "config", "reset", "--yes").exit_code == 0
    assert run("disklens", "config", "get", "default_depth").stdout.strip() == "2"


def test_cli_subprocess_end_to_end(isolated_env: Path, run_proc: Callable[..., Any]) -> None:
    work = isolated_env / "e2e"
    work.mkdir()
    (work / "a.txt").write_bytes(b"hello world" * 100)
    (work / "b.txt").write_bytes(b"hello world" * 100)

    proc_an = run_proc("disklens", "analyze", str(work), "--json")
    assert proc_an.exit_code == 0
    assert proc_an.json()["file_count"] == 2

    proc_dup = run_proc("disklens", "duplicates", str(work), "--json")
    assert proc_dup.exit_code == 0
    assert proc_dup.json()["duplicate_group_count"] == 1


def test_cli_export_stdout_json_and_invalid_format_and_interrupt(
    isolated_env: Path, run: Callable[..., Any], monkeypatch: Any
) -> None:
    src = isolated_env / "exp_src"
    src.mkdir()
    (src / "item.txt").write_bytes(b"123456")

    # Export JSON directly to stdout
    res_json_out = run("disklens", "export", str(src), "--format", "json")
    assert res_json_out.exit_code == 0
    doc = res_json_out.json()
    assert doc["root"] == str(src)
    assert len(doc["records"]) >= 2

    # Export CSV with global --json flag
    res_csv_json = run("disklens", "export", str(src), "--format", "csv", "--json")
    assert res_csv_json.exit_code == 0
    assert res_csv_json.json()["format"] == "csv"

    # Invalid export format -> UsageError (exit 64)
    res_bad_fmt = run("disklens", "export", str(src), "--format", "xml")
    assert res_bad_fmt.exit_code == int(ExitCode.USAGE)

    # Report output to .json file
    out_json_report = isolated_env / "rep.json"
    res_rep_f = run("disklens", "report", str(src), "--output", str(out_json_report))
    assert res_rep_f.exit_code == 0
    assert json.loads(out_json_report.read_text(encoding="utf-8"))["root"] == str(src)

    # Ctrl-C cancellation handling -> ExitCode.INTERRUPTED (130)
    def _boom(*_args: object, **_kwargs: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr("disklens.cli.scan_directory", _boom)
    res_int = run("disklens", "analyze", str(src))
    assert res_int.exit_code == int(ExitCode.INTERRUPTED)
