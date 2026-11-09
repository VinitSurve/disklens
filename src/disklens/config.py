"""Configuration schema for disklens (stored in this tool's own config directory)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from disklens.common.config import ConfigSchema, ConfigStore, Field
from disklens.common.paths import ToolPaths

SCHEMA = ConfigSchema(
    {
        "default_depth": Field(
            "int",
            2,
            "Default directory tree display depth for analyze.",
            minimum=0,
            maximum=20,
        ),
        "include_hidden": Field(
            "bool",
            True,
            "Include dotfiles and hidden directories when scanning.",
        ),
        "top_n": Field(
            "int",
            20,
            "Default number of largest files and directories to display.",
            minimum=1,
            maximum=500,
        ),
        "hash_partial_kib": Field(
            "int",
            64,
            "Partial hash prefix size in KiB for stage-1 duplicate detection.",
            minimum=4,
            maximum=4096,
        ),
        "cleanup_age_days": Field(
            "int",
            30,
            "Minimum age in days before log files are proposed for cleanup.",
            minimum=0,
            maximum=3650,
        ),
        "large_project_threshold_mb": Field(
            "int",
            100,
            "Size threshold in MB to classify a project directory as a large project.",
            minimum=1,
            maximum=100_000,
        ),
        "extra_cleanup_names": Field(
            "list",
            [],
            "Additional file or directory names to flag as heuristic cleanup candidates.",
        ),
    }
)


@dataclass(frozen=True)
class DiskLensConfig:
    """Typed view of active disklens configuration values."""

    default_depth: int = 2
    include_hidden: bool = True
    top_n: int = 20
    hash_partial_kib: int = 64
    cleanup_age_days: int = 30
    large_project_threshold_mb: int = 100
    extra_cleanup_names: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> DiskLensConfig:
        extra = data.get("extra_cleanup_names", [])
        return cls(
            default_depth=int(data.get("default_depth", 2)),
            include_hidden=bool(data.get("include_hidden", True)),
            top_n=int(data.get("top_n", 20)),
            hash_partial_kib=int(data.get("hash_partial_kib", 64)),
            cleanup_age_days=int(data.get("cleanup_age_days", 30)),
            large_project_threshold_mb=int(data.get("large_project_threshold_mb", 100)),
            extra_cleanup_names=tuple(str(item) for item in extra),
        )


def load_config(paths: ToolPaths) -> DiskLensConfig:
    """Load validated configuration from the disklens config store."""
    store = ConfigStore(paths, SCHEMA)
    return DiskLensConfig.from_mapping(store.load())
