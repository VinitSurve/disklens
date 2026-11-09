"""Storage category classification with verified vs heuristic confidence."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Confidence = Literal["verified", "heuristic"]

CATEGORY_LABELS: dict[str, str] = {
    "dependencies": "Development dependencies",
    "build_artifacts": "Build artifacts",
    "caches": "Caches",
    "logs": "Logs",
    "temp": "Temporary files",
    "downloads": "Downloads",
    "media": "Media (image/audio/video)",
    "archives": "Archives & disk images",
    "large_project": "Large project directories",
    "other": "Other files",
}

ALL_CATEGORIES: tuple[str, ...] = tuple(CATEGORY_LABELS.keys())

PROJECT_MANIFESTS: frozenset[str] = frozenset(
    {
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        "Pipfile",
        "poetry.lock",
        "uv.lock",
        "tox.ini",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lockb",
        "tsconfig.json",
        "next.config.js",
        "next.config.mjs",
        "next.config.ts",
        "nuxt.config.js",
        "nuxt.config.ts",
        "vite.config.js",
        "vite.config.ts",
        "Cargo.toml",
        "Cargo.lock",
        "go.mod",
        "go.sum",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "gradlew",
        "Package.swift",
        "Podfile",
        "Podfile.lock",
        "Gemfile",
        "Gemfile.lock",
        "composer.json",
        "CMakeLists.txt",
        "Makefile",
        "meson.build",
    }
)

PYTHON_MANIFESTS: frozenset[str] = frozenset(
    {
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        "Pipfile",
        "poetry.lock",
        "uv.lock",
        "tox.ini",
    }
)

BUILD_ARTIFACT_DIRS: dict[str, frozenset[str]] = {
    "dist": PROJECT_MANIFESTS,
    "build": PROJECT_MANIFESTS,
    "target": frozenset(
        {
            "Cargo.toml",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "Package.swift",
            "Makefile",
            "pyproject.toml",
            "package.json",
        }
    ),
    ".next": frozenset({"package.json", "next.config.js", "next.config.mjs", "next.config.ts"}),
    ".nuxt": frozenset({"package.json", "nuxt.config.js", "nuxt.config.ts"}),
    "out": PROJECT_MANIFESTS,
    "__pycache__": PYTHON_MANIFESTS,
    ".pytest_cache": PYTHON_MANIFESTS,
    ".mypy_cache": PYTHON_MANIFESTS,
    ".ruff_cache": PYTHON_MANIFESTS,
    ".hypothesis": PYTHON_MANIFESTS,
    ".tox": PYTHON_MANIFESTS,
    ".nox": PYTHON_MANIFESTS,
    ".gradle": frozenset(
        {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradlew"}
    ),
    "DerivedData": PROJECT_MANIFESTS,
    ".turbo": frozenset({"package.json"}),
    ".parcel-cache": frozenset({"package.json"}),
    ".svelte-kit": frozenset({"package.json"}),
    ".angular": frozenset({"package.json"}),
    "htmlcov": PYTHON_MANIFESTS,
}

DEPENDENCY_DIRS: dict[str, frozenset[str]] = {
    "node_modules": frozenset(
        {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"}
    ),
    ".venv": PYTHON_MANIFESTS,
    "venv": PYTHON_MANIFESTS,
    "vendor": frozenset(
        {"go.mod", "composer.json", "Gemfile", "Cargo.toml", "package.json", "pyproject.toml"}
    ),
    "Pods": frozenset({"Podfile", "Podfile.lock", "Package.swift"}),
    "__pypackages__": PYTHON_MANIFESTS,
    "bower_components": frozenset({"package.json", "bower.json"}),
}

HEURISTIC_CACHE_DIRS: frozenset[str] = frozenset(
    {
        ".cache",
        "cache",
        "caches",
        "_cacache",
        ".eslintcache",
        ".stylelintcache",
        ".webpack",
    }
)

MEDIA_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp",
        ".svg",
        ".heic",
        ".heif",
        ".tiff",
        ".tif",
        ".bmp",
        ".ico",
        ".raw",
        ".cr2",
        ".nef",
        ".mp3",
        ".wav",
        ".flac",
        ".aac",
        ".ogg",
        ".m4a",
        ".opus",
        ".aiff",
        ".mp4",
        ".mov",
        ".mkv",
        ".avi",
        ".webm",
        ".m4v",
        ".wmv",
        ".flv",
    }
)

ARCHIVE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".tbz2",
        ".xz",
        ".txz",
        ".zst",
        ".7z",
        ".rar",
        ".dmg",
        ".iso",
        ".pkg",
        ".deb",
        ".rpm",
        ".whl",
        ".jar",
        ".war",
    }
)

BUILD_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pyc",
        ".pyo",
        ".pyd",
        ".o",
        ".obj",
        ".a",
        ".so",
        ".dylib",
        ".dll",
        ".class",
    }
)

TEMP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".tmp",
        ".temp",
        ".bak",
        ".swp",
        ".swo",
        ".part",
        ".crdownload",
    }
)

LOG_EXTENSIONS: frozenset[str] = frozenset({".log"})

EXACT_TEMP_FILENAMES: frozenset[str] = frozenset({".DS_Store", "Thumbs.db", ". localized"})


@dataclass(frozen=True)
class Classification:
    """Category and confidence assigned to a filesystem entry."""

    category: str
    confidence: Confidence
    reason: str = ""


def detect_manifests(entry_names: set[str] | frozenset[str]) -> tuple[str, ...]:
    """Return sorted project manifest filenames present in ``entry_names``."""
    found = [name for name in entry_names if name in PROJECT_MANIFESTS]
    for name in entry_names:
        if name.endswith((".xcodeproj", ".xcworkspace")) and name not in found:
            found.append(name)
    return tuple(sorted(found))


def matching_manifests_for_build_dir(
    dir_name: str,
    sibling_names: set[str] | frozenset[str],
    *,
    has_ancestor_python_manifest: bool = False,
) -> tuple[str, ...]:
    """Return adjacent manifests that verify ``dir_name`` is a build output directory."""
    expected = BUILD_ARTIFACT_DIRS.get(dir_name)
    if expected is None:
        return ()
    matched = [name for name in sibling_names if name in expected]
    if dir_name in ("DerivedData", "build", "dist", "target", "out"):
        for name in sibling_names:
            if name.endswith((".xcodeproj", ".xcworkspace")) and name not in matched:
                matched.append(name)
    if not matched and dir_name == "__pycache__":
        py_siblings = [name for name in sibling_names if name.endswith(".py")]
        if py_siblings:
            matched.append(py_siblings[0])
        elif has_ancestor_python_manifest:
            matched.append("pyproject.toml")
    return tuple(sorted(matched))


def matching_manifests_for_dep_dir(
    dir_name: str,
    sibling_names: set[str] | frozenset[str],
    *,
    dir_path: Path | None = None,
) -> tuple[str, ...]:
    """Return adjacent manifests (or internal markers like pyvenv.cfg) for a dependency dir."""
    expected = DEPENDENCY_DIRS.get(dir_name)
    if expected is None:
        return ()
    matched = [name for name in sibling_names if name in expected]
    if dir_name == "Pods":
        for name in sibling_names:
            if name.endswith((".xcodeproj", ".xcworkspace")) and name not in matched:
                matched.append(name)
    if not matched and dir_name in (".venv", "venv") and dir_path is not None:
        try:
            cfg = dir_path / "pyvenv.cfg"
            if not cfg.is_symlink() and cfg.is_file():
                matched.append("pyvenv.cfg")
        except OSError:
            pass
    return tuple(sorted(matched))


def get_known_cache_roots(home: Path | None = None) -> tuple[str, ...]:
    """Return normalized absolute path prefixes of known user cache directories."""
    user_home = Path(os.path.abspath(home or Path.home()))
    roots = (
        user_home / "Library" / "Caches",
        user_home / ".cache",
        user_home / ".npm" / "_cacache",
        user_home / "Library" / "Developer" / "Xcode" / "DerivedData",
        user_home / ".gradle" / "caches",
        user_home / ".cargo" / "registry" / "cache",
    )
    return tuple(str(p) for p in roots)


def is_verified_cache_path(path_str: str, cache_roots: tuple[str, ...]) -> bool:
    """True when ``path_str`` lies inside a known user cache root."""
    return any(path_str == root or path_str.startswith(root + os.sep) for root in cache_roots)


def is_downloads_path(path_str: str, downloads_root: str) -> bool:
    """True when ``path_str`` is inside ``~/Downloads``."""
    return path_str == downloads_root or path_str.startswith(downloads_root + os.sep)


def is_logs_root_path(path_str: str, logs_root: str) -> bool:
    """True when ``path_str`` is inside ``~/Library/Logs`` or ``/var/log``."""
    if path_str == logs_root or path_str.startswith(logs_root + os.sep):
        return True
    return path_str == "/var/log" or path_str.startswith("/var/log/")


def classify_directory(
    dir_name: str,
    dir_path_str: str,
    sibling_names: set[str] | frozenset[str],
    *,
    cache_roots: tuple[str, ...],
    downloads_root: str,
    logs_root: str,
    has_ancestor_python_manifest: bool = False,
    extra_cleanup_names: tuple[str, ...] = (),
) -> Classification | None:
    """Classify a directory if it establishes a category for itself and its subtree.

    Returns ``None`` if the directory is an ordinary folder whose files should be
    classified individually.
    """
    if is_verified_cache_path(dir_path_str, cache_roots):
        return Classification("caches", "verified", "Known user cache location")

    if dir_name in DEPENDENCY_DIRS:
        manifests = matching_manifests_for_dep_dir(
            dir_name, sibling_names, dir_path=Path(dir_path_str)
        )
        if manifests:
            return Classification(
                "dependencies",
                "verified",
                f"Dependency directory verified by {manifests[0]}",
            )
        return Classification(
            "dependencies",
            "heuristic",
            f"Directory name matches dependency pattern ({dir_name})",
        )

    if dir_name in BUILD_ARTIFACT_DIRS:
        manifests = matching_manifests_for_build_dir(
            dir_name,
            sibling_names,
            has_ancestor_python_manifest=has_ancestor_python_manifest,
        )
        if manifests:
            return Classification(
                "build_artifacts",
                "verified",
                f"Build artifact directory verified by {manifests[0]}",
            )
        return Classification(
            "build_artifacts",
            "heuristic",
            f"Directory name matches build output pattern ({dir_name})",
        )

    if dir_name.endswith(".dSYM"):
        return Classification("build_artifacts", "heuristic", "Debug symbols bundle (.dSYM)")

    if dir_name in HEURISTIC_CACHE_DIRS or dir_name.endswith("_cache"):
        return Classification("caches", "heuristic", f"Cache directory name ({dir_name})")

    if is_logs_root_path(dir_path_str, logs_root):
        return Classification("logs", "verified", "System/user logs directory")

    if dir_name in ("logs", "log"):
        return Classification("logs", "heuristic", f"Log directory name ({dir_name})")

    if extra_cleanup_names and dir_name in extra_cleanup_names:
        return Classification("temp", "heuristic", f"Configured cleanup name ({dir_name})")

    if is_downloads_path(dir_path_str, downloads_root):
        return Classification("downloads", "verified", "Located under ~/Downloads")

    return None


def classify_file(
    file_name: str,
    file_path_str: str,
    *,
    inherited: Classification | None,
    cache_roots: tuple[str, ...],
    downloads_root: str,
    logs_root: str,
    extra_cleanup_names: tuple[str, ...] = (),
) -> Classification:
    """Classify a single file, respecting any enclosing special directory classification."""
    if inherited is not None and inherited.category in (
        "dependencies",
        "build_artifacts",
        "caches",
        "logs",
    ):
        return inherited

    if is_verified_cache_path(file_path_str, cache_roots):
        return Classification("caches", "verified", "Inside known cache directory")

    if is_logs_root_path(file_path_str, logs_root):
        return Classification("logs", "verified", "Inside user/system logs directory")

    if file_name in EXACT_TEMP_FILENAMES:
        return Classification("temp", "verified", f"OS metadata file ({file_name})")

    if extra_cleanup_names and file_name in extra_cleanup_names:
        return Classification("temp", "heuristic", f"Configured cleanup name ({file_name})")

    dot_idx = file_name.rfind(".")
    ext = file_name[dot_idx:].lower() if dot_idx > 0 else ""

    if ext in TEMP_EXTENSIONS or file_name.endswith("~"):
        return Classification("temp", "heuristic", f"Temporary file extension ({ext or '~'})")

    if ext in LOG_EXTENSIONS or ".log." in file_name.lower():
        return Classification("logs", "heuristic", "Log filename pattern")

    if ext in BUILD_FILE_EXTENSIONS:
        return Classification("build_artifacts", "heuristic", f"Compiled artifact ({ext})")

    if ext in MEDIA_EXTENSIONS:
        return Classification("media", "heuristic", f"Media extension ({ext})")

    if ext in ARCHIVE_EXTENSIONS or file_name.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        return Classification("archives", "heuristic", f"Archive extension ({ext})")

    if inherited is not None and inherited.category == "downloads":
        return inherited

    if is_downloads_path(file_path_str, downloads_root):
        return Classification("downloads", "verified", "Located under ~/Downloads")

    return Classification("other", "verified", "General file")
