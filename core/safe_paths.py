"""Path hardening helpers for files extracted from untrusted captures."""

from __future__ import annotations

import os
import re
import urllib.parse
from typing import Iterator, Tuple


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")
_INVALID_WINDOWS_CHARS = re.compile(r'[<>:"/\\|?*]+')
_RESERVED_WINDOWS_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def sanitize_filename(filename: object, fallback: str = "extracted.bin", max_length: int = 180) -> str:
    """Return a basename-only filename safe to create inside an export dir."""
    raw = str(filename or "")
    raw = urllib.parse.unquote(raw, errors="replace")
    raw = raw.replace("\\", "/").split("/")[-1]
    raw = _CONTROL_CHARS.sub("_", raw)
    raw = _INVALID_WINDOWS_CHARS.sub("_", raw)
    raw = raw.strip().strip(". ")

    if not raw or raw in {".", ".."} or not any(ch.isalnum() for ch in raw):
        raw = fallback

    stem, ext = os.path.splitext(raw)
    if stem.upper() in _RESERVED_WINDOWS_NAMES:
        stem = f"_{stem}"
    raw = f"{stem}{ext}"

    if len(raw) > max_length:
        stem, ext = os.path.splitext(raw)
        keep = max(1, max_length - len(ext))
        raw = f"{stem[:keep]}{ext}"

    return raw or fallback


def ensure_child_path(base_dir: str, path: str) -> str:
    """Resolve ``path`` and require it to stay under ``base_dir``."""
    base_abs = os.path.abspath(base_dir)
    path_abs = os.path.abspath(path)
    if os.path.commonpath([base_abs, path_abs]) != base_abs:
        raise ValueError(f"unsafe extracted path outside export dir: {path}")
    return path_abs


def safe_join(base_dir: str, filename: object, fallback: str = "extracted.bin") -> Tuple[str, str]:
    """Join a sanitized filename to ``base_dir`` and verify containment."""
    safe_name = sanitize_filename(filename, fallback=fallback)
    return ensure_child_path(base_dir, os.path.join(base_dir, safe_name)), safe_name


def safe_unique_path(base_dir: str, filename: object, fallback: str = "extracted.bin") -> Tuple[str, str]:
    """Return a non-existing safe child path, appending a numeric suffix if needed."""
    candidate, safe_name = safe_join(base_dir, filename, fallback=fallback)
    if not os.path.exists(candidate):
        return candidate, safe_name

    stem, ext = os.path.splitext(safe_name)
    for idx in range(1, 10000):
        name = sanitize_filename(f"{stem}_{idx}{ext}", fallback=fallback)
        candidate = ensure_child_path(base_dir, os.path.join(base_dir, name))
        if not os.path.exists(candidate):
            return candidate, name
    raise ValueError(f"could not allocate safe extracted filename for {filename!r}")


def iter_safe_child_files(base_dir: str) -> Iterator[Tuple[str, str]]:
    """Yield regular files that are direct children of ``base_dir`` only."""
    base_abs = os.path.abspath(base_dir)
    if not os.path.isdir(base_abs):
        return
    for entry in os.scandir(base_abs):
        try:
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                continue
            path_abs = ensure_child_path(base_abs, entry.path)
            yield path_abs, sanitize_filename(entry.name)
        except OSError:
            continue
