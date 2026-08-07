"""Locate the TShark executable used by all application entry points."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Mapping, Optional


def _executable_name(platform: str) -> str:
    return "tshark.exe" if platform == "win32" else "tshark"


def _as_executable_candidate(value, executable_name: str) -> Optional[str]:
    if value is None or value == "":
        return None

    candidate = os.fspath(value)
    if os.path.isdir(candidate):
        candidate = os.path.join(candidate, executable_name)
    return candidate


def _is_valid_executable(path: Optional[str], platform: str) -> bool:
    if not path or not os.path.isfile(path):
        return False
    return platform == "win32" or os.access(path, os.X_OK)


def _normalise(path: str) -> str:
    return os.path.abspath(os.path.normpath(os.path.expanduser(path)))


def _first_valid(candidates, platform: str) -> Optional[str]:
    for candidate in candidates:
        if _is_valid_executable(candidate, platform):
            return _normalise(candidate)
    return None


def _known_paths(platform: str, env: Mapping[str, str], executable_name: str):
    if platform == "win32":
        paths = [
            r"E:\internet_safe\wireshark\tshark.exe",
            r"E:\wireshark\tshark.exe",
            r"E:\cyber_safe\wireshark\tshark.exe",
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            r"D:\Program Files\Wireshark\tshark.exe",
            r"D:\Wireshark\tshark.exe",
        ]
        for variable in ("ProgramFiles", "ProgramFiles(x86)"):
            base = env.get(variable)
            if base:
                paths.append(os.path.join(base, "Wireshark", executable_name))
        return paths

    return [
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
        "/opt/wireshark/bin/tshark",
        "/opt/homebrew/bin/tshark",
    ]


def _path_candidates(path_value: Optional[str], executable_name: str):
    if not path_value:
        return []
    return [
        os.path.join(directory, executable_name)
        for directory in path_value.split(os.pathsep)
        if directory
    ]


def find_tshark(
    explicit_path=None,
    project_root=None,
    env: Optional[Mapping[str, str]] = None,
    platform: Optional[str] = None,
) -> Optional[str]:
    """Return the first usable TShark path, or ``None`` if none is available.

    ``explicit_path`` and ``WIRESHARK_PATH`` may point to either the executable
    itself or the directory containing it. The optional arguments keep lookup
    deterministic in tests while defaulting to the current process settings.
    """
    current_platform = platform or sys.platform
    environment = os.environ if env is None else env
    executable_name = _executable_name(current_platform)

    if explicit_path:
        return _first_valid(
            [_as_executable_candidate(explicit_path, executable_name)],
            current_platform,
        )

    env_candidate = _as_executable_candidate(
        environment.get("WIRESHARK_PATH"), executable_name
    )
    found = _first_valid([env_candidate], current_platform)
    if found:
        return found

    root = (
        Path(project_root)
        if project_root is not None
        else Path(__file__).resolve().parent.parent
    )
    vendor_candidate = root / "vendor" / "wireshark" / executable_name
    found = _first_valid([os.fspath(vendor_candidate)], current_platform)
    if found:
        return found

    path_value = environment.get("PATH")
    found_on_path = shutil.which(executable_name, path=path_value)
    found = _first_valid([found_on_path], current_platform)
    if found:
        return found

    # shutil.which uses the host platform's executable-bit rules. The fallback
    # keeps the injected platform argument deterministic on POSIX test hosts.
    found = _first_valid(_path_candidates(path_value, executable_name), current_platform)
    if found:
        return found

    return _first_valid(
        _known_paths(current_platform, environment, executable_name),
        current_platform,
    )
