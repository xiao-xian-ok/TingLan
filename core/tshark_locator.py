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


_DEFAULT_LOOKUP_CACHE: Optional[str] = None


def clear_tshark_cache() -> None:
    """丢弃缓存的默认查找结果，下次 ``find_tshark()`` 会重新扫描。"""
    global _DEFAULT_LOOKUP_CACHE
    _DEFAULT_LOOKUP_CACHE = None


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

    无参调用（GUI 和各分析器的走法）的结果会被缓存：一次查找要跑一遍
    ``shutil.which()`` 的全 PATH 扫描加若干 ``os.stat``，实测 12ms，而它挂在
    每次点击的路径上，``protocol_analyzer`` 里还有 6 处各自独立调用 —— 全都
    在重算同一个不会变的答案。

    只缓存**成功**的结果。失败不缓存，否则用户装好 Wireshark 或设了
    ``WIRESHARK_PATH`` 之后不重启进程就永远还是"未找到"。带参调用一律不走
    缓存，否则测试注入的 ``env`` / ``platform`` 会被上一次的结果顶掉。
    """
    global _DEFAULT_LOOKUP_CACHE

    is_default_lookup = (
        explicit_path is None
        and project_root is None
        and env is None
        and platform is None
    )
    if is_default_lookup and _DEFAULT_LOOKUP_CACHE is not None:
        return _DEFAULT_LOOKUP_CACHE

    found = _locate(explicit_path, project_root, env, platform)

    if is_default_lookup and found is not None:
        _DEFAULT_LOOKUP_CACHE = found
    return found


def _locate(
    explicit_path,
    project_root,
    env: Optional[Mapping[str, str]],
    platform: Optional[str],
) -> Optional[str]:
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
