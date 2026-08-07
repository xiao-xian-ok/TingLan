from pathlib import Path

import pytest

import core.tshark_locator as tshark_locator


def _file(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="ascii")
    return path


def _assert_same_path(actual: str, expected: Path) -> None:
    assert actual is not None
    assert Path(actual).resolve() == expected.resolve()


def test_explicit_file_has_highest_priority(tmp_path: Path) -> None:
    explicit = _file(tmp_path / "explicit" / "tshark.exe")
    env_file = _file(tmp_path / "env" / "tshark.exe")
    project_root = tmp_path / "project"
    vendor = _file(project_root / "vendor" / "wireshark" / "tshark.exe")
    path_file = _file(tmp_path / "path" / "tshark.exe")

    result = tshark_locator.find_tshark(
        explicit_path=str(explicit),
        project_root=str(project_root),
        env={"WIRESHARK_PATH": str(env_file), "PATH": str(path_file.parent)},
        platform="win32",
    )

    _assert_same_path(result, explicit)


def test_wireshark_path_accepts_a_tshark_file(tmp_path: Path) -> None:
    env_file = _file(tmp_path / "custom" / "tshark.exe")
    project_root = tmp_path / "project"
    vendor = _file(project_root / "vendor" / "wireshark" / "tshark.exe")
    path_file = _file(tmp_path / "path" / "tshark.exe")

    result = tshark_locator.find_tshark(
        project_root=str(project_root),
        env={"WIRESHARK_PATH": str(env_file), "PATH": str(path_file.parent)},
        platform="win32",
    )

    _assert_same_path(result, env_file)


def test_wireshark_path_accepts_an_installation_directory(tmp_path: Path) -> None:
    install_dir = tmp_path / "wireshark"
    env_file = _file(install_dir / "tshark.exe")
    project_root = tmp_path / "project"
    vendor = _file(project_root / "vendor" / "wireshark" / "tshark.exe")
    path_file = _file(tmp_path / "path" / "tshark.exe")

    result = tshark_locator.find_tshark(
        project_root=str(project_root),
        env={"WIRESHARK_PATH": str(install_dir), "PATH": str(path_file.parent)},
        platform="win32",
    )

    _assert_same_path(result, env_file)


def test_project_vendor_tshark_precedes_path(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    vendor = _file(project_root / "vendor" / "wireshark" / "tshark.exe")
    path_file = _file(tmp_path / "path" / "tshark.exe")

    result = tshark_locator.find_tshark(
        project_root=str(project_root),
        env={"PATH": str(path_file.parent)},
        platform="win32",
    )

    _assert_same_path(result, vendor)


def test_path_tshark_is_used_when_higher_priority_candidates_are_missing(
    tmp_path: Path,
) -> None:
    path_file = _file(tmp_path / "bin" / "tshark.exe")

    result = tshark_locator.find_tshark(
        project_root=str(tmp_path / "project"),
        env={"PATH": str(path_file.parent)},
        platform="win32",
    )

    _assert_same_path(result, path_file)


def test_returns_none_without_any_candidate_independent_of_host_installation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Block filesystem and PATH probes so a developer's installed Wireshark
    # cannot affect this negative case.
    monkeypatch.setattr(tshark_locator.shutil, "which", lambda *args, **kwargs: None)
    monkeypatch.setattr(tshark_locator.os.path, "exists", lambda path: False)
    monkeypatch.setattr(tshark_locator.os.path, "isfile", lambda path: False)
    monkeypatch.setattr(tshark_locator.os, "access", lambda *args, **kwargs: False)
    monkeypatch.setattr(Path, "exists", lambda self: False)
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    monkeypatch.setattr(tshark_locator, "which", lambda *args, **kwargs: None, raising=False)

    result = tshark_locator.find_tshark(
        project_root=str(tmp_path / "project"),
        env={"PATH": ""},
        platform="win32",
    )

    assert result is None
