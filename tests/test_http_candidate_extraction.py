import io
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

import services.analysis_service as analysis_service
from services.analysis_service import AnalysisService


def _service_with_tshark() -> AnalysisService:
    service = AnalysisService.__new__(AnalysisService)
    service._tshark_path = "test-tshark"
    return service


def _pdf_body(label: str = "payload") -> bytes:
    return b"%PDF-1.7\n" + label.encode("ascii") + b"x" * 600


def _metadata(
    frame_number: int,
    content_type: str,
    content_length: int,
    response_line: str = "",
) -> dict:
    return {
        "frame_number": frame_number,
        "content_type": content_type,
        "content_length": content_length,
        "response_code": "200",
        "content_disposition": response_line,
        "response_line": response_line,
        "request_uri": "/download",
        "host": "example.test",
    }


def _response_row(
    frame_number: int,
    content_type: str,
    body: bytes,
    response_line: str = "",
) -> str:
    separator = analysis_service.separator_arg().split("=", 1)[1]
    return separator.join(
        [
            str(frame_number),
            content_type,
            str(len(body)),
            response_line,
            body.hex(),
        ]
    )


def _install_candidates(
    monkeypatch: pytest.MonkeyPatch,
    service: AnalysisService,
    metadata: list[dict],
    candidates: list[dict],
) -> None:
    monkeypatch.setattr(service, "_get_http_response_metadata", lambda _: metadata)
    monkeypatch.setattr(service, "_identify_real_file_downloads", lambda _: candidates)


class _LineStreamingProcess:
    def __init__(self, output: str) -> None:
        self.stdout = io.StringIO(output)
        self.stderr = io.StringIO("")
        self.returncode = 0

    def wait(self, timeout: object = None) -> int:
        return self.returncode

    def poll(self) -> int:
        return self.returncode

    def communicate(self, *_: object, **__: object) -> tuple[str, str]:
        raise AssertionError("candidate output must be consumed line by line from stdout")


def _install_streaming_tshark(
    monkeypatch: pytest.MonkeyPatch,
    response_rows: str,
) -> tuple[list[list[str]], list[list[str]], list[dict[str, object]]]:
    run_commands: list[list[str]] = []
    popen_commands: list[list[str]] = []
    popen_kwargs: list[dict[str, object]] = []

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        run_commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=response_rows, stderr="")

    def fake_popen(command: list[str], **kwargs: object) -> _LineStreamingProcess:
        popen_commands.append(command)
        popen_kwargs.append(kwargs)
        return _LineStreamingProcess(response_rows)

    monkeypatch.setattr(analysis_service.subprocess, "run", fake_run)
    monkeypatch.setattr(analysis_service.subprocess, "Popen", fake_popen)
    return run_commands, popen_commands, popen_kwargs


def _assert_one_candidate_fields_command(commands: list[list[str]]) -> list[str]:
    assert len(commands) == 1
    command = commands[0]
    assert "--export-objects" not in command
    assert command[command.index("-Y") + 1] == "http.response"
    assert command[command.index("-T") + 1] == "fields"
    assert "frame.number" in command
    assert "http.content_type" in command
    assert "http.content_length" in command
    assert "http.response.line" in command
    assert "http.file_data" in command
    assert not any("frame.number ==" in part for part in command)
    return command


def _assert_streamed_candidate_fields_command(
    run_commands: list[list[str]],
    popen_commands: list[list[str]],
    popen_kwargs: list[dict[str, object]],
) -> list[str]:
    assert not run_commands, (
        "candidate HTTP response bodies must be read from subprocess.Popen.stdout, "
        "not subprocess.run"
    )
    command = _assert_one_candidate_fields_command(popen_commands)
    assert len(popen_kwargs) == 1
    assert "timeout" not in popen_kwargs[0]
    return command


def test_default_export_uses_one_fields_stream_and_writes_only_matching_candidates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    candidate_body = _pdf_body("candidate")
    non_candidate_body = _pdf_body("not-a-candidate")
    third_body = _pdf_body("also-not-a-candidate")
    attachment = 'Content-Disposition: attachment; filename="download.pdf"'
    metadata = [
        _metadata(41, "application/pdf", len(candidate_body), attachment),
        _metadata(99, "application/pdf", len(candidate_body)),
    ]
    response_rows = "\n".join(
        [
            _response_row(41, "application/pdf", candidate_body, attachment),
            _response_row(42, "application/pdf", non_candidate_body),
            _response_row(43, "application/pdf", third_body),
        ]
    )
    service = _service_with_tshark()
    _install_candidates(monkeypatch, service, metadata, metadata)
    monkeypatch.setattr(analysis_service.tempfile, "mkdtemp", lambda **_: str(tmp_path))

    run_commands, popen_commands, popen_kwargs = _install_streaming_tshark(
        monkeypatch,
        response_rows,
    )

    extracted = service.extract_http_objects("capture.pcap")

    _assert_streamed_candidate_fields_command(
        run_commands,
        popen_commands,
        popen_kwargs,
    )
    assert len(extracted) == 1
    assert extracted[0].file_name == "download.pdf"
    assert Path(extracted[0].file_path).read_bytes() == candidate_body
    assert {path.read_bytes() for path in tmp_path.iterdir()} == {candidate_body}


def test_default_export_skips_unknown_binary_without_creating_frame_bin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    unknown_body = b"\x00\x01\x02\x03" * 200
    candidate = _metadata(51, "application/octet-stream", len(unknown_body))
    service = _service_with_tshark()
    _install_candidates(monkeypatch, service, [candidate], [candidate])
    monkeypatch.setattr(analysis_service.tempfile, "mkdtemp", lambda **_: str(tmp_path))

    def unexpected_safe_path(*_: object, **__: object) -> None:
        raise AssertionError("unknown binary must be skipped before allocating a path")

    run_commands, popen_commands, popen_kwargs = _install_streaming_tshark(
        monkeypatch,
        _response_row(51, "application/octet-stream", unknown_body),
    )
    monkeypatch.setattr(analysis_service, "safe_unique_path", unexpected_safe_path)

    extracted = service.extract_http_objects("capture.pcap")

    _assert_streamed_candidate_fields_command(
        run_commands,
        popen_commands,
        popen_kwargs,
    )
    assert extracted == []
    assert not list(tmp_path.glob("frame_*.bin"))
    assert not list(tmp_path.iterdir())


def test_default_export_skips_static_png_before_allocating_a_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    png_body = b"\x89PNG\r\n\x1a\n" + b"x" * 600
    candidate = _metadata(61, "image/png", len(png_body))
    service = _service_with_tshark()
    _install_candidates(monkeypatch, service, [candidate], [candidate])
    monkeypatch.setattr(analysis_service.tempfile, "mkdtemp", lambda **_: str(tmp_path))

    safe_path = Mock(side_effect=AssertionError("static images must be skipped before allocating a path"))

    run_commands, popen_commands, popen_kwargs = _install_streaming_tshark(
        monkeypatch,
        _response_row(61, "image/png", png_body),
    )
    monkeypatch.setattr(analysis_service, "safe_unique_path", safe_path)

    extracted = service.extract_http_objects("capture.pcap")

    _assert_streamed_candidate_fields_command(
        run_commands,
        popen_commands,
        popen_kwargs,
    )
    assert extracted == []
    safe_path.assert_not_called()
    assert not list(tmp_path.iterdir())


def test_default_export_uses_magic_extension_when_response_has_no_filename(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pdf_body = _pdf_body("magic-name")
    candidate = _metadata(77, "application/octet-stream", len(pdf_body))
    service = _service_with_tshark()
    _install_candidates(monkeypatch, service, [candidate], [candidate])
    monkeypatch.setattr(analysis_service.tempfile, "mkdtemp", lambda **_: str(tmp_path))

    run_commands, popen_commands, popen_kwargs = _install_streaming_tshark(
        monkeypatch,
        _response_row(77, "application/octet-stream", pdf_body),
    )

    extracted = service.extract_http_objects("capture.pcap")

    _assert_streamed_candidate_fields_command(
        run_commands,
        popen_commands,
        popen_kwargs,
    )
    assert len(extracted) == 1
    assert extracted[0].file_name == "frame_77.pdf"
    assert not extracted[0].file_name.endswith(".bin")
    assert extracted[0].file_type == "document"
    assert extracted[0].content_type == "application/pdf"
    assert Path(extracted[0].file_path).read_bytes() == pdf_body


def test_candidate_export_sanitizes_attachment_names_and_caps_before_writing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    attachment = 'Content-Disposition: attachment; filename="../../unsafe:name?.pdf"'
    candidates = [
        _metadata(frame, "application/pdf", len(_pdf_body(str(frame))), attachment)
        for frame in range(1, 202)
    ]
    response_rows = "\n".join(
        _response_row(
            candidate["frame_number"],
            candidate["content_type"],
            _pdf_body(str(candidate["frame_number"])),
            attachment,
        )
        for candidate in candidates
    )
    service = _service_with_tshark()
    _install_candidates(monkeypatch, service, candidates, candidates)
    monkeypatch.setattr(analysis_service.tempfile, "mkdtemp", lambda **_: str(tmp_path))

    safe_path_calls: list[tuple[object, object]] = []
    original_safe_unique_path = analysis_service.safe_unique_path

    def record_safe_unique_path(
        base_dir: object,
        filename: object,
        *args: object,
        **kwargs: object,
    ) -> tuple[str, str]:
        safe_path_calls.append((base_dir, filename))
        return original_safe_unique_path(base_dir, filename, *args, **kwargs)

    run_commands, popen_commands, popen_kwargs = _install_streaming_tshark(
        monkeypatch,
        response_rows,
    )
    monkeypatch.setattr(analysis_service, "safe_unique_path", record_safe_unique_path)

    extracted = service.extract_http_objects("capture.pcap")

    _assert_streamed_candidate_fields_command(
        run_commands,
        popen_commands,
        popen_kwargs,
    )
    assert len(safe_path_calls) == 200
    assert len(extracted) == 200
    assert len(list(tmp_path.iterdir())) == 200
    assert extracted[0].file_name == "unsafe_name_.pdf"
    assert all(path.parent == tmp_path for path in map(lambda item: Path(item.file_path), extracted))
    assert not (tmp_path.parent / "unsafe_name_.pdf").exists()


def test_default_export_skips_short_candidate_before_allocating_a_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    short_pdf = b"%PDF-1.7\n" + b"x" * 190
    attachment = 'Content-Disposition: attachment; filename="short.pdf"'
    candidate = _metadata(88, "application/pdf", len(short_pdf), attachment)
    service = _service_with_tshark()
    _install_candidates(monkeypatch, service, [candidate], [candidate])
    monkeypatch.setattr(analysis_service.tempfile, "mkdtemp", lambda **_: str(tmp_path))

    def unexpected_safe_path(*_: object, **__: object) -> None:
        raise AssertionError("short candidates must be skipped before allocating a path")

    run_commands, popen_commands, popen_kwargs = _install_streaming_tshark(
        monkeypatch,
        _response_row(88, "application/pdf", short_pdf, attachment),
    )
    monkeypatch.setattr(analysis_service, "safe_unique_path", unexpected_safe_path)

    extracted = service.extract_http_objects("capture.pcap")

    _assert_streamed_candidate_fields_command(
        run_commands,
        popen_commands,
        popen_kwargs,
    )
    assert extracted == []
    assert not list(tmp_path.iterdir())


def test_complete_export_is_opt_in(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service = _service_with_tshark()
    monkeypatch.setattr(analysis_service.tempfile, "mkdtemp", lambda **_: str(tmp_path))
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(analysis_service.subprocess, "run", fake_run)

    extracted = service.extract_http_objects("capture.pcap", complete_export=True)

    assert extracted == []
    assert any("--export-objects" in command for command in commands)
