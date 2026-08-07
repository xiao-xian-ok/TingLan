import subprocess

import pytest

import services.analysis_service as analysis_service
from services.analysis_service import AnalysisService


def _service_with_tshark() -> AnalysisService:
    service = AnalysisService.__new__(AnalysisService)
    service._tshark_path = "test-tshark"
    return service


def test_http_response_metadata_does_not_request_unsupported_disposition_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(analysis_service.subprocess, "run", fake_run)

    metadata = _service_with_tshark()._get_http_response_metadata("capture.pcap")

    assert metadata == []
    assert len(calls) == 1
    assert "http.content_disposition" not in calls[0][0]


def test_http_response_metadata_ignores_output_when_tshark_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    separator = analysis_service.separator_arg().split("=", 1)[1]
    parsed_lines = []

    def fake_run(command, **kwargs):
        output = separator.join(
            [
                "17",
                "application/octet-stream",
                "4096",
                "200",
                "attachment; filename=payload.bin",
                "/payload.bin",
                "example.test",
            ]
        )
        return subprocess.CompletedProcess(command, 1, stdout=output)

    def fake_split_fields(line: str, expected: int):
        parsed_lines.append((line, expected))
        return line.split(separator)

    monkeypatch.setattr(analysis_service.subprocess, "run", fake_run)
    monkeypatch.setattr(analysis_service, "split_fields", fake_split_fields)

    metadata = _service_with_tshark()._get_http_response_metadata("capture.pcap")

    assert metadata == []
    assert parsed_lines == []


def test_extract_http_objects_skips_all_boundaries_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_boundary(*args, **kwargs):
        raise AssertionError("disabled extraction must not touch external boundaries")

    monkeypatch.setattr(analysis_service.subprocess, "run", unexpected_boundary)
    monkeypatch.setattr(analysis_service.tempfile, "mkdtemp", unexpected_boundary)
    monkeypatch.setattr(analysis_service.os.path, "exists", unexpected_boundary)

    extracted_files = _service_with_tshark().extract_http_objects(
        "capture.pcap",
        enabled=False,
    )

    assert extracted_files == []
