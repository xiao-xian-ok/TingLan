import logging
from unittest.mock import Mock

import pytest

from core.stream_worker import StreamAnalysisWorker
from core.tshark_stream import TsharkProcessError
from services.analysis_service import AnalysisService


class FailingResponseHandler:
    def stream_packets(self, _config):
        raise TsharkProcessError("response fields stream failed")


def test_response_stream_failure_is_observable_without_legacy_object_export(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    worker = StreamAnalysisWorker(
        pcap_path="capture.pcap",
        tshark_path="test-tshark",
    )
    worker._handler = FailingResponseHandler()
    legacy_export = Mock(return_value=[])

    monkeypatch.setattr(
        AnalysisService,
        "extract_http_objects",
        legacy_export,
    )

    with caplog.at_level(logging.WARNING, logger="core.stream_worker"):
        assert worker._scan_http_responses([]) == []

    assert "HTTP response stream scan failed: response fields stream failed" in caplog.text
    legacy_export.assert_not_called()
