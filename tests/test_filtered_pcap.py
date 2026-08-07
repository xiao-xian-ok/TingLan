import utils


def test_read_pcap_passes_filter_and_disables_packet_retention(monkeypatch) -> None:
    capture_calls = []
    expected_capture = object()

    class FakeAnalysisService:
        def find_tshark(self):
            return "fake/tshark"

    def fake_file_capture(*args, **kwargs):
        capture_calls.append((args, kwargs))
        return expected_capture

    monkeypatch.setattr(utils, "AnalysisService", FakeAnalysisService)
    monkeypatch.setattr(utils.pyshark, "FileCapture", fake_file_capture)

    result = utils.read_pcap("capture.pcap", display_filter="dns")

    assert result is expected_capture
    assert len(capture_calls) == 1
    args, kwargs = capture_calls[0]
    assert args == ("capture.pcap",)
    assert kwargs["tshark_path"] == "fake/tshark"
    assert kwargs["display_filter"] == "dns"
    assert kwargs["keep_packets"] is False
