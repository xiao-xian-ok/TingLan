from core.protocol_analyzer import TLSAnalyzer
from core.tshark_fields import separator_arg


def test_extract_tls_sessions_parses_project_field_separator(monkeypatch) -> None:
    separator = separator_arg().split("=", 1)[1]
    calls = []

    def fake_run_tshark(tshark_path, args):
        calls.append((tshark_path, list(args)))
        return separator.join(
            ["10.0.0.1", "10.0.0.2", "50123", "443", "7"]
        ) + "\n"

    monkeypatch.setattr(
        TLSAnalyzer,
        "_run_tshark",
        staticmethod(fake_run_tshark),
    )

    sessions = TLSAnalyzer().extract_tls_sessions("capture.pcap", "tshark")

    assert len(calls) == 1
    assert list(sessions) == ["7"]
    assert sessions["7"] == {
        "packets": 1,
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "sport": "50123",
        "dport": "443",
    }
