from core.protocol_analyzer import TLSAnalyzer


def test_extract_keylog_skips_follow_for_payload_without_keylog(
    monkeypatch,
    tmp_path,
) -> None:
    calls = []

    def fake_run_tshark(tshark_path, args):
        calls.append(list(args))

        if "-Y" in args and args[args.index("-Y") + 1] == "tcp.payload":
            assert "-T" in args
            assert args[args.index("-T") + 1] == "fields"
            return ""

        if "-e" in args and args[args.index("-e") + 1] == "tcp.stream":
            return "12\n34\n"

        if "-qz" in args and any(
            value.startswith("follow,tcp") for value in args
        ):
            return ""

        raise AssertionError(f"unexpected tshark arguments: {args}")

    monkeypatch.setattr(
        TLSAnalyzer,
        "_run_tshark",
        staticmethod(fake_run_tshark),
    )

    result = TLSAnalyzer().extract_keylog_from_pcap(
        "capture.pcap",
        "tshark",
        str(tmp_path),
    )

    follow_calls = [
        args
        for args in calls
        if "-qz" in args
        and any(value.startswith("follow,tcp") for value in args)
    ]

    assert result is None
    assert follow_calls == []
