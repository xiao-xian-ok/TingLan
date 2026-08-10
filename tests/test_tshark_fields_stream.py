import io

from core.tshark_fields import FIELD_SEPARATOR
from core.tshark_stream import (
    HTTP_RESPONSE_FIELDS,
    OutputFormat,
    PacketData,
    PacketParser,
    StreamConfig,
    TsharkProcessHandler,
)
import core.tshark_stream as tshark_stream


REQUEST_FIELDS = [
    "frame.number",
    "frame.time",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "frame.len",
    "tcp.stream",
    "http.request.method",
    "http.request.uri",
    "http.host",
    "http.content_type",
    "http.user_agent",
    "http.file_data",
    "http.response.code",
    "http.request_in",
]


def _fields_line(*values: str) -> str:
    return FIELD_SEPARATOR.join(values)


def test_parse_fields_line_maps_http_request_to_packet_data() -> None:
    packet = PacketParser.parse_fields_line(
        _fields_line(
            "17",
            "2026-08-06 10:15:00.000000",
            "eth:ip:tcp:http",
            "192.0.2.10",
            "198.51.100.20",
            "53124",
            "80",
            "256",
            "9",
            "POST",
            "/submit?source=test",
            "example.test",
            "application/x-www-form-urlencoded",
            "TingLanTest/1.0",
            "75:73:65:72:3d:61:6c:69:63:65",
            "",
            "",
        ),
        REQUEST_FIELDS,
    )

    assert packet is not None
    assert packet.frame_number == 17
    assert packet.timestamp == "2026-08-06 10:15:00.000000"
    assert packet.protocol == "HTTP"
    assert packet.src_ip == "192.0.2.10"
    assert packet.dst_ip == "198.51.100.20"
    assert packet.src_port == 53124
    assert packet.dst_port == 80
    assert packet.length == 256
    assert packet.tcp_stream == 9
    assert packet.http_method == "POST"
    assert packet.http_uri == "/submit?source=test"
    assert packet.http_host == "example.test"
    assert packet.http_content_type == "application/x-www-form-urlencoded"
    assert packet.http_user_agent == "TingLanTest/1.0"
    assert packet.http_request_body == b"user=alice"
    assert packet.http_response_code == ""
    assert packet.http_response_body == b""


def test_parse_fields_line_maps_response_body_and_retains_request_reference() -> None:
    response_fields = [
        "frame.number",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "http.response.code",
        "http.content_type",
        "http.file_data",
        "http.request_in",
    ]
    packet = PacketParser.parse_fields_line(
        _fields_line(
            "42",
            "198.51.100.20",
            "192.0.2.10",
            "80",
            "53124",
            "9",
            "201",
            "application/json",
            "7b:22:6f:6b:22:3a:74:72:75:65:7d",
            "17",
        ),
        response_fields,
    )

    assert packet is not None
    assert packet.frame_number == 42
    assert packet.tcp_stream == 9
    assert packet.http_response_code == "201"
    assert packet.http_content_type == "application/json"
    assert packet.http_response_body == b'{"ok":true}'
    assert packet.http_request_body == b""
    assert packet.http_request_in == "17"


def test_parse_fields_line_keeps_response_line_without_content_disposition_field() -> None:
    assert "http.content_disposition" not in HTTP_RESPONSE_FIELDS
    response_fields = [
        "frame.number",
        "http.response.line",
        "http.file_data",
    ]

    packet = PacketParser.parse_fields_line(
        _fields_line(
            "42",
            'Content-Disposition: attachment; filename="archive.zip"',
            "50:4b:03:04:61:72:63:68:69:76:65",
        ),
        response_fields,
    )

    assert packet is not None
    assert packet.http_content_disposition == ""
    assert packet.http_response_lines == [
        'Content-Disposition: attachment; filename="archive.zip"'
    ]
    assert packet.http_response_body == b"PK\x03\x04archive"


class _FinishedFieldsProcess:
    def __init__(self, line: str) -> None:
        self.stdout = io.BytesIO((line + "\n").encode("utf-8"))
        self.stderr = io.BytesIO()
        self.returncode = None
        self.pid = 1

    def poll(self):
        if self.stdout.tell() < len(self.stdout.getbuffer()):
            return None
        self.returncode = 0
        return 0


class _QuietMonitor:
    def __init__(self, _stderr) -> None:
        self.has_error = False
        self.exception = None
        self.all_errors = []

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass


def test_stream_packets_uses_fields_parser_for_fields_output(monkeypatch) -> None:
    fields = ["frame.number", "http.request.method"]
    line = _fields_line("91", "GET")
    parsed_packet = PacketData(frame_number=91, http_method="GET")
    parser_calls = []
    popen_commands = []

    def parse_fields_line(line_value: str, fields_value: list[str]):
        parser_calls.append((line_value, fields_value))
        return parsed_packet

    def fake_popen(command, **_kwargs):
        popen_commands.append(command)
        return _FinishedFieldsProcess(line)

    monkeypatch.setattr(
        PacketParser,
        "parse_fields_line",
        staticmethod(parse_fields_line),
        raising=False,
    )
    monkeypatch.setattr(tshark_stream.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(tshark_stream, "StderrMonitor", _QuietMonitor)
    monkeypatch.setattr(tshark_stream.time, "sleep", lambda _seconds: None)

    handler = TsharkProcessHandler(tshark_path="test-tshark")
    packets = list(
        handler.stream_packets(
            StreamConfig(
                pcap_path="capture.pcap",
                output_format=OutputFormat.FIELDS,
                fields=fields,
            )
        )
    )

    assert packets == [parsed_packet]
    assert parser_calls == [(line, fields)]
    assert popen_commands == [
        [
            "test-tshark",
            "-r",
            "capture.pcap",
            "-n",
            "-l",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "http.request.method",
            "-E",
            f"separator={FIELD_SEPARATOR}",
        ]
    ]


# ---------------------------------------------- 字节字段解码的形态判定
#
# tshark 的字节型字段（http.file_data 等）输出的是**冒号分隔的十六进制**。
# 原来的判据只看"长度偶数且能被 int(,16) 解析"，于是正文里的纯数字串会被
# 当成 hex 解成乱码字节，明文直接毁掉，后面的规则匹配自然什么都看不到。


def test_colon_separated_hex_is_decoded():
    assert PacketParser._decode_field_data("3c:3f:70:68:70") == b"<?php"


def test_bare_hex_with_letters_is_decoded():
    assert PacketParser._decode_field_data("3c3f706870") == b"<?php"


def test_pure_decimal_text_is_not_treated_as_hex():
    """`20250101` 既是合法 hex 也是合法正文，这种情况按正文处理"""
    assert PacketParser._decode_field_data("20250101") == b"20250101"


def test_odd_length_text_stays_text():
    assert PacketParser._decode_field_data("12345") == b"12345"


def test_plain_text_stays_text():
    assert PacketParser._decode_field_data("cmd=whoami") == b"cmd=whoami"
