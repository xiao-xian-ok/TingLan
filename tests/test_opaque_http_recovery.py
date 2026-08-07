import io
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

import services.analysis_service as analysis_service
from services.analysis_service import AnalysisService


FOLLOW_CANDIDATE_LIMIT = 24


def _service_with_tshark() -> AnalysisService:
    service = AnalysisService.__new__(AnalysisService)
    service._tshark_path = "test-tshark"
    return service


def _zip_body(label: str = "archive") -> bytes:
    return b"PK\x03\x04" + label.encode("ascii") + b"x" * 600


def _follow_transcript(
    stream_id: int,
    server_payload: bytes,
    uri: str = "/download/archive.zip",
) -> str:
    client_payload = f"GET {uri} HTTP/1.1\r\nHost: example.test\r\n\r\n".encode("ascii")
    return "\n".join(
        [
            "===================================================================",
            "Follow: tcp,raw",
            f"Filter: tcp.stream eq {stream_id}",
            "Node 0: 192.0.2.10:50000",
            "Node 1: 198.51.100.20:80",
            client_payload.hex(),
            "\t" + server_payload.hex(),
            "===================================================================",
        ]
    )


def _http_response(
    body: bytes,
    *,
    filename: str = "archive.zip",
    content_length: int | None = None,
) -> bytes:
    length = len(body) if content_length is None else content_length
    return (
        b"HTTP/1.1 200 OK\r\n"
        + f'Content-Disposition: attachment; filename="{filename}"\r\n'.encode("ascii")
        + f"Content-Length: {length}\r\n".encode("ascii")
        + b"Content-Type: application/zip\r\n\r\n"
        + body
    )


def _assert_default_mode_does_not_export_objects(tshark: "_OpaqueHttpTshark") -> None:
    assert all("--export-objects" not in command for command in tshark.commands)


class _EmptyCandidateProcess:
    def __init__(self, output: str = "") -> None:
        self.stdout = io.StringIO(output)
        self.stderr = io.StringIO("")
        self.returncode = 0

    def wait(self, timeout: object = None) -> int:
        return self.returncode


class _OpaqueHttpTshark:
    def __init__(
        self,
        requests: list[tuple[int, str]],
        follow_outputs: dict[int, str],
        parsed_response_streams: tuple[int, ...] = (),
        materialized_response_bodies: dict[int, bytes] | None = None,
    ) -> None:
        self.requests = requests
        self.follow_outputs = follow_outputs
        self.parsed_response_streams = parsed_response_streams
        self.materialized_response_bodies = materialized_response_bodies or {}
        self.commands: list[list[str]] = []

    @property
    def followed_streams(self) -> list[int]:
        streams = []
        for command in self.commands:
            if "-z" not in command:
                continue
            follow_argument = command[command.index("-z") + 1]
            if follow_argument.startswith("follow,tcp,raw,"):
                streams.append(int(follow_argument.rsplit(",", 1)[1]))
        return streams

    def run(self, command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if "-z" in command:
            follow_argument = command[command.index("-z") + 1]
            if follow_argument.startswith("follow,tcp,raw,"):
                stream_id = int(follow_argument.rsplit(",", 1)[1])
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=self.follow_outputs.get(stream_id, ""),
                    stderr="",
                )

        display_filter = command[command.index("-Y") + 1] if "-Y" in command else ""
        fields = [
            command[index + 1]
            for index, value in enumerate(command[:-1])
            if value == "-e"
        ]
        separator = analysis_service.separator_arg().split("=", 1)[1]

        if display_filter.startswith("http.request"):
            rows = []
            for stream_id, uri in self.requests:
                values = {
                    "tcp.stream": str(stream_id),
                    "http.request.uri": uri,
                    "http.request.full_uri": f"http://example.test{uri}",
                    "http.request.method": "GET",
                    "http.host": "example.test",
                }
                rows.append(separator.join(values.get(field, "") for field in fields))
            return subprocess.CompletedProcess(command, 0, stdout="\n".join(rows), stderr="")

        if display_filter == "http.response":
            rows = []
            for stream_id in self.parsed_response_streams:
                uri = dict(self.requests).get(stream_id, "/download/parsed.zip")
                filename = uri.split("?", 1)[0].rsplit("/", 1)[-1] or "parsed.zip"
                body = self.materialized_response_bodies.get(stream_id)
                values = {
                    "frame.number": str(1000 + stream_id),
                    "tcp.stream": str(stream_id),
                    "http.content_type": "application/zip",
                    "http.content_length": str(len(body) if body is not None else 604),
                    "http.response.code": "200",
                    "http.response.line": f'Content-Disposition: attachment; filename="{filename}"',
                    "http.request.uri": uri,
                    "http.host": "example.test",
                    "http.file_data": body.hex() if body is not None else "",
                }
                rows.append(separator.join(values.get(field, "") for field in fields))
            return subprocess.CompletedProcess(command, 0, stdout="\n".join(rows), stderr="")

        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def popen(self, command: list[str], **_: object) -> _EmptyCandidateProcess:
        self.commands.append(command)
        fields = [
            command[index + 1]
            for index, value in enumerate(command[:-1])
            if value == "-e"
        ]
        separator = analysis_service.separator_arg().split("=", 1)[1]
        rows = []
        for stream_id, body in self.materialized_response_bodies.items():
            uri = dict(self.requests).get(stream_id, "/download/parsed.zip")
            filename = uri.split("?", 1)[0].rsplit("/", 1)[-1] or "parsed.zip"
            values = {
                "frame.number": str(1000 + stream_id),
                "http.content_type": "application/zip",
                "http.content_length": str(len(body)),
                "http.response.line": f'Content-Disposition: attachment; filename="{filename}"',
                "http.file_data": body.hex(),
            }
            rows.append(separator.join(values.get(field, "") for field in fields))
        return _EmptyCandidateProcess("\n".join(rows))


def _install_tshark(
    monkeypatch: pytest.MonkeyPatch,
    tshark: _OpaqueHttpTshark,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(analysis_service.subprocess, "run", tshark.run)
    monkeypatch.setattr(analysis_service.subprocess, "Popen", tshark.popen)
    monkeypatch.setattr(analysis_service.tempfile, "mkdtemp", lambda **_: str(tmp_path))


def test_default_export_recovers_opaque_file_download_from_server_follow_stream(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    body = _zip_body()
    tshark = _OpaqueHttpTshark(
        requests=[(1807, "/archive/payload.zip")],
        follow_outputs={
            1807: _follow_transcript(
                1807,
                _http_response(body, filename="payload.zip"),
                uri="/archive/payload.zip",
            )
        },
        # The response headers are visible, but no materialized body exists.
        parsed_response_streams=(1807,),
    )
    _install_tshark(monkeypatch, tshark, tmp_path)

    extracted = _service_with_tshark().extract_http_objects("capture.pcap")

    assert tshark.followed_streams == [1807]
    _assert_default_mode_does_not_export_objects(tshark)
    assert [item.file_name for item in extracted] == ["payload.zip"]
    assert Path(extracted[0].file_path).read_bytes() == body
    assert not list(tmp_path.glob("frame_*.bin"))


def test_default_export_does_not_follow_uri_without_file_extension(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tshark = _OpaqueHttpTshark(
        requests=[(1807, "/api/data")],
        follow_outputs={1807: _follow_transcript(1807, _http_response(_zip_body()))},
    )
    _install_tshark(monkeypatch, tshark, tmp_path)

    extracted = _service_with_tshark().extract_http_objects("capture.pcap")

    assert extracted == []
    assert tshark.followed_streams == []
    _assert_default_mode_does_not_export_objects(tshark)
    assert not list(tmp_path.iterdir())


def test_default_export_does_not_materialize_opaque_static_script(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    body = b"function normal() { return 1; }" * 30
    server_payload = (
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Content-Type: application/javascript\r\n\r\n"
        + body
    )
    tshark = _OpaqueHttpTshark(
        requests=[(1807, "/static/app.js")],
        follow_outputs={1807: _follow_transcript(1807, server_payload, "/static/app.js")},
    )
    _install_tshark(monkeypatch, tshark, tmp_path)
    original_safe_path = analysis_service.safe_unique_path
    safe_path = Mock(wraps=original_safe_path)
    monkeypatch.setattr(analysis_service, "safe_unique_path", safe_path)

    extracted = _service_with_tshark().extract_http_objects("capture.pcap")

    assert extracted == []
    assert tshark.followed_streams == [1807]
    safe_path.assert_not_called()
    assert not list(tmp_path.iterdir())


def test_default_export_follows_each_opaque_file_stream_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tshark = _OpaqueHttpTshark(
        requests=[
            (1807, "/download/first.zip"),
            (1807, "/download/second.tar.gz"),
        ],
        follow_outputs={1807: _follow_transcript(1807, _http_response(_zip_body()))},
    )
    _install_tshark(monkeypatch, tshark, tmp_path)

    extracted = _service_with_tshark().extract_http_objects("capture.pcap")

    assert tshark.followed_streams == [1807]
    _assert_default_mode_does_not_export_objects(tshark)
    assert len(extracted) == 1


@pytest.mark.parametrize(
    "server_payload",
    [
        b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=payload.zip\r\n\r\n",
        _http_response(_zip_body(), content_length=len(_zip_body()) + 1),
    ],
    ids=["malformed", "incomplete-content-length"],
)
def test_default_export_drops_invalid_opaque_follow_response_without_writing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    server_payload: bytes,
) -> None:
    tshark = _OpaqueHttpTshark(
        requests=[(1807, "/download/archive.zip")],
        follow_outputs={1807: _follow_transcript(1807, server_payload)},
    )
    _install_tshark(monkeypatch, tshark, tmp_path)

    extracted = _service_with_tshark().extract_http_objects("capture.pcap")

    assert tshark.followed_streams == [1807]
    _assert_default_mode_does_not_export_objects(tshark)
    assert extracted == []
    assert not list(tmp_path.glob("frame_*.bin"))
    assert not list(tmp_path.iterdir())


def test_default_export_does_not_follow_stream_with_materialized_http_response(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parsed_body = _zip_body("parsed")
    tshark = _OpaqueHttpTshark(
        requests=[
            (1807, "/download/opaque.zip"),
            (42, "/download/parsed.zip"),
        ],
        follow_outputs={1807: _follow_transcript(1807, _http_response(_zip_body("opaque")))},
        parsed_response_streams=(42,),
        materialized_response_bodies={42: parsed_body},
    )
    _install_tshark(monkeypatch, tshark, tmp_path)

    extracted = _service_with_tshark().extract_http_objects("capture.pcap")

    assert tshark.followed_streams == [1807]
    _assert_default_mode_does_not_export_objects(tshark)
    assert {item.file_name for item in extracted} == {"archive.zip", "parsed.zip"}
    parsed = next(item for item in extracted if item.file_name == "parsed.zip")
    assert Path(parsed.file_path).read_bytes() == parsed_body
    assert not list(tmp_path.glob("frame_*.bin"))


def test_default_export_caps_opaque_follow_candidates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    requests = [
        (stream_id, f"/download/archive-{stream_id}.zip")
        for stream_id in range(1, FOLLOW_CANDIDATE_LIMIT + 2)
    ]
    follow_outputs = {
        stream_id: _follow_transcript(stream_id, b"not an HTTP response")
        for stream_id in range(1, FOLLOW_CANDIDATE_LIMIT + 2)
    }
    tshark = _OpaqueHttpTshark(
        requests=requests,
        follow_outputs=follow_outputs,
    )
    _install_tshark(monkeypatch, tshark, tmp_path)

    extracted = _service_with_tshark().extract_http_objects("capture.pcap")

    assert tshark.followed_streams == list(range(1, FOLLOW_CANDIDATE_LIMIT + 1))
    _assert_default_mode_does_not_export_objects(tshark)
    assert extracted == []
    assert not list(tmp_path.glob("frame_*.bin"))
    assert not list(tmp_path.iterdir())
