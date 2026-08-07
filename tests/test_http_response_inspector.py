from core.http_response_inspector import (
    HttpResponseInspector,
    content_disposition_from_response_lines,
)


def test_content_disposition_parser_ignores_other_headers_and_keeps_quoted_commas() -> None:
    assert content_disposition_from_response_lines(
        ['Location: /next?filename=not-an-attachment.zip,Content-Type: text/plain']
    ) == ""
    assert content_disposition_from_response_lines(
        ['Content-Disposition: attachment; filename="report,final:1.zip",Content-Type: application/zip']
    ) == 'attachment; filename="report,final:1.zip"'


def _inspect(
    body: bytes,
    *,
    frame_number: int = 1,
    content_type: str = "text/plain",
    content_disposition: str = "",
    request_uri: str = "/download",
):
    return HttpResponseInspector().inspect(
        frame_number=frame_number,
        body=body,
        content_type=content_type,
        content_disposition=content_disposition,
        request_uri=request_uri,
    )


def test_retains_unlinked_zip_response_with_magic_type() -> None:
    result = _inspect(b"PK\x03\x04zip-data", frame_number=41)

    assert result is not None
    assert result.filename == "frame_41.zip"
    assert result.content_type == "application/zip"
    assert result.file_type == "archive"


def test_marks_zip_attachment_disguised_as_jpeg() -> None:
    result = _inspect(
        b"PK\x03\x04zip-data",
        content_disposition='attachment; filename="photo.jpg"',
    )

    assert result is not None
    assert result.filename == "photo.jpg"
    assert result.is_disguised is True


def test_retains_php_eval_body_as_suspicious_webshell() -> None:
    body = b"<?php " + b"ev" + b"al($_POST['cmd']); ?>"
    result = _inspect(body)

    assert result is not None
    assert result.filename.endswith(".php")
    assert result.content_type == "application/x-php"
    assert result.file_type == "webshell"


def test_ignores_normal_html_response() -> None:
    assert _inspect(
        b"<!doctype html><html><body>normal page</body></html>",
        content_type="text/html",
    ) is None


def test_ignores_static_png_without_download_evidence() -> None:
    assert _inspect(
        b"\x89PNG\r\n\x1a\n" + b"x" * 300,
        content_type="image/png",
        request_uri="/static/logo.png",
    ) is None


def test_retains_png_with_explicit_attachment_filename() -> None:
    result = _inspect(
        b"\x89PNG\r\n\x1a\n" + b"x" * 300,
        content_type="image/png",
        content_disposition='attachment; filename="evidence.png"',
        request_uri="/download/evidence.png",
    )

    assert result is not None
    assert result.filename == "evidence.png"
    assert result.file_type == "image"


def test_ignores_normal_javascript_without_download_evidence() -> None:
    assert _inspect(
        b"function normal() { return 1; }" * 20,
        content_type="application/javascript",
        request_uri="/static/app.js",
    ) is None


def test_ignores_weakly_obfuscated_javascript_without_download_evidence() -> None:
    assert _inspect(
        b"eval(unescape('%41'));" * 20,
        content_type="application/javascript",
        request_uri="",
    ) is None


def test_retains_active_x_script_as_high_confidence_malware() -> None:
    result = _inspect(
        b"var shell = new ActiveXObject('WScript.Shell'); shell.Run('cmd.exe');",
        content_type="application/javascript",
    )

    assert result is not None
    assert result.filename == "frame_1.vbs"
    assert result.file_type == "script"


def test_retains_file_like_request_uri_without_attachment_or_magic() -> None:
    result = _inspect(
        b"plain script content",
        request_uri="/uploads/tool.php?download=1",
    )

    assert result is not None
    assert result.filename == "tool.php"
    assert result.file_type == "script"


def test_decodes_utf8_extended_attachment_filename() -> None:
    result = _inspect(
        b"PK\x03\x04zip-data",
        content_disposition="attachment; filename*=UTF-8''report%20%E4%B8%AD%E6%96%87.zip",
    )

    assert result is not None
    assert result.filename == "report 中文.zip"
