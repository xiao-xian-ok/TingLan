import base64
import gzip
import hashlib
import hmac
import zlib
from dataclasses import dataclass
from urllib.parse import quote

import pytest

from core.ast_engine import PHPASTEngine
from core.auto_decoder import (
    DecodingMethod,
    DecodingResult,
    DecodingStep,
    MagicDecoder,
)
from core.attack_detector import detect_attack
from core.display_safety import (
    LOSSY_TEXT_NOTICE,
    format_binary_as_hex,
    is_binary_or_corrupt_text,
    safe_display_text,
)
from core.safe_paths import (
    ensure_child_path,
    iter_safe_child_files,
    safe_unique_path,
    sanitize_filename,
)
from core.http_reassembly import (
    decode_http_body_bytes,
    decode_http_body_text,
    format_http_body_for_display,
    reconstruct_http_response_from_fields,
    reconstruct_http_response_from_text_dump,
)
from core.protocol_analyzer import CobaltStrikeAnalyzer
from core.CS_analyzer import decrypt_traffic as decrypt_cs_traffic
from core.protocol_display import format_protocol_raw_values
from core.tshark_stream import PacketParser
from core.tshark_fields import FIELD_SEPARATOR, parse_quoted_fields, split_fields


def test_safe_paths_sanitize_traversal_and_reserved_names(tmp_path):
    assert sanitize_filename("../..\\webshell.php") == "webshell.php"
    assert sanitize_filename("%2e%2e/%2e%2e/flag.txt") == "flag.txt"
    assert sanitize_filename("CON") == "_CON"
    assert sanitize_filename("\x00\x1f..") == "extracted.bin"

    with pytest.raises(ValueError):
        ensure_child_path(str(tmp_path), str(tmp_path.parent / "escape.bin"))


def test_safe_unique_path_and_iter_safe_child_files_stay_in_export_dir(tmp_path):
    first_path, first_name = safe_unique_path(str(tmp_path), "../payload.bin")
    assert first_name == "payload.bin"
    assert first_path.startswith(str(tmp_path))

    with open(first_path, "wb") as handle:
        handle.write(b"one")

    second_path, second_name = safe_unique_path(str(tmp_path), "../payload.bin")
    assert second_name == "payload_1.bin"
    assert second_path.startswith(str(tmp_path))

    with open(second_path, "wb") as handle:
        handle.write(b"two")

    (tmp_path / "nested").mkdir()
    with open(tmp_path / "nested" / "ignored.bin", "wb") as handle:
        handle.write(b"nested")

    exported = dict(iter_safe_child_files(str(tmp_path)))
    assert set(exported.values()) == {"payload.bin", "payload_1.bin"}


def test_tshark_field_separator_preserves_payload_delimiters():
    payload = "a,b\tc|d|||e"
    line = FIELD_SEPARATOR.join(["10.0.0.1", payload, "200"])

    assert split_fields(line, expected=3) == ["10.0.0.1", payload, "200"]
    assert split_fields("only-one", expected=3) == ["only-one", "", ""]


def test_tshark_quoted_field_parser_handles_complex_payload():
    payload = 'comma,tab\tpipe|quote"inside'
    escaped_payload = payload.replace('"', '""')
    line = FIELD_SEPARATOR.join(["1", f'"{escaped_payload}"', "3"])

    assert parse_quoted_fields(line, expected=3) == ["1", payload, "3"]


class _FakeHttpLayer:
    def __init__(self, **fields):
        self._data = fields


def test_http_reassembly_decodes_colon_separated_chunk_data():
    layer = _FakeHttpLayer(
        **{
            "response-version": "HTTP/1.1",
            "response-code": "200",
            "chunk-data": "0a:0a:0a:3c:21:44:4f:43:54:59:50:45:20:68:74:6d:6c:3e",
        }
    )

    assert decode_http_body_bytes(layer).startswith(b"\n\n\n<!DOCTYPE html>")
    assert decode_http_body_text(layer).startswith("\n\n\n<!DOCTYPE html>")


def test_http_reassembly_concatenates_multiple_chunk_fields():
    layer = _FakeHttpLayer(
        http_http_chunk_data=[
            "3c:68:74:6d:6c:3e",
            "3c:62:6f:64:79:3e",
            "54:6f:6d:63:61:74",
        ]
    )

    assert decode_http_body_text(layer) == "<html><body>Tomcat"


def test_http_reassembly_decodes_gzip_content_encoding():
    html = b"<!DOCTYPE html>\n<html><body>Tomcat Native</body></html>"
    layer = _FakeHttpLayer(
        **{
            "content-encoding": "gzip",
            "content-type": "text/html; charset=UTF-8",
            "chunk-data": gzip.compress(html).hex(":"),
        }
    )

    assert decode_http_body_bytes(layer) != html
    assert decode_http_body_text(layer) == html.decode("utf-8")


def test_http_reassembly_sniffs_gzip_when_header_is_missing():
    body = b"hidden gzip response body"
    layer = _FakeHttpLayer(**{"chunk-data": gzip.compress(body).hex(":")})

    assert decode_http_body_text(layer) == "hidden gzip response body"


def test_http_reassembly_decodes_zlib_and_raw_deflate_content():
    body = b"deflate response body"
    zlib_layer = _FakeHttpLayer(
        **{
            "content-encoding": "deflate",
            "chunk-data": zlib.compress(body).hex(":"),
        }
    )
    raw_layer = _FakeHttpLayer(
        **{
            "content-encoding": "deflate",
            "chunk-data": zlib.compress(body)[2:-4].hex(":"),
        }
    )

    assert decode_http_body_text(zlib_layer) == "deflate response body"
    assert decode_http_body_text(raw_layer) == "deflate response body"


def test_http_reassembly_does_not_force_binary_garbage_to_text():
    binary_body = b"\x00\x01\x02\x03\xff\xfe\xfd" * 20
    layer = _FakeHttpLayer(**{"chunk-data": binary_body.hex(":")})

    assert decode_http_body_text(layer) == ""
    assert "\ufffd" in decode_http_body_text(layer, allow_binary_text=True)


def test_display_safety_hides_lossy_decoded_binary_text():
    garbled = "��S1kM`�J�8����`�i�R��5�$�H)g�yW�(�fKgj��A��y�%`���K"

    assert is_binary_or_corrupt_text(garbled) is True
    assert safe_display_text(garbled) == LOSSY_TEXT_NOTICE


def test_display_safety_handles_short_lossy_binary_fragments():
    assert is_binary_or_corrupt_text("�3�") is True
    assert format_binary_as_hex("�3�") == LOSSY_TEXT_NOTICE


def test_display_safety_keeps_legitimate_unicode_text_readable():
    text = "检测结果：Tomcat 响应体已成功还原\n<html>OK</html>"

    assert is_binary_or_corrupt_text(text) is False
    assert safe_display_text(text) == text


def test_cobaltstrike_cookie_extraction_parses_cookie_values_not_whole_header():
    metadata_ciphertext = base64.b64encode(b"A" * 128).decode("ascii")
    cookie_header = f"JSESSIONID=normal-value; __cfduid={metadata_ciphertext}; theme=light"

    candidates = CobaltStrikeAnalyzer.extract_metadata_cookie_candidates(cookie_header)

    assert len(candidates) == 1
    assert candidates[0]["cookie"] == metadata_ciphertext
    assert candidates[0]["source"] == "__cfduid"
    assert candidates[0]["decoded_length"] == 128
    assert candidates[0]["confidence"] >= 0.8


def test_cobaltstrike_cookie_extraction_normalizes_url_encoded_base64():
    metadata_ciphertext = base64.b64encode(b"\xfb" * 128).decode("ascii")
    cookie_header = f"metadata={quote(metadata_ciphertext, safe='')}"

    candidates = CobaltStrikeAnalyzer.extract_metadata_cookie_candidates(cookie_header)

    assert len(candidates) == 1
    assert candidates[0]["cookie"] == metadata_ciphertext
    assert candidates[0]["raw_cookie"] != metadata_ciphertext
    assert CobaltStrikeAnalyzer._decode_base64_cookie_value(candidates[0]["cookie"]) == b"\xfb" * 128


def test_cobaltstrike_cookie_extraction_rejects_short_or_non_base64_values():
    cookie_header = "short=abcd; tracking=not-a-valid-base64-token; id=12345"

    assert CobaltStrikeAnalyzer.extract_metadata_cookie_candidates(cookie_header) == []


def _build_cs_encrypted_blob(aes_key: bytes, hmac_key: bytes, raw_content: bytes, task_type: int = 1) -> str:
    AES = pytest.importorskip("Crypto.Cipher.AES")

    payload = task_type.to_bytes(4, "big") + raw_content
    plain = (7).to_bytes(4, "big") + len(payload).to_bytes(4, "big") + payload
    plain += b"\x00" * ((16 - len(plain) % 16) % 16)
    encrypted = AES.new(aes_key, AES.MODE_CBC, b"abcdefghijklmnop").encrypt(plain)
    signature = hmac.new(hmac_key, encrypted, hashlib.sha256).digest()[:16]
    framed = (len(encrypted) + 16).to_bytes(4, "big") + encrypted + signature
    return framed.hex()


def test_cobaltstrike_decrypt_traffic_preserves_text_content():
    aes_key = b"0123456789abcdef"
    hmac_key = b"fedcba9876543210fedcba9876543210"
    blob = _build_cs_encrypted_blob(aes_key, hmac_key, b"whoami\n")

    result = decrypt_cs_traffic(blob, aes_key, hmac_key)

    assert result["hmac_ok"] is True
    assert result["counter"] == 7
    assert result["task_type"] == 1
    assert result["text_content"] == "whoami\n"
    assert result["content_is_binary"] is False


def test_cobaltstrike_decrypt_traffic_renders_binary_as_hex_not_garbage():
    aes_key = b"0123456789abcdef"
    hmac_key = b"fedcba9876543210fedcba9876543210"
    blob = _build_cs_encrypted_blob(aes_key, hmac_key, b"\x00\x01\x02\xff\xfe\xfd" * 12)

    result = decrypt_cs_traffic(blob, aes_key.hex(), hmac_key.hex())

    assert result["hmac_ok"] is True
    assert result["content_is_binary"] is True
    assert result["text_content"] == ""
    assert "0000" in result["display_content"]
    assert "\ufffd" not in result["display_content"]


def _build_cs_like_http_body() -> bytes:
    encrypted = (bytes(range(256)) * 3)[:752]
    signature = bytes(reversed(range(16)))
    declared_length = len(encrypted) + len(signature)
    return declared_length.to_bytes(4, "big") + encrypted + signature


def test_cobaltstrike_detects_length_prefixed_encrypted_http_body():
    body = _build_cs_like_http_body()

    candidate = CobaltStrikeAnalyzer.detect_encrypted_http_payload(
        body,
        method="POST",
        content_type="application/octet-stream",
        uri="/submit.php?id=1603726794",
    )

    assert candidate is not None
    assert candidate["declared_length"] == 768
    assert candidate["encrypted_length"] == 752
    assert candidate["entropy"] >= 7.0


def test_binary_cs_http_body_is_not_misclassified_as_rce_or_sqli():
    body = _build_cs_like_http_body()

    result = detect_attack(
        body,
        method="POST",
        uri="/submit.php?id=1603726794",
        content_type="application/octet-stream",
    )

    assert result["detected"] is False
    assert result["detection_type"] == "unknown"
    assert result["text_detection_skipped"] is True
    assert result["is_binary_payload"] is True
    assert result["protocol_hint"] == "cobalt_strike_encrypted_http"
    assert not any(ind["name"].startswith(("rce:", "sqli:")) for ind in result["indicators"])


def test_protocol_display_formats_structured_cs_raw_values_without_crashing():
    raw_values = [
        {
            "kind": "encrypted_http_body",
            "frame_number": 70737,
            "tcp_stream": 394,
            "method": "POST",
            "uri": "/submit.php?id=1603726794",
            "declared_length": 768,
            "encrypted_length": 752,
            "hmac_length": 16,
            "entropy": 7.73,
            "content_type": "application/octet-stream",
        },
        {
            "cookie": "A" * 180,
            "source": "__cfduid",
            "decoded_length": 128,
            "confidence": 0.85,
        },
    ]

    lines = format_protocol_raw_values(raw_values)
    rendered = "\n".join(lines)

    assert "结构化原始值" in rendered
    assert "Encrypted HTTP Body" in rendered
    assert "Metadata Cookie" in rendered
    assert "dict.__format__" not in rendered


def test_protocol_display_limits_large_raw_values_to_prevent_ui_freeze():
    lines = format_protocol_raw_values([{"idx": i, "value": "x" * 200} for i in range(2000)], max_items=50)
    rendered = "\n".join(lines)

    assert "仅显示前 50 项" in rendered
    assert len(rendered) < 30000


def test_http_response_reconstruction_from_burp_style_fields():
    restored = reconstruct_http_response_from_fields(
        {
            "response-version": "HTTP/1.1",
            "response-code": "200",
            "content-type": "text/html; charset=UTF-8",
            "chunk-data": "3c:21:44:4f:43:54:59:50:45:20:68:74:6d:6c:3e",
        }
    )

    assert restored.startswith("HTTP/1.1 200")
    assert "Content-Type: text/html; charset=UTF-8" in restored
    assert "<!DOCTYPE html>" in restored


def test_http_response_reconstruction_decodes_compressed_field_dump():
    html = b"<html><body><h1>Tomcat Connectors</h1></body></html>"
    dump = "\n".join([
        "HTTP Response",
        "HTTP/1.1 200 OK",
        "content-type: text/html; charset=UTF-8",
        "content-encoding: gzip",
        f"chunk-data: {gzip.compress(html).hex(':')}",
    ])

    restored = reconstruct_http_response_from_text_dump(dump)

    assert "Content-Encoding: gzip" in restored
    assert "Tomcat Connectors" in restored
    assert "\ufffd" not in restored


def test_http_response_reconstruction_from_wireshark_field_dump_text():
    dump = "\n".join([
        "HTTP Response",
        "HTTP/1.1 200",
        "time: 0.002177000",
        "response-code-desc: OK",
        "request-in: 132430",
        "chunk-boundary: 0d:0a",
        "transfer-encoding: chunked",
        "date: Sat, 22 Feb 2025 07:47:13 GMT",
        "response-number: 1",
        "response-version: HTTP/1.1",
        "chunk-data: 0a:0a:0a:3c:21:44:4f:43:54:59:50:45:20:68:74:6d:6c:3e:0a:3c:68:74:6d:6c:3e:3c:62:6f:64:79:3e:54:6f:6d:63:61:74:3c:2f:62:6f:64:79:3e:3c:2f:68:74:6d:6c:3e",
    ])

    restored = reconstruct_http_response_from_text_dump(dump)

    assert restored.startswith("HTTP/1.1 200 OK")
    assert "Transfer-Encoding: chunked" in restored
    assert "Date: Sat, 22 Feb 2025 07:47:13 GMT" in restored
    assert "chunk-data:" not in restored
    assert "<!DOCTYPE html>" in restored
    assert "\n<html>" in restored
    assert "\n  <body>" in restored


def test_http_display_restores_visible_newline_and_tab_escapes():
    display = format_http_body_for_display("\\n\\t<!DOCTYPE html>\\n<html><body>OK</body></html>")

    assert "\\n" not in display
    assert display.startswith("<!DOCTYPE html>\n<html>")
    assert "\n  <body>" in display


def test_http_display_pretty_prints_minified_html():
    display = format_http_body_for_display("<html><body><h1>Tomcat</h1></body></html>", "text/html")

    assert display.splitlines() == [
        "<html>",
        "  <body>",
        "    <h1>",
        "      Tomcat",
        "    </h1>",
        "  </body>",
        "</html>",
    ]


def test_tshark_ek_parser_uses_chunk_data_when_file_data_is_absent():
    line = (
        '{"layers":{"frame":{"frame_frame_number":["7"],"frame_frame_len":["128"],'
        '"frame_frame_protocols":["eth:ip:tcp:http"]},'
        '"ip":{"ip_ip_src":["10.0.0.2"],"ip_ip_dst":["10.0.0.1"]},'
        '"tcp":{"tcp_tcp_srcport":["8080"],"tcp_tcp_dstport":["50000"],"tcp_tcp_stream":["3"]},'
        '"http":{"http_http_response_code":["200"],'
        '"http_http_chunk_data":["3c:68:31:3e:4f:4b:3c:2f:68:31:3e"]}}}'
    )

    packet = PacketParser.parse_ek_line(line)

    assert packet is not None
    assert packet.http_response_body == b"<h1>OK</h1>"


def test_php_ast_detects_direct_tainted_sink():
    code = '<?php $cmd = $_POST["cmd"]; system($cmd); ?>'
    result = PHPASTEngine().analyze(code)

    assert result.is_likely_webshell is True
    assert any(call.function_name == "system" and call.is_tainted for call in result.dangerous_calls)
    assert any(finding.type == "tainted_sink" for finding in result.findings)


def test_php_ast_detects_taint_through_decoder_chain():
    code = "<?php $x = base64_decode($_REQUEST['p']); eval($x); ?>"
    result = PHPASTEngine().analyze(code)

    assert result.is_likely_webshell is True
    assert any(call.function_name == "eval" and call.is_tainted for call in result.dangerous_calls)


def test_php_ast_reduces_weight_for_untainted_dangerous_call():
    code = '<?php system("id"); ?>'
    engine = PHPASTEngine()
    result = engine.analyze(code)
    confirmed, adjusted_weight, reason = engine.validate_detection(
        code,
        regex_indicators=[{"name": "system"}],
        regex_weight=80,
    )

    assert result.dangerous_calls
    assert not any(call.is_tainted for call in result.dangerous_calls)
    assert result.is_likely_webshell is False
    assert confirmed is False
    assert adjusted_weight <= 40
    assert reason == "no_taint_propagation"


def test_php_ast_detects_dynamic_function_name_with_tainted_argument():
    code = "<?php $f = 'sys'.'tem'; $arg = $_GET['x']; $f($arg); ?>"
    result = PHPASTEngine().analyze(code)

    assert result.is_likely_webshell is True
    assert any(call.resolved_name == "system" and call.is_tainted for call in result.dangerous_calls)
    assert any(finding.type == "obfuscated_dangerous_call" for finding in result.findings)


def test_php_ast_handles_malformed_and_extreme_input_without_crashing():
    engine = PHPASTEngine()
    malformed = "<?php $x = ((( $_POST['a']; eval($x"
    oversized_literal = "<?php $x = '" + ("A" * 10000) + "'; ?>"

    malformed_result = engine.analyze(malformed)
    oversized_result = engine.analyze(oversized_literal)

    assert malformed_result is not None
    assert oversized_result is not None
    assert oversized_result.is_likely_webshell is False


def test_magic_decoder_decodes_multilayer_payload_without_cyberchef():
    plaintext = b"flag{multi_layer_decoder_ok}"
    encoded = base64.b64encode(plaintext.hex().encode("ascii"))

    result = MagicDecoder(bridge=None).decode(encoded, crib=r"flag\{[^}]+\}")

    assert "flag{multi_layer_decoder_ok}" in result.final_text
    assert result.total_layers >= 2
    assert result.flags_found == ["flag{multi_layer_decoder_ok}"]


@dataclass
class _FakeCyberChefCandidate:
    data: str
    recipe: list
    entropy: float = 3.0
    is_utf8: bool = True
    total_layers: int = 1
    decode_chain: str = "From Base64"


@dataclass
class _FakeCyberChefResponse:
    ok: bool
    results: list
    error: str = ""


class _IncompleteCyberChefBridge:
    def magic(self, data, depth, intensive, crib):
        decoded_once = base64.b64decode(data).decode("ascii")
        return _FakeCyberChefResponse(
            ok=True,
            results=[
                _FakeCyberChefCandidate(
                    data=decoded_once,
                    recipe=[{"op": "From Base64", "args": []}],
                )
            ],
        )


def test_magic_decoder_falls_back_when_cyberchef_result_is_still_encoded():
    plaintext = b"flag{fallback_after_partial_cyberchef}"
    encoded = base64.b64encode(base64.b64encode(plaintext))

    result = MagicDecoder(bridge=_IncompleteCyberChefBridge()).decode(
        encoded,
        crib=r"flag\{[^}]+\}",
    )

    assert result.final_text == "flag{fallback_after_partial_cyberchef}"
    assert result.total_layers >= 2


def test_magic_decoder_cycle_guard_stops_iterative_loop(monkeypatch):
    decoder = MagicDecoder(bridge=None)

    def alternating_decode(data, crib=None):
        output = b"BBBB" if data == b"AAAA" else b"AAAA"
        step = DecodingStep(
            method=DecodingMethod.BASE64,
            input_data=data,
            output_data=output,
            success=True,
        )
        return DecodingResult(
            original_data=data,
            final_data=output,
            steps=[step],
            total_layers=1,
        )

    monkeypatch.setattr(decoder._decoder, "decode", alternating_decode)

    result = decoder._decode_python(b"AAAA")

    assert result.final_data == b"BBBB"
    assert result.total_layers == 1


def test_magic_decoder_rejects_tiny_or_empty_inputs():
    decoder = MagicDecoder(bridge=None)

    assert decoder.decode(b"").total_layers == 0
    assert decoder.decode(b"abc").final_data == b"abc"
