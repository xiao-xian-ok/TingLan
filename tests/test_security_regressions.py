import base64
from dataclasses import dataclass

import pytest

from core.ast_engine import PHPASTEngine
from core.auto_decoder import (
    DecodingMethod,
    DecodingResult,
    DecodingStep,
    MagicDecoder,
)
from core.safe_paths import (
    ensure_child_path,
    iter_safe_child_files,
    safe_unique_path,
    sanitize_filename,
)
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
