import pytest

from core.file_restorer import FileRestorer


@pytest.mark.parametrize(
    ("payload", "expected_extension"),
    [
        pytest.param(b"PK\x03\x04" + b"zip-body", "zip", id="zip"),
        pytest.param(b"MZ" + b"pe-body", "exe", id="pe"),
        pytest.param(
            b"x" * 257 + b"ustar" + b"x" * 38,
            "tar",
            id="tar-signature-at-offset-257",
        ),
        pytest.param(b"not-a-recognized-file", None, id="unknown"),
    ],
)
def test_detect_file_type_fast_matches_full_signature_detection(
    payload: bytes,
    expected_extension: str | None,
) -> None:
    restorer = FileRestorer()

    full_match = restorer.detect_file_type(payload)
    fast_match = restorer.detect_file_type_fast(payload)

    assert (full_match.extension if full_match else None) == expected_extension
    assert fast_match == full_match
