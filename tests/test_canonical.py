import pytest
import rfc8785

from pact.canonical import (
    CanonicalizationProfile,
    ContentCanonicalizationError,
    canonical_json,
    canonicalize_content,
)


def test_canonical_json_uses_rfc_8785_order_and_number_encoding() -> None:
    value = {"numbers": [1e30, 4.5, 0.002], "literals": [None, True, False]}

    assert canonical_json(value) == (
        b'{"literals":[null,true,false],"numbers":[1e+30,4.5,0.002]}'
    )


def test_canonical_json_rejects_values_outside_i_json() -> None:
    with pytest.raises(rfc8785.CanonicalizationError):
        canonical_json({"value": float("nan")})


def test_binary_content_is_unchanged() -> None:
    content = b"\x00\xff\r\n"

    assert (
        canonicalize_content(content, CanonicalizationProfile.BINARY_V1)
        is content
    )


def test_text_content_is_utf8_nfc_with_lf_endings() -> None:
    content = "Cafe\u0301\r\nnext\rlast".encode()

    assert (
        canonicalize_content(content, CanonicalizationProfile.TEXT_V1)
        == "Caf\xe9\nnext\nlast".encode()
    )


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"\xef\xbb\xbftext", "BOM"),
        (b"\xff", "valid UTF-8"),
    ],
)
def test_invalid_text_content_is_rejected(
    content: bytes,
    message: str,
) -> None:
    with pytest.raises(ContentCanonicalizationError, match=message):
        canonicalize_content(content, CanonicalizationProfile.TEXT_V1)
