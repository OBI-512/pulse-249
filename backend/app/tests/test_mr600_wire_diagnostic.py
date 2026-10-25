import httpx

from app.remote_gateway.mr600_wire_diagnostic import _decrypt_response_shape, summarize_request
from app.remote_gateway.tp_link_mr_web_auth import _aes_cbc_base64


def test_mr600_wire_diagnostic_request_summary_is_structural_only():
    secret_sign = "a" * 256
    secret_data = _aes_cbc_base64(
        "1&1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\nmodelName\r\n",
        key="1234567890123456",
        iv="6543210987654321",
    )
    request = httpx.Request(
        "POST",
        "http://192.0.2.44/cgi_gdpr",
        headers={
            "Content-Type": "text/plain",
            "TokenID": "TOKEN_SECRET",
            "Cookie": "JSESSIONID=COOKIE_SECRET",
        },
        content=f"sign={secret_sign}\r\ndata={secret_data}\r\n".encode("ascii"),
    )

    shape = summarize_request(request)

    assert shape.method == "POST"
    assert shape.path == "/cgi_gdpr"
    assert shape.token_id_present is True
    assert shape.cookie_present is True
    assert shape.field_names == ("data", "sign")
    assert shape.sign_length == 256
    assert shape.sign_is_hex is True
    assert shape.data_length == len(secret_data)
    assert shape.data_is_base64 is True
    assert shape.cipher_bytes > 0
    assert shape.cipher_block_aligned is True
    assert "TOKEN_SECRET" not in repr(shape)
    assert "COOKIE_SECRET" not in repr(shape)
    assert secret_sign not in repr(shape)
    assert secret_data not in repr(shape)


def test_mr600_wire_diagnostic_validates_response_crypto_without_returning_plaintext():
    key = "1234567890123456"
    iv = "6543210987654321"
    plaintext = "$.ret=0;\r\nvar modelName=\"MR600\";\r\n"
    encrypted = _aes_cbc_base64(plaintext, key=key, iv=iv).encode("ascii")

    ok, plaintext_bytes, plaintext_lines = _decrypt_response_shape(encrypted, key=key, iv=iv)

    assert ok is True
    assert plaintext_bytes == len(plaintext.encode("utf-8"))
    assert plaintext_lines == 2
    assert plaintext not in repr((ok, plaintext_bytes, plaintext_lines))


def test_mr600_wire_diagnostic_rejects_non_ciphertext_response():
    assert _decrypt_response_shape(b"not-base64", key="1234567890123456", iv="6543210987654321") == (False, 0, 0)
