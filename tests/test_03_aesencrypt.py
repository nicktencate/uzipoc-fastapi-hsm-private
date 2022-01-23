from base64 import b64encode, b64decode


def _encrypt(client, module, slot, params):
    resp = client.post(f"/hsm/{module}/{slot}/encrypt", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    encrypted = resp["result"]
    assert len(b64decode(encrypted["data"])) in [16, 32], "Data length error"
    assert len(b64decode(encrypted["iv"])) == 16, "IV length error"
    return encrypted["data"], encrypted["iv"]


def _decrypt(client, module, slot, params):
    resp = client.post(f"/hsm/{module}/{slot}/decrypt", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    decrypted = resp["result"]["data"]
    return b64decode(decrypted)


def test_aesencrypt(client, module, slot):
    message = b"Hallo wereld"
    params = {
        "label": "AESkey",
        "objtype": "SECRET_KEY",
        "data": b64encode(message).decode(),
    }

    data, iv = _encrypt(client, module, slot, params)

    params = {"label": "AESkey", "objtype": "SECRET_KEY", "data": data, "iv": iv}
    assert _decrypt(client, module, slot, params) == message


def test_aes_mechanisms(client, module, slot):
    message = b"Hallo wereld"
    mechanisms = client.get(f"/hsm/{module}/{slot}").json()["mechanisms"]
    # Advanced encrypt en decrypt
    for mode in [
        "AES_CBC_PAD",
        "AES_CFB8",
        "AES_CFB8",
        "AES_CFB64",
        "AES_CFB128",
        "AES_ECB",
        "AES_CBC",
    ]:
        if mode in mechanisms:
            message = message + b"\x00" * (
                16 - len(message)
            )  # All mechanisms tolerate 128 bit inputs
            params = {
                "label": "AESkey",
                "objtype": "SECRET_KEY",
                "data": b64encode(
                    message
                ).decode(),  # 128 bits = 16 bytes input required for some
                "mechanism": mode,
            }
            data, iv = _encrypt(client, module, slot, params)

            params = {
                "label": "AESkey",
                "objtype": "SECRET_KEY",
                "data": data,
                "iv": iv,
            }
            assert _decrypt(client, module, slot, params) == message
