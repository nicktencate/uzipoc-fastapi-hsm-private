from base64 import b64encode, b64decode


def _sign(client, module, slot, params):
    resp = client.post(f"/hsm/{module}/{slot}/sign", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    signature = resp["result"]["data"]
    assert len(b64decode(signature)) == 16, "Length error DSA sign"
    return signature


def _verify(client, module, slot, params):
    resp = client.post(f"/hsm/{module}/{slot}/verify", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    signature = resp["result"]
    return signature


def test_default(client, module, slot):
    message = b"Hallo wereld"

    params = {
        "label": "AESkey",
        "data": b64encode(message).decode(),
        "mechanism": "AES_CMAC",
    }
    params = {
        "label": "AESkey",
        "data": b64encode(message).decode(),
        "signature": _sign(client, module, slot, params),
        "mechanism": "AES_CMAC",
    }
    assert _verify(client, module, slot, params)
