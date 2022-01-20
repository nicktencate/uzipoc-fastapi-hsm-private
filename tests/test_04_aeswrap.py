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


def test_aeswrap(client, module, slot):
    message = b"Hallo wereld1234"
    params = {
        "label": "AESkey",
        "objtype": "SECRET_KEY",
        "data": b64encode(message).decode(),
    }
    resp = client.post(f"/hsm/{module}/{slot}/wrap", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    encrypted = resp["result"]
    assert len(b64decode(encrypted["data"])) == 24, "Data length error"

    params = {
        "label": "AESkey",
        "objtype": "SECRET_KEY",
        "data": encrypted["data"],
    }
    resp = client.post(f"/hsm/{module}/{slot}/unwrap", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    decrypted = resp["result"]["data"]
    assert b64decode(decrypted) == message
