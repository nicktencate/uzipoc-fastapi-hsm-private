from base64 import b64encode, b64decode


def test(session, baseurl):
    message = b"Hallo wereld    "
    print("Testing AES wrap")

    params = {"label": "AESkey", "objtype": "SECRET_KEY"}

    # Basic encrypt and decrypt
    params = {
        "label": "AESkey",
        "objtype": "SECRET_KEY",
        "data": b64encode(message).decode(),
    }
    encrypted = session.post(baseurl + "/wrap", json=params).json()["result"]
    print(encrypted)
    assert len(b64decode(encrypted["data"])) == 24, "Data length error"

    params = {
        "label": "AESkey",
        "objtype": "SECRET_KEY",
        "data": encrypted["data"],
    }
    decrypted = session.post(baseurl + "/unwrap", json=params).json()["result"]["data"]
    assert b64decode(decrypted) == message

    return True
