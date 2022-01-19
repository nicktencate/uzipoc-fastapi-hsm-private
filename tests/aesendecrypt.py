from base64 import b64encode, b64decode


def test(session, baseurl):

    message = b"Hallo wereld"
    print("Testing AES mode: Default")

    params = {"label": "AESkey", "objtype": "SECRET_KEY"}
    _aessize = session.post(baseurl, json=params).json()["objects"][0]["VALUE_LEN"] * 8

    # Basic encrypt and decrypt
    params = {
        "label": "AESkey",
        "objtype": "SECRET_KEY",
        "data": b64encode(message).decode(),
    }
    encrypted = session.post(baseurl + "/encrypt", json=params).json()["result"]
    assert len(b64decode(encrypted["data"])) == 16, "Data length error"
    assert len(b64decode(encrypted["iv"])) == 16, "IV length error"

    params = {
        "label": "AESkey",
        "objtype": "SECRET_KEY",
        "data": encrypted["data"],
        "iv": encrypted["iv"],
    }
    decrypted = session.post(baseurl + "/decrypt", json=params).json()["result"]["data"]
    assert b64decode(decrypted) == message

    mechanisms = session.get(baseurl).json()["mechanisms"]
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
            print("Testing AES mode:", mode)
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
            encrypted = session.post(baseurl + "/encrypt", json=params).json()["result"]
            assert len(b64decode(encrypted["data"])) == 32, "Data length error"
            assert len(b64decode(encrypted["iv"])) == 16, "IV length error"

            params = {
                "label": "AESkey",
                "objtype": "SECRET_KEY",
                "data": encrypted["data"],
                "iv": encrypted["iv"],
            }
            decrypted = session.post(baseurl + "/decrypt", json=params).json()[
                "result"
            ]["data"]
            assert b64decode(decrypted) == message

    return True
