from base64 import b64encode, b64decode


def test(session, baseurl):

    message = b"Hallo wereld"
    # params = {"label": "ECkey", "objtype": "PUBLIC_KEY"}
    # pk = session.post(baseurl, json=params).json()["objects"][0]

    # Basic sign and verify
    # For a short message of 1 block it's MODULES_BITS long
    print("Testing EC sign: default")
    params = {
        "label": "ECkey",
        "objtype": "PRIVATE_KEY",
        "data": b64encode(message).decode(),
        "mechanism": "ECDSA",
    }
    signature = session.post(baseurl + "/sign", json=params).json()["result"]
    assert len(b64decode(signature)) >  64, "Length error EC sign"

    print("Testing EC verify: default")
    params = {
        "label": "ECkey",
        "objtype": "PUBLIC_KEY",
        "data": b64encode(message).decode(),
        "mechanism": "ECDSA",
        "signature": signature,
    }
    decrypted = session.post(baseurl + "/verify", json=params).json()["result"]
    assert decrypted is True

    return True
