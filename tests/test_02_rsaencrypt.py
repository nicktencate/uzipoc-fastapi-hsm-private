from base64 import b64encode, b64decode


def _encrypt(client, module, slot, params, bits):
    resp = client.post(f"/hsm/{module}/{slot}/encrypt", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    encrypted = resp["result"]
    assert len(b64decode(encrypted)) == bits / 8, "Length error RSA encrypt"
    return encrypted


def _decrypt(client, module, slot, params):
    resp = client.post(f"/hsm/{module}/{slot}/decrypt", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    decrypted = resp["result"]
    return b64decode(decrypted)


def test_rsaencrypt(client, module, slot):
    message = b"Hallo wereld"
    params = {"label": "RSAkey", "objtype": "PUBLIC_KEY"}
    bits = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0][
        "MODULUS_BITS"
    ]

    # Basic encrypt and decrypt
    # For a short message of 1 block it's MODULES_BITS long
    params = {
        "label": "RSAkey",
        "objtype": "PUBLIC_KEY",
        "data": b64encode(message).decode(),
    }

    params = {
        "label": "RSAkey",
        "objtype": "PRIVATE_KEY",
        "data": _encrypt(client, module, slot, params, bits),
    }
    assert _decrypt(client, module, slot, params) == message


def test_rsaencrypt_pkcs(client, module, slot):
    message = b"Hallo wereld"
    params = {"label": "RSAkey", "objtype": "PUBLIC_KEY"}
    bits = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0][
        "MODULUS_BITS"
    ]
    params = {
        "label": "RSAkey",
        "objtype": "PUBLIC_KEY",
        "mechanism": "RSA_PKCS",
        "data": b64encode(message).decode(),
    }

    params = {
        "label": "RSAkey",
        "objtype": "PRIVATE_KEY",
        "mechanism": "RSA_PKCS",
        "data": _encrypt(client, module, slot, params, bits),
    }
    assert _decrypt(client, module, slot, params) == message


def test_rsaencrypt_pkcs_oaep(client, module, slot):
    message = b"Hallo wereld"
    params = {"label": "RSAkey", "objtype": "PUBLIC_KEY"}
    bits = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0][
        "MODULUS_BITS"
    ]
    params = {
        "label": "RSAkey",
        "objtype": "PUBLIC_KEY",
        "mechanism": "RSA_PKCS_OAEP",
        "hashmethod": "sha1",
        "data": b64encode(message).decode(),
    }

    params = {
        "label": "RSAkey",
        "objtype": "PRIVATE_KEY",
        "mechanism": "RSA_PKCS_OAEP",
        "hashmethod": "sha1",
        "data": _encrypt(client, module, slot, params, bits),
    }
    assert _decrypt(client, module, slot, params) == message
