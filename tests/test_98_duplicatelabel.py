def test_genaes(client, module, slot):
    params = {"bits": 256, "label": "AESkey"}
    resp = client.post(f"/hsm/{module}/{slot}/generate/aes", json=params).json()
    assert resp == {
        "error": "Unprocessible HSM Request",
        "error_description": "Object already exists",
    }


def test_genrsa(client, module, slot):
    params = {"bits": 2048, "label": "RSAkey"}
    resp = client.post(f"/hsm/{module}/{slot}/generate/rsa", json=params).json()
    assert resp == {
        "error": "Unprocessible HSM Request",
        "error_description": "Object already exists",
    }


def test_gendsa(client, module, slot):
    params = {"bits": 2048, "label": "DSAkey"}
    resp = client.post(f"/hsm/{module}/{slot}/generate/dsa", json=params).json()
    assert resp == {
        "error": "Unprocessible HSM Request",
        "error_description": "Object already exists",
    }


def test_eckey(client, module, slot):
    params = {"curve": "secp256r1", "label": "ECkey"}
    resp = client.post(f"/hsm/{module}/{slot}/generate/ec", json=params).json()
    assert resp == {
        "error": "Unprocessible HSM Request",
        "error_description": "Object already exists",
    }


def test_edwards(client, module, slot):
    if (
        "EC_EDWARDS_KEY_PAIR_GEN"
        in client.get(f"/hsm/{module}/{slot}").json()["mechanisms"]
    ):
        params = {"curve": "curve25519", "label": "X25519key"}
        resp = client.post(f"/hsm/{module}/{slot}/generate/edwards", json=params).json()
        assert resp == {
            "error": "Unprocessible HSM Request",
            "error_description": "Object already exists",
        }
