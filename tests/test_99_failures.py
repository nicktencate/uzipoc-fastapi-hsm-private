from base64 import b64encode
import asn1crypto.pem


def test_root(client, _module, _slot):
    resp = client.get("/").json()
    assert resp == {
        "data": {
            "ca": {"ca": "clients/ca.pem", "crl": "clients/crl.pem"},
            "modules": [
                {
                    "module": "/usr/lib64/pkcs11/libsofthsm2.so",
                    "name": "softhsm",
                    "slots": [
                        {"pinfile": "secrets/someslot-000.pin", "slot": "SoftHSMLabel"}
                    ],
                }
            ],
        },
        "error": 0,
        "message": "working",
    }


def test_list(client, _module, _slot):
    resp = client.get("/hsm/list").json()
    assert resp == {"modules": ["softhsm"]}


def test_nomodule(client, module, slot):
    resp = client.get(f"/hsm/no-{module}/{slot}")
    assert resp.status_code == 422
    resp = client.get(f"/hsm/{module}/no-{slot}")
    assert resp.status_code == 422


def test_nosuchkey(client, module, slot):
    params = {
        "label": "NoSuchKey",
        "objtype": "PRIVATE_KEY",
        "data": b64encode(b"Failure").decode(),
        "mechanism": "RSA_PKCS",
    }
    resp = client.post(f"/hsm/{module}/{slot}/sign", json=params).json()
    assert resp == {
        "error": "Unprocessible HSM Request",
        "error_description": "No such key",
    }


def test_remove(client, module, slot):
    params = {"label": "AESkey2", "objtype": "SECRET_KEY"}
    assert client.post(f"/hsm/{module}/{slot}/destroy", json=params).json()[
        "result"
    ] == {"removed": 0}


def test_unsupported_pem_import(client, module, slot):
    params = {
        "label": "wtf",
        "pem": True,
        "data": b64encode(asn1crypto.pem.armor("WTF", b"Uhhhhhh")).decode(),
    }
    assert client.post(f"/hsm/{module}/{slot}/import", json=params).json() == {
        "error": "Unprocessible HSM Request",
        "error_description": "Can't import WTF",
    }


def test_unsupported_public_key_pem_import(client, module, slot):
    params = {
        "label": "wtf",
        "pem": True,
        "data": b64encode(
            asn1crypto.pem.armor(
                "PUBLIC KEY",
                asn1crypto.keys.PublicKeyInfo(
                    {"algorithm": {"algorithm": "dh"}, "public_key": 42}
                ).dump(),
            )
        ).decode(),
    }
    assert client.post(f"/hsm/{module}/{slot}/import", json=params).json() == {
        "error": "Unprocessible HSM Request",
        "error_description": "Can't import public key dh",
    }


def test_unsupported_raw_import(client, module, slot):
    params = {"label": "wtf", "pem": False, "data": b64encode(b"Uhhhhhh").decode()}
    assert client.post(f"/hsm/{module}/{slot}/import", json=params).json() == {
        "error": "Unprocessible HSM Request",
        "error_description": "Raw import not supported yet",
    }


def test_rsawronglength(client, module, slot):
    params = {
        "label": "RSAkey",
        "objtype": "PRIVATE_KEY",
        "data": b64encode(b"Failure").decode(),
        "mechanism": "RSA_PKCS_OAEP",
        "hashmethod": "sha512",
    }
    resp = client.post(f"/hsm/{module}/{slot}/sign", json=params).json()
    assert resp == {
        "error": "Unprocessible HSM Request",
        "error_description": "Data length does not match hash method",
    }


def test_ec_without_mech(client, module, slot):
    params = {
        "label": "ECkey",
        "objtype": "PRIVATE_KEY",
        "data": b64encode(b"Uhhh").decode(),
    }
    resp = client.post(f"/hsm/{module}/{slot}/sign", json=params).json()
    assert resp == {
        "error": "Unprocessible HSM Request",
        "error_description": "Failure at executing function: <class 'pkcs11.exceptions.MechanismInvalid'>",
    }
    params = {
        "label": "ECkey",
        "objtype": "PUBLIC_KEY",
        "data": b64encode(b"Uhhh").decode(),
        "signature": b64encode(b"Uhhh").decode(),
    }
    resp = client.post(f"/hsm/{module}/{slot}/verify", json=params).json()
    assert resp == {
        "error": "Unprocessible HSM Request",
        "error_description": "Failure at executing function: <class 'pkcs11.exceptions.MechanismInvalid'>",
    }


def test_derive_no_args(client, module, slot):

    aessize = 256

    message = b"\x42" * int(aessize / 8)
    params = {"label": "ECkey2", "objtype": "PUBLIC_KEY"}
    pk = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0]
    otherpub = asn1crypto.keys.PublicKeyInfo.load(
        asn1crypto.pem.unarmor(pk["publickey"].encode())[2]
    )["public_key"].native

    params = {
        "label": "ECkey",
        "objtype": "PRIVATE_KEY",
        "otherpub": b64encode(otherpub).decode(),
        "data": b64encode(message).decode(),
    }
    resp = client.post(f"/hsm/{module}/{slot}/derive", json=params).json()
    assert resp == {
        "error": "Unprocessible HSM Request",
        "error_description": "Not enought arguments",
    }
