from base64 import b64encode, b64decode
import asn1crypto.pem
import asn1crypto.keys


def test_default(client, module, slot):

    aessize = 256

    message = b"\x42" * int(aessize / 8)
    params = {"label": "ECkey2", "objtype": "PUBLIC_KEY"}
    pk = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0]
    otherpub = asn1crypto.keys.PublicKeyInfo.load(
        asn1crypto.pem.unarmor(pk["publickey"].encode())[2]
    )["public_key"].native

    params = {"label": "ECkey", "objtype": "PUBLIC_KEY"}
    pk = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0]
    thispub = asn1crypto.keys.PublicKeyInfo.load(
        asn1crypto.pem.unarmor(pk["publickey"].encode())[2]
    )["public_key"].native

    params = {
        "label": "ECkey",
        "objtype": "PRIVATE_KEY",
        "otherpub": b64encode(otherpub).decode(),
        "size": 256,
        "data": b64encode(message).decode(),
    }
    shared1 = b64decode(
        client.post(f"/hsm/{module}/{slot}/derive", json=params).json()["result"]
    )
    params = {
        "label": "ECkey2",
        "objtype": "PRIVATE_KEY",
        "otherpub": b64encode(thispub).decode(),
        "size": 256,
        "data": b64encode(message).decode(),
    }
    shared2 = b64decode(
        client.post(f"/hsm/{module}/{slot}/derive", json=params).json()["result"]
    )
    assert len(shared1) == aessize / 8
    assert len(shared2) == aessize / 8
    assert shared1 == shared2

    params = {
        "label": "ECkey",
        "objtype": "PRIVATE_KEY",
        "otherpub": b64encode(otherpub).decode(),
        "size": 256,
        "wrap": "aes256_wrap",
        "data": b64encode(message).decode(),
        "algorithm": "NULL",
    }
    shared1 = b64decode(
        client.post(f"/hsm/{module}/{slot}/derive", json=params).json()["result"]
    )
    assert len(shared1) == (aessize / 8) + 8
    params = {
        "label": "ECkey2",
        "objtype": "PRIVATE_KEY",
        "otherpub": b64encode(thispub).decode(),
        "size": 256,
        "unwrap": "aes256_wrap",
        "data": b64encode(shared1).decode(),
        "algorithm": "NULL",
    }
    shared2 = b64decode(
        client.post(f"/hsm/{module}/{slot}/derive", json=params).json()["result"]
    )
    assert len(shared2) == len(message)
    assert shared2 == message

    params = {
        "label": "ECkey",
        "objtype": "PRIVATE_KEY",
        "otherpub": b64encode(otherpub).decode(),
        "size": 256,
        "wrap": "aes256_wrap",
        "data": b64encode(message).decode(),
        "algorithm": "dhSinglePass-stdDH-sha256kdf-scheme",
    }
    shared1 = b64decode(
        client.post(f"/hsm/{module}/{slot}/derive", json=params).json()["result"]
    )
    assert len(shared1) == (aessize / 8) + 8
    params = {
        "label": "ECkey2",
        "objtype": "PRIVATE_KEY",
        "otherpub": b64encode(thispub).decode(),
        "size": 256,
        "unwrap": "aes256_wrap",
        "data": b64encode(shared1).decode(),
        "algorithm": "dhSinglePass-stdDH-sha256kdf-scheme",
    }
    shared2 = b64decode(
        client.post(f"/hsm/{module}/{slot}/derive", json=params).json()["result"]
    )
    assert len(shared2) == len(message)
    assert shared2 == message
