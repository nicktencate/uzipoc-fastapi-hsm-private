from base64 import b64encode, b64decode

import Crypto.Hash.SHA
import Crypto.Hash.SHA224
import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512

HasherToCryptoHash = {
    "sha1": Crypto.Hash.SHA,
    "sha224": Crypto.Hash.SHA224,
    "sha256": Crypto.Hash.SHA256,
    "sha384": Crypto.Hash.SHA384,
    "sha512": Crypto.Hash.SHA512,
}


def _sign(client, module, slot, params):
    resp = client.post(f"/hsm/{module}/{slot}/sign", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    signature = resp["result"]
    assert len(b64decode(signature)) > 64, "Length error EC sign"
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
        "label": "ECkey",
        "objtype": "PRIVATE_KEY",
        "data": b64encode(message).decode(),
        "mechanism": "ECDSA",
    }

    params = {
        "label": "ECkey",
        "objtype": "PUBLIC_KEY",
        "data": b64encode(message).decode(),
        "mechanism": "ECDSA",
        "signature": _sign(client, module, slot, params),
    }

    assert _verify(client, module, slot, params)
