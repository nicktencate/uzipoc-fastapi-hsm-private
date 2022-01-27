from base64 import b64encode, b64decode


def _sign(client, module, slot, params):
    resp = client.post(f"/hsm/{module}/{slot}/sign", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    signature = resp["result"]
    assert len(b64decode(signature)) == 64, "Length error DSA sign"
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
        "label": "DSAkey",
        "objtype": "PRIVATE_KEY",
        "data": b64encode(message).decode(),
    }
    params = {
        "label": "DSAkey",
        "objtype": "PUBLIC_KEY",
        "data": b64encode(message).decode(),
        "signature": _sign(client, module, slot, params),
    }
    assert _verify(client, module, slot, params)

    mechanisms = [
        mechanism
        for mechanism in client.get(f"/hsm/{module}/{slot}").json()["mechanisms"]
        if mechanism.startswith("DSA_SHA")
    ]

    for mech in mechanisms:
        params = {
            "label": "DSAkey",
            "objtype": "PRIVATE_KEY",
            "data": b64encode(message).decode(),
            "mechanism": mech,
        }
        params = {
            "label": "DSAkey",
            "objtype": "PUBLIC_KEY",
            "data": b64encode(message).decode(),
            "signature": _sign(client, module, slot, params),
            "mechanism": mech,
        }
        assert _verify(client, module, slot, params)
