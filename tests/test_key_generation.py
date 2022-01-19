def test_genaes(client, module, slot):
    params = {"bits": 256, "label": "AESkey"}
    resp = client.post(f"/hsm/{module}/{slot}/generate/aes", json=params).json()
    assert resp == {
        "module": module,
        "slot": slot,
        "result": [
            {
                "CLASS": "SECRET_KEY",
                "TOKEN": True,
                "PRIVATE": True,
                "LABEL": "AESkey",
                "CHECK_VALUE": "86c5ee",
                "KEY_TYPE": "AES",
                "SENSITIVE": True,
                "ENCRYPT": True,
                "DECRYPT": True,
                "WRAP": True,
                "UNWRAP": True,
                "SIGN": True,
                "VERIFY": True,
                "VALUE_LEN": 32,
                "LOCAL": True,
                "NEVER_EXTRACTABLE": True,
                "ALWAYS_SENSITIVE": True,
                "KEY_GEN_MECHANISM": "AES_KEY_GEN",
                "MODIFIABLE": True,
                "COPYABLE": True,
            }
        ],
    }


def test_gendsa(client, module, slot):
    params = {"bits": 2048, "label": "DSAkey"}
    resp = client.post(f"/hsm/{module}/{slot}/generate/dsa", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    assert all(
        i in resp["result"][0].keys()
        for i in [
            "CLASS",
            "TOKEN",
            "LABEL",
            "KEY_TYPE",
            "VERIFY",
            "VERIFY_RECOVER",
            "PRIME",
        ]
    )
    assert resp["result"][0]["KEY_TYPE"] == "DSA"


def test_eckey(client, module, slot):
    params = {"curve": "secp256r1", "label": "ECkey"}
    resp = client.post(f"/hsm/{module}/{slot}/generate/ec", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    assert all(
        i in resp["result"][0].keys()
        for i in [
            "CLASS",
            "TOKEN",
            "LABEL",
            "KEY_TYPE",
            "VERIFY",
            "VERIFY_RECOVER",
            "PRIME",
        ]
    )
    assert resp["result"][0]["KEY_TYPE"] == "EC"


# def test_edwards(client, module, slot):
#     params = {"curve": "curve25519", "label": "X25519key"}
#     edwards_X = client.post(
#         f"/hsm/{module}/{slot}/generate/edwards", json=params
#     ).json()
#     assert edwards_X["module"] == module
#     assert edwards_X["slot"] == slot
#     assert all(
#         i in edwards_X["result"][0].keys()
#         for i in [
#             "CLASS",
#             "TOKEN",
#             "LABEL",
#             "KEY_TYPE",
#             "VERIFY",
#             "VERIFY_RECOVER",
#             "PRIME",
#         ]
#     )
#     assert edwards_X["result"][0]["KEY_TYPE"] == "EC"

    # params = {"curve": "ed25519", "label": "ED25519key"}
    # edwards_ED = client.post(
    #     f"/hsm/{module}/{slot}/generate/edwards", json=params
    # ).json()
    # print(edwards_ED)
