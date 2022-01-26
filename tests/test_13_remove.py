import base64
import os.path


def test_remove(client, module, slot):
    params = {"label": "AESkey2", "objtype": "SECRET_KEY"}
    assert client.post(f"/hsm/{module}/{slot}/destroy", json=params).json()[
        "result"
    ] == {"removed": 1}
