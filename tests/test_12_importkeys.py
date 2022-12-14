import base64
import os.path


def test_import(client, module, slot):
    files = [
        "openssl-x25519key.pem",
        "openssl-x25519public.pem",
        "openssl-ed25519key.pem",
        "openssl-ed25519public.pem",
        "openssl-ed25519public.pem",
        "openssl-ecpublic.pem",
        "openssl-eckey.pem",
        "openssl-rsapublic.pem",
        "openssl-rsakey.pem",
    ]
    for file in files:
        if os.path.isfile(f"tests/{file}"):
            with open(f"tests/{file}", "rb") as keyfile:
                params = {
                    "label": file,
                    "pem": True,
                    "data": base64.b64encode(keyfile.read()).decode(),
                }
                assert (
                    len(
                        client.post(f"/hsm/{module}/{slot}/import", json=params).json()[
                            "objects"
                        ]
                    )
                    == 1
                ), f"Import error on {file}"
    return True
