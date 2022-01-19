import base64


def test(session, baseurl):
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
        print(f"Importing: {file}")
        with open(f"tests/{file}", "rb") as keyfile:
            params = {
                "label": file,
                "pem": True,
                "data": base64.b64encode(keyfile.read()).decode(),
            }
            assert (
                len(session.post(baseurl + "/import", json=params).json()["objects"])
                == 1
            ), f"Import error on {file}"
    return True
