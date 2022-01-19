def test(session, baseurl):
    params = {"bits": 4096, "label": "RSAkey"}
    print("Generating RSA key: ", params["bits"])
    ret = session.post(baseurl + "/generate/rsa", json=params).json()
    return ret
