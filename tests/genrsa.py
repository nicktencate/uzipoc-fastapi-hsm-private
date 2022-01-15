def test(session, baseurl):
    params = {"bits": 4096, "label": "RSAkey"}
    print("Generating RSA key: ", params["bits"])
    return session.post(baseurl + "/generate/rsa", json=params).json()
