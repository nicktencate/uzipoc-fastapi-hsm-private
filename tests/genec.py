def test(session, baseurl):
    params = {"curve": "secp256r1", "label": "ECkey"}
    print("Generating EC key: ", params["curve"])
    return session.post(baseurl + "/generate/ec", json=params).json()
