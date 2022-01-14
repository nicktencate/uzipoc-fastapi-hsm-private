def test(session, baseurl):
    params = {
        'curve': 'curve25519',
        'label': "X25519key"
    }
    print("Generating ED key: ", params['curve'])
    #print(session.post(baseurl+"/generate/edwards", json = params).json())
    params = {
        'curve': 'ed25519',
        'label': "ED25519key"
    }
    print("Generating ED key: ", params['curve'])
    return session.post(baseurl+"/generate/edwards", json = params).json()
