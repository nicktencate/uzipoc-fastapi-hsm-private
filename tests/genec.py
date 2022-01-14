def test(session, baseurl):
    params = {
        'curve': 'secp256r1',
        'label': "ECkey"
    }
    return session.post(baseurl+"/generate/ec", json = params).json()
  
   
