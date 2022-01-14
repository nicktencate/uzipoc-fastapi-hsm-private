
def test(session, baseurl):
    params = {
        'bits': 2048,
        'label': "RSAkey"
    }
    return session.post(baseurl+"/generate/rsa", json = params).json()
  
   
