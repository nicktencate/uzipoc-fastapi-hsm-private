
def test(session, baseurl):
    params = {
        'bits': 4096,
        'label': "RSAkey"
    }
    return session.post(baseurl+"/generate/rsa", json = params).json()
  
   
