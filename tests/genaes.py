
def test(session, baseurl):
    params = {
        'bits': 256,
        'label': "AESkey"
    }
    return session.post(baseurl+"/generate/aes", json = params).json()
  
   
