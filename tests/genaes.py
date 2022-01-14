
def test(session, baseurl):
    params = {
        'bits': 256,
        'label': "AESkey"
    }
    print("Generating AES key: ",params['bits'])
    return session.post(baseurl+"/generate/aes", json = params).json()
  
   
