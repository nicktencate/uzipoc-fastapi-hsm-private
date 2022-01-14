
def test(session, baseurl):
    params = {
        'bits': 2048,
        'label': "DSAkey"
    }
    print("Generating RSA key: ",params['bits'])
    return session.post(baseurl+"/generate/dsa", json = params).json()
  
   
