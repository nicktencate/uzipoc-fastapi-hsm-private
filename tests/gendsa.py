
def test(session, baseurl):
    params = {
        'bits': 2048,
        'label': "DSAkey"
    }
    return session.post(baseurl+"/generate/dsa", json = params).json()
  
   
