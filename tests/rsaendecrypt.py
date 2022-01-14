from base64 import b64encode, b64decode
def test(session, baseurl):

    message = b'Hallo wereld'
    params = {
        'label': "RSAkey",
        'objtype': 'PUBLIC_KEY'
    }
    bits = session.post(baseurl, json = params).json()['objects'][0]['MODULUS_BITS']

    # Basic encrypt and decrypt
    # For a short message of 1 block it's MODULES_BITS long
    print("Testing RSA encryption: default")
    params = {
        'label': "RSAkey",
        'objtype': 'PUBLIC_KEY',
        'data': b64encode(message).decode()
    }
    encrypted = session.post(baseurl+"/encrypt", json = params).json()['result']
    assert len(b64decode(encrypted)) == bits/8, "Length error RSA encrypt"

    params = {
        'label': "RSAkey",
        'objtype': 'PRIVATE_KEY',
        'data': encrypted
    }
    decrypted = session.post(baseurl+"/decrypt", json = params).json()['result']
    assert b64decode(decrypted) == message

    print("Testing RSA encryption: RSA_PKCS")
    params = {
        'label': "RSAkey",
        'objtype': 'PUBLIC_KEY',
        'mechanism': 'RSA_PKCS',
        'data': b64encode(message).decode()
    }
    encrypted = session.post(baseurl+"/encrypt", json = params).json()['result']
    assert len(b64decode(encrypted)) == bits/8, "Length error RSA encrypt"

    params = {
        'label': "RSAkey",
        'objtype': 'PRIVATE_KEY',
        'mechanism': 'RSA_PKCS',
        'data': encrypted
    }
    decrypted = session.post(baseurl+"/decrypt", json = params).json()['result']
    assert b64decode(decrypted) == message

    # More modern encryption
    print("Testing RSA encryption: RSA_PKCS_OAEP (SHA1)")
    params = {
        'label': "RSAkey",
        'objtype': 'PUBLIC_KEY',
        'mechanism': 'RSA_PKCS_OAEP',
        'hashmethod': 'sha1',
        'data': b64encode(message).decode()
    }
    encrypted = session.post(baseurl+"/encrypt", json = params).json()['result']
    assert len(b64decode(encrypted)) == bits/8, "Length error RSA encrypt"

    params = {
        'label': "RSAkey",
        'objtype': 'PRIVATE_KEY',
        'mechanism': 'RSA_PKCS_OAEP',
        'hashmethod': 'sha1',
        'data': encrypted
    }
    decrypted = session.post(baseurl+"/decrypt", json = params).json()['result']
    assert b64decode(decrypted) == message

    return True
