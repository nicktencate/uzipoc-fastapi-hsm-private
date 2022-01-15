from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5, PKCS1_PSS
from Crypto.Util import number
import hashlib
import asn1crypto.tsp

import Crypto.Hash.SHA
import Crypto.Hash.SHA224
import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512

HasherToCryptoHash = {
    'sha1': Crypto.Hash.SHA,
    'sha224': Crypto.Hash.SHA224,
    'sha256': Crypto.Hash.SHA256,
    'sha384': Crypto.Hash.SHA384,
    'sha512': Crypto.Hash.SHA512,
    }


def test(session, baseurl):

    message = b'Hallo wereld'
    params = {
        'label': "RSAkey",
        'objtype': 'PUBLIC_KEY'
    }
    pk = session.post(baseurl, json = params).json()['objects'][0]
    bits = pk['MODULUS_BITS']
    publickey = pk['publickey']

    # Basic sign and verify
    # For a short message of 1 block it's MODULES_BITS long
    print("Testing RSA sign: default")
    params = {
        'label': "RSAkey",
        'objtype': 'PRIVATE_KEY',
        'data': b64encode(message).decode()
    }
    signature = session.post(baseurl+"/sign", json = params).json()['result']
    assert len(b64decode(signature)) == bits/8, "Length error RSA encrypt"

    print("Testing RSA verify: default")
    params = {
        'label': "RSAkey",
        'objtype': 'PUBLIC_KEY',
        'data': b64encode(message).decode(),
        'signature': signature
    }
    decrypted = session.post(baseurl+"/verify", json = params).json()['result']
    assert decrypted == True

    allmechanisms = session.get(baseurl).json()['mechanisms']
    print(allmechanisms)
    mechanisms = [mechanism for mechanism in allmechanisms if mechanism.startswith('SHA') and mechanism.endswith('_RSA_PKCS')]
    for mech in mechanisms:
        print("Testing RSA sign: ",mech)
        params = {
            'label': "RSAkey",
            'objtype': 'PRIVATE_KEY',
            'data': b64encode(message).decode(),
            'mechanism': mech
        }
        signature = session.post(baseurl+"/sign", json = params).json()['result']
        assert len(b64decode(signature)) == bits/8, "Length error RSA encrypt"

        print("Testing RSA verify (hsm): ",mech)
        params = {
            'label': "RSAkey",
            'objtype': 'PUBLIC_KEY',
            'data': b64encode(message).decode(),
            'mechanism': mech,
            'signature': signature
        }
        decrypted = session.post(baseurl+"/verify", json = params).json()['result']
        assert decrypted == True

        print("Testing RSA verify (external): ",mech)
        hashmethod = mech[:mech.index('_')].lower()
        manualhashmethod = mech[mech.index('_')+1:] 
        hasher = getattr(hashlib, hashmethod)
        pubkey = RSA.importKey(publickey)
        psig = number.long_to_bytes(pow(number.bytes_to_long(b64decode(signature)),pubkey.e,pubkey.n))
        signedhash = psig[psig.index(b'\x00')+1:]
        assert asn1crypto.tsp.MessageImprint().load(signedhash)['hashed_message'].native == hasher(message).digest()

    mechanisms = [mechanism for mechanism in allmechanisms if mechanism.startswith('SHA') and mechanism.endswith('_RSA_PKCS_PSS')]
    for mech in mechanisms:
        print("Testing RSA sign: ",mech)
        hashmethod = mech[:mech.index('_')].lower()
        params = {
            'label': "RSAkey",
            'objtype': 'PRIVATE_KEY',
            'data': b64encode(message).decode(),
            'mechanism': mech,
            'hashmethod': hashmethod,
        }
        signature = session.post(baseurl+"/sign", json = params).json()['result']
        assert len(b64decode(signature)) == bits/8, "Length error RSA encrypt"
        

        print("Testing RSA verify: ",mech)
        params = {
            'label': "RSAkey",
            'objtype': 'PUBLIC_KEY',
            'data': b64encode(message).decode(),
            'mechanism': mech,
            'signature': signature,
            'hashmethod': hashmethod,
        }
        decrypted = session.post(baseurl+"/verify", json = params).json()['result']
        assert decrypted == True

        print("Testing RSA verify (external): ",mech)
        manualhashmethod = mech[mech.index('_')+1:] 
        hasher = getattr(hashlib, hashmethod)
        pubkey = RSA.importKey(publickey)
        psig = number.long_to_bytes(pow(number.bytes_to_long(b64decode(signature)),pubkey.e,pubkey.n))
        CryptoHash = HasherToCryptoHash[hashmethod]
        assert PKCS1_PSS.EMSA_PSS_VERIFY(CryptoHash.new(message), psig, 4096-1, lambda x,y: PKCS1_PSS.MGF1(x, y, CryptoHash.new()), CryptoHash.digest_size) == True, "Non-HSM verify error"

    return True
