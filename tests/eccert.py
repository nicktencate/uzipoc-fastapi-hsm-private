import Crypto.PublicKey.RSA
import asn1crypto.pem
import random
import datetime
import hashlib
import base64

def test(session, baseurl):
    params = {
        "label": "ECkey",
        "objtype": "PUBLIC_KEY",
    }
    publickey = session.post(baseurl, json=params).json()['objects'][0]['publickey'].encode()
    asn1publickey = asn1crypto.keys.PublicKeyInfo.load(asn1crypto.pem.unarmor(publickey)[2])

    signature_alg = {'algorithm': 'sha256_ecdsa'}
    not_before = datetime.datetime.now().astimezone()
    not_after = not_before.replace(not_before.year+1)
    newcertcontent = {
        'version': 'v3',
        'serial_number': random.randint(a=2**64,b=2**65-1),
        'signature': signature_alg,
        'issuer': asn1crypto.x509.Name.build({'common_name': 'ectestcert'}),
        'validity': {
            'not_before': {'utc_time': not_before},
            'not_after': {'utc_time': not_after},
        },
        'subject': asn1crypto.x509.Name.build({'common_name': 'ectestcert'}),
        'subject_public_key_info': asn1publickey,
        'extensions': [{'extn_id': 'key_identifier',
                        'critical': False,
                        'extn_value': hashlib.sha1(asn1publickey['public_key'].native).digest(),
                       },
                       {'extn_id': 'authority_key_identifier',
                        'critical': False,
                        'extn_value': {'key_identifier': hashlib.sha1(asn1publickey['public_key'].native).digest(),
                                       'authority_cert_issuer': None,
                                       'authority_cert_serial_number': None,
                                      },
                       },
                       {'extn_id': 'basic_constraints',
                        'critical': True,
                        'extn_value': {'ca': True,
                                       'path_len_constraint': None,
                                      }
                       }
                      ]
    
    
        }
    tbscert = asn1crypto.x509.TbsCertificate(newcertcontent)

    hashmethod = 'sha256'
    params = {
        "label": "ECkey",
        "objtype": "PRIVATE_KEY",
        "data": base64.b64encode(hashlib.sha256(tbscert.dump()).digest()).decode(),
        "mechanism": 'ECDSA',
    }
    print(params)
    print(session.post(baseurl + "/sign", json=params))
    signature = base64.b64decode(session.post(baseurl + "/sign", json=params).json()["result"])
    signedcertparams = {
        'tbs_certificate': tbscert,
        'signature_algorithm': signature_alg,
        'signature_value': signature,
    }
    finalcert = asn1crypto.x509.Certificate(signedcertparams)

    finalcertpem = asn1crypto.pem.armor('CERTIFICATE', finalcert.dump())
    open('tests/test-cert-ec.pem','wb').write(finalcertpem)
    params = {
        "label": "RSAcert",
        "objtype": "CERTIFICATE",
        "data": base64.b64encode(finalcertpem)
    }
    #assert session.post(baseurl + "/sign", json=params).json()["result"] == True
    return True
