import asn1crypto.pem
import hashlib
import base64
import tests.certgen

def test(session, baseurl):
    params = {
        "label": "ECkey",
        "objtype": "PUBLIC_KEY",
    }
    publickey = session.post(baseurl, json=params).json()['objects'][0]['publickey'].encode()
    asn1publickey = asn1crypto.keys.PublicKeyInfo.load(asn1crypto.pem.unarmor(publickey)[2])

    for method in ['sha1_ecdsa', 'sha224_ecdsa', 'sha256_ecdsa', 'sha512_ecdsa']:
        print(f"Certificate with: {method}")
        signature_alg = {'algorithm': method}
    
        newcertcontent = tests.certgen.certgen('ectestcert', asn1publickey, signature_alg)
        tbscert = asn1crypto.x509.TbsCertificate(newcertcontent)
    
        hashmethod = signature_alg['algorithm'][:signature_alg['algorithm'].index('_')]
        params = {
            "label": "ECkey",
            "objtype": "PRIVATE_KEY",
            "data": base64.b64encode(hashlib.sha256(tbscert.dump()).digest()).decode(),
            "mechanism": 'ECDSA',
        }
        signature = base64.b64decode(session.post(baseurl + "/sign", json=params).json()["result"])
        signedcertparams = {
            'tbs_certificate': tbscert,
            'signature_algorithm': signature_alg,
            'signature_value': signature,
        }
        finalcert = asn1crypto.x509.Certificate(signedcertparams)
    
        finalcertpem = asn1crypto.pem.armor('CERTIFICATE', finalcert.dump())
        open(f'tests/test-cert-ec-{method}.pem','wb').write(finalcertpem)
        params = {
            "label": "RSAcert",
            "objtype": "CERTIFICATE",
            "data": base64.b64encode(finalcertpem)
        }
    return True
