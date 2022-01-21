import hashlib
from base64 import b64encode, b64decode

import asn1crypto.pem

import tests.certgen

def _sign(client, module, slot, params, bits):
    resp = client.post(f"/hsm/{module}/{slot}/sign", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    signature = resp["result"]
    assert len(b64decode(signature)) == bits / 8, "Length error RSA sign"
    return b64decode(signature)

def makecert(client, module, slot, signature_alg, certcontent):
    tbscert = asn1crypto.x509.TbsCertificate(certcontent)
    hashmethod = signature_alg["algorithm"][: signature_alg["algorithm"].index("_")]

    hashasn1 = asn1crypto.tsp.MessageImprint(
        {
            "hash_algorithm": {"algorithm": hashmethod},
            "hashed_message": getattr(hashlib, hashmethod)(tbscert.dump()).digest(),
        }
    )

    params = {"label": "RSAkey", "objtype": "PUBLIC_KEY"}
    pk = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0]
    bits = pk["MODULUS_BITS"]

    params = {
        "label": "RSAkey",
        "objtype": "PRIVATE_KEY",
        "data": b64encode(hashasn1.dump()).decode(),
        "mechanism": "RSA_PKCS",
        "hashmethod": hashmethod,
    }

    signedcertparams = {
        "tbs_certificate": tbscert,
        "signature_algorithm": signature_alg,
        "signature_value": _sign(client, module, slot, params, bits)
    }
    return asn1crypto.x509.Certificate(signedcertparams)

def gencert(client, module, slot, method, asn1publickey):
    signature_alg = {"algorithm": method}
    certcontent = tests.certgen.certgen(
        f"rsaroottestcert-{method}", asn1publickey, signature_alg
    )
    rootcert = makecert(client, module, slot, signature_alg, certcontent)

    certcontent = tests.certgen.certgen(
        f"rsaleaf-testcert-{method}", asn1publickey, signature_alg, rootcert
    )
    leafcert = makecert(client, module, slot, signature_alg, certcontent)

    writecert(client, module, slot, rootcert, "root", method)
    writecert(client, module, slot, leafcert, "leaf", method)

def writecert(client, module, slot, cert, node, method):
    finalcertpem = asn1crypto.pem.armor("CERTIFICATE", cert.dump())
    with open(f"tests/test-{node}-cert-rsa-{method}.pem", "wb") as file:
        file.write(finalcertpem)
    params = {
        "label": f"RSA{node}-cert-{method}",
        "pem": True,
        "data": b64encode(finalcertpem).decode(),
    }
    stored = client.post(f"/hsm/{module}/{slot}/import", json=params).json()
    assert len(stored["objects"][0]["CHECK_VALUE"]) == 6, "ED certificate store error"


def test_default(client, module, slot):
    params = {"label": "RSAkey", "objtype": "PUBLIC_KEY"}
    pk = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0]
    bits = pk["MODULUS_BITS"]
    publickey = pk["publickey"]
    asn1publickey = asn1crypto.keys.PublicKeyInfo(
        {
            "algorithm": {"algorithm": "rsa"},
            "public_key": asn1crypto.keys.RSAPublicKey.load(
                asn1crypto.pem.unarmor(publickey.encode())[2]
            )
        }
    )

    for method in [
        "md5_rsa",
        "sha1_rsa",
        "sha224_rsa",
        "sha256_rsa",
        "sha384_rsa",
        "sha512_rsa",
    ]:
        gencert(client, module, slot, method, asn1publickey)
