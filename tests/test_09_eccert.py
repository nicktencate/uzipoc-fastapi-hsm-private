import hashlib
from base64 import b64encode, b64decode

import asn1crypto.pem

import tests.certgen

def _sign(client, module, slot, params):
    resp = client.post(f"/hsm/{module}/{slot}/sign", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    signature = resp["result"]
    assert len(b64decode(signature)) > 64, "Length error EC sign"
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

    params = {
        "label": "ECkey",
        "objtype": "PRIVATE_KEY",
        "data": b64encode(
            getattr(hashlib, hashmethod)(tbscert.dump()).digest()
        ).decode(),
        "mechanism": "ECDSA",
    }

    signedcertparams = {
        "tbs_certificate": tbscert,
        "signature_algorithm": signature_alg,
        "signature_value": _sign(client, module, slot, params)
    }
    return asn1crypto.x509.Certificate(signedcertparams)

def gencert(client, module, slot, method, asn1publickey):
    signature_alg = {"algorithm": method}
    certcontent = tests.certgen.certgen(
        f"ecroottestcert-{method}", asn1publickey, signature_alg
    )
    rootcert = makecert(client, module, slot, signature_alg, certcontent)

    certcontent = tests.certgen.certgen(
        f"ecleaf-testcert-{method}", asn1publickey, signature_alg, rootcert
    )
    leafcert = makecert(client, module, slot, signature_alg, certcontent)

    writecert(client, module, slot, rootcert, "root", method)
    writecert(client, module, slot, leafcert, "leaf", method)

def writecert(client, module, slot, cert, node, method):
    finalcertpem = asn1crypto.pem.armor("CERTIFICATE", cert.dump())
    with open(f"tests/test-{node}-cert-ec-{method}.pem", "wb") as file:
        file.write(finalcertpem)
    params = {
        "label": f"EC{node}-cert-{method}",
        "pem": True,
        "data": b64encode(finalcertpem).decode(),
    }
    stored = client.post(f"/hsm/{module}/{slot}/import", json=params).json()
    assert len(stored["objects"][0]["CHECK_VALUE"]) == 6, "ED certificate store error"


def test_default(client, module, slot):
    params = {
        "label": "ECkey",
        "objtype": "PUBLIC_KEY",
    }
    publickey = (
        client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0]["publickey"].encode()
    )
    asn1publickey = asn1crypto.keys.PublicKeyInfo.load(
        asn1crypto.pem.unarmor(publickey)[2]
    )

    for method in ["sha1_ecdsa", "sha224_ecdsa", "sha256_ecdsa", "sha512_ecdsa"]:
        gencert(client, module, slot, method, asn1publickey)
