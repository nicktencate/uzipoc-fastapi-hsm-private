import hashlib
from base64 import b64encode, b64decode
import codecs

import asn1crypto.pem

import tests.certgen

import tests.asn1patches

def _sign(client, module, slot, params):
    resp = client.post(f"/hsm/{module}/{slot}/sign", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    signature = resp["result"]
    assert len(b64decode(signature)) == 64, "Length error ED sign"
    return b64decode(signature)


def makecert(client, module, slot, signature_alg, certcontent):
    tbscert = asn1crypto.x509.TbsCertificate(certcontent)

    params = {
        "label": "ED25519key",
        "objtype": "PRIVATE_KEY",
        "data": b64encode(tbscert.dump()).decode(),
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
        f"edroottestcert-{method}", asn1publickey, signature_alg
    )
    rootcert = makecert(client, module, slot, signature_alg, certcontent)

    certcontent = tests.certgen.certgen(
        f"edleaf-testcert-{method}", asn1publickey, signature_alg, rootcert
    )
    leafcert = makecert(client, module, slot, signature_alg, certcontent)

    writecert(client, module, slot, rootcert, "root", method)
    writecert(client, module, slot, leafcert, "leaf", method)

def writecert(client, module, slot, cert, node, method):
    finalcertpem = asn1crypto.pem.armor("CERTIFICATE", cert.dump())
    with open(f"tests/test-{node}-cert-ec-{method}.pem", "wb") as file:
        file.write(finalcertpem)
    params = {
        "label": f"ED{node}-cert-{method}",
        "pem": True,
        "data": b64encode(finalcertpem).decode(),
    }
    stored = client.post(f"/hsm/{module}/{slot}/import", json=params).json()
    assert len(stored["objects"][0]["CHECK_VALUE"]) == 6, "ED certificate store error"


def test_default(client, module, slot):
    params = {
        "label": "ED25519key",
        "objtype": "PUBLIC_KEY",
    }
    publickey = (
        client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0]["EC_POINT"].encode()
    )
    tests.asn1patches.switchcallback()
    asn1publickey = asn1crypto.keys.PublicKeyInfo(
        {
            "algorithm": {"algorithm": "ed25519"},
            "public_key": asn1crypto.core.load(codecs.decode(publickey, "hex")).native,
        }
    )

    for method in ["ed25519"]:
        gencert(client, module, slot, method, asn1publickey)
    tests.asn1patches.switchcallback()
