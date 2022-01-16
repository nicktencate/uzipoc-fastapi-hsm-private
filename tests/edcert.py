import base64
import codecs

import asn1crypto.pem
import asn1crypto.keys
import asn1crypto.algos

import tests.certgen

# default asn1crypto does not know about. development on github version knows
asn1crypto.keys.PublicKeyAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.110"
] = "x25519"
asn1crypto.keys.PublicKeyAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.111"
] = "x448"
asn1crypto.keys.PublicKeyAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.112"
] = "ed25519"
asn1crypto.keys.PublicKeyAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.113"
] = "ed448"
asn1crypto.algos.SignedDigestAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.112"
] = "ed25519"
asn1crypto.algos.SignedDigestAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.113"
] = "ed448"
asn1crypto.algos.SignedDigestAlgorithmId._reverse_map[  # pylint: disable=protected-access
    "ed25519"
] = "1.3.101.112"
asn1crypto.algos.SignedDigestAlgorithmId._reverse_map[  # pylint: disable=protected-access
    "ed448"
] = "1.3.101.113"
asn1crypto.keys.PublicKeyInfo._spec_callbacks = None  # pylint: disable=protected-access


def test(session, baseurl):
    params = {
        "label": "ED25519key",
        "objtype": "PUBLIC_KEY",
    }
    publickey = (
        session.post(baseurl, json=params).json()["objects"][0]["EC_POINT"].encode()
    )
    asn1publickey = asn1crypto.keys.PublicKeyInfo(
        {
            "algorithm": {"algorithm": "ed25519"},
            "public_key": asn1crypto.core.load(codecs.decode(publickey, "hex")).native,
        }
    )

    for method in ["ed25519"]:
        print(f"Certificate with: {method}")
        signature_alg = {"algorithm": method}

        newcertcontent = tests.certgen.certgen(
            "edtestcert", asn1publickey, signature_alg
        )
        tbscert = asn1crypto.x509.TbsCertificate(newcertcontent)

        params = {
            "label": "ED25519key",
            "objtype": "PRIVATE_KEY",
            "data": base64.b64encode(tbscert.dump()).decode(),
        }
        signature = base64.b64decode(
            session.post(baseurl + "/sign", json=params).json()["result"]
        )
        signedcertparams = {
            "tbs_certificate": tbscert,
            "signature_algorithm": signature_alg,
            "signature_value": signature,
        }
        finalcert = asn1crypto.x509.Certificate(signedcertparams)

        finalcertpem = asn1crypto.pem.armor("CERTIFICATE", finalcert.dump())
        with open(f"tests/test-cert-ed-{method}.pem", "wb") as file:
            file.write(finalcertpem)
    return True
