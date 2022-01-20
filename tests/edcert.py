import base64
import codecs

import asn1crypto.pem
import asn1crypto.keys
import asn1crypto.algos

import tests.certgen
import tests.asn1patches


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
        params = {
            "label": "EDcert",
            "pem": True,
            "data": base64.b64encode(finalcertpem).decode(),
        }
        assert (
            len(
                session.post(baseurl + "/import", json=params).json()["objects"][0][
                    "CHECK_VALUE"
                ]
            )
            == 6
        ), "ED certificate store error"

    return True