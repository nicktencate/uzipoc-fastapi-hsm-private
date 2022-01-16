import hashlib
import base64

import asn1crypto.pem

import tests.certgen


def test(session, baseurl):  # pylint: disable=too-many-locals
    params = {
        "label": "RSAkey",
        "objtype": "PUBLIC_KEY",
    }
    publickey = (
        session.post(baseurl, json=params).json()["objects"][0]["publickey"].encode()
    )
    asn1publickey = asn1crypto.keys.PublicKeyInfo(
        {
            "algorithm": {"algorithm": "rsa"},
            "public_key": asn1crypto.keys.RSAPublicKey.load(
                asn1crypto.pem.unarmor(publickey)[2]
            ),
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
        signature_alg = {"algorithm": method}
        newcertcontent = tests.certgen.certgen(
            "rsatestcert", asn1publickey, signature_alg
        )
        tbscert = asn1crypto.x509.TbsCertificate(newcertcontent)

        hashmethod = signature_alg["algorithm"][: signature_alg["algorithm"].index("_")]

        hashasn1 = asn1crypto.tsp.MessageImprint(
            {
                "hash_algorithm": {"algorithm": hashmethod},
                "hashed_message": getattr(hashlib, hashmethod)(tbscert.dump()).digest(),
            }
        )
        params = {
            "label": "RSAkey",
            "objtype": "PRIVATE_KEY",
            "data": base64.b64encode(hashasn1.dump()).decode(),
            "mechanism": "RSA_PKCS",
            "hashmethod": hashmethod,
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
        with open(f"tests/test-cert-rsa-{method}.pem", "wb") as file:
            file.write(finalcertpem)
        params = {
            "label": "RSAcert",
            "objtype": "CERTIFICATE",
            "data": base64.b64encode(finalcertpem),
        }

    return True
