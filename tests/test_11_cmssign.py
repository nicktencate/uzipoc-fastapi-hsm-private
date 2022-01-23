import datetime
import hashlib
from base64 import b64encode, b64decode

import asn1crypto.cms
import asn1crypto.tsp
import asn1crypto.pem
import asn1crypto.core
import asn1crypto.algos

import tests.asn1patches  # pylint: disable=unused-import

def test_cms_ec(client, module, slot):  # pylint: disable = too-many-locals
    message = b"Content-Type: text/plain\r\n\r\nHallow wereld\r\n"
    sd = asn1crypto.cms.SignedData()
    hashalgo = "sha256"
    digestalgo = {"algorithm": hashalgo}
    certs = []
    for certfile in [
        "tests/test-leaf-cert-ec-sha512_ecdsa.pem",
    ]:
        with open(certfile, "rb") as file:
            der = asn1crypto.pem.unarmor(file.read())[2]
            certs.append(asn1crypto.x509.Certificate().load(der))

    # en dan ook de chain voor de certificaten
    signdata = {
        "version": "v1",
        "encap_content_info": {"content_type": "data", "content": message},
        "digest_algorithms": [{"algorithm": hashalgo}],
        "certificates": certs,
        "crls": None,
        "signer_infos": [],
    }

    for cert in certs:
        keytype = cert["tbs_certificate"]["subject_public_key_info"].algorithm
        signtype = "ecdsa" if keytype == "ec" else "rsa"
        signtime = asn1crypto.cms.Time(
            {"utc_time": datetime.datetime.now().astimezone()}
        )
        mhash = getattr(hashlib, hashalgo)(message).digest()
        # No moar old shit like des, 3des and rc2
        capabilities = [
            [
                {"algorithm": algo}
                for algo in asn1crypto.algos.EncryptionAlgorithm._oid_specs  # pylint: disable=protected-access
                if algo.startswith("aes") and algo.endswith("_cbc")
            ]
        ]
        signed_attrs = [
            {"type": "content_type", "values": ["data"]},
            {"type": "signing_time", "values": [signtime]},
            {"type": "message_digest", "values": [mhash]},
            # signature_time_stamp_token => Standaard, kan via freets
            {
                "type": "1.2.840.113549.1.9.15",
                "values": capabilities,
            },
        ]
        signed_attrs = asn1crypto.cms.CMSAttributes(signed_attrs)
        thehash = getattr(hashlib, hashalgo)(signed_attrs.dump()).digest()
        # sign thehash to thesignature
        if signtype == "ecdsa":
            params = {
                "label": "ECkey",
                "objtype": "PRIVATE_KEY",
                "data": b64encode(thehash).decode(),
                "mechanism": "ECDSA",
            }
            signature = b64decode(
                client.post(f"/hsm/{module}/{slot}/sign", json=params).json()["result"]
            )
        elif signtype == "rsa":
            hashasn1 = asn1crypto.tsp.MessageImprint(
                {
                    "hash_algorithm": {"algorithm": hashalgo},
                    "hashed_message": thehash,
                }
            )
            params = {
                "label": "RSAkey",
                "objtype": "PRIVATE_KEY",
                "data": b64encode(hashasn1.dump()).decode(),
                "mechanism": "RSA_PKCS",
                "hashmethod": hashalgo,
            }
            signature = b64decode(
                client.post(f"/hsm/{module}/{slot}/sign", json=params).json()["result"]
            )

        signer_info = {
            "version": signdata["version"],
            "sid": {
                "issuer_and_serial_number": {
                    "issuer": cert["tbs_certificate"]["issuer"],
                    "serial_number": cert["tbs_certificate"]["serial_number"],
                }
            },
            "digest_algorithm": digestalgo,
            "signature_algorithm": {"algorithm": f"{hashalgo}_{signtype}"},
            "unsigned_attrs": None,
            "signed_attrs": signed_attrs,
            "signature": signature,
        }
        signer_info = asn1crypto.cms.SignerInfo(signer_info)
        signdata["signer_infos"].append(signer_info)

    sd = asn1crypto.cms.SignedData(signdata)
    asn1obj = asn1crypto.cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": sd,
        }
    )
    with open("tests/signed.cms.pem", "wb") as file:
        file.write(asn1crypto.pem.armor("CMS", asn1obj.dump()))

    return True
