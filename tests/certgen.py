import random
import datetime
import hashlib

import asn1crypto.x509


def certgen(name, asn1publickey, signature_alg):
    not_before = datetime.datetime.now().astimezone()
    not_after = not_before.replace(not_before.year + 1)
    publickey_tohash = (
        asn1publickey.dump()
        if asn1publickey["algorithm"]["algorithm"].native == "rsa"
        else asn1publickey["public_key"].native
    )
    newcertcontent = {
        "version": "v3",
        "serial_number": random.randint(a=2 ** 64, b=2 ** 65 - 1),
        "signature": signature_alg,
        "issuer": asn1crypto.x509.Name.build({"common_name": name}),
        "validity": {
            "not_before": {"utc_time": not_before},
            "not_after": {"utc_time": not_after},
        },
        "subject": asn1crypto.x509.Name.build({"common_name": name}),
        "subject_public_key_info": asn1publickey,
        "extensions": [
            {
                "extn_id": "key_identifier",
                "critical": False,
                "extn_value": hashlib.sha1(publickey_tohash).digest(),
            },
            {
                "extn_id": "authority_key_identifier",
                "critical": False,
                "extn_value": {
                    "key_identifier": hashlib.sha1(publickey_tohash).digest(),
                    "authority_cert_issuer": None,
                    "authority_cert_serial_number": None,
                },
            },
            {
                "extn_id": "basic_constraints",
                "critical": True,
                "extn_value": {
                    "ca": True,
                    "path_len_constraint": None,
                },
            },
        ],
    }
    return newcertcontent
