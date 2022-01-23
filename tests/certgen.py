import random
import datetime
import hashlib

import asn1crypto.x509


def certgen(name, asn1publickey, signature_alg, rootcert=False):
    not_before = datetime.datetime.now().astimezone()
    not_after = not_before.replace(not_before.year + 1)
    publickey_tohash = (
        asn1publickey.dump()
        if asn1publickey["algorithm"]["algorithm"].native == "rsa"
        else asn1publickey["public_key"].native
    )
    subject = asn1crypto.x509.Name.build({"common_name": name})
    if rootcert:
        rootkey_tohash = (
            rootcert["tbs_certificate"]["subject_public_key_info"].dump()
            if asn1publickey["algorithm"]["algorithm"].native == "rsa"
            else rootcert["tbs_certificate"]["subject_public_key_info"][
                "public_key"
            ].native
        )
        authki = hashlib.sha1(rootkey_tohash).digest()
        authsn = rootcert["tbs_certificate"]["serial_number"]
        issuer = rootcert["tbs_certificate"]["subject"]
        authci = [asn1crypto.x509.GeneralName({'directory_name': rootcert['tbs_certificate']['subject']})]
    else:
        rootkey_tohash = publickey_tohash
        authki = hashlib.sha1(publickey_tohash).digest()
        authci = None
        authsn = None
        issuer = subject
    newcertcontent = {
        "version": "v3",
        "serial_number": random.randint(a=2 ** 64, b=2 ** 65 - 1),
        "signature": signature_alg,
        "issuer": issuer,
        "validity": {
            "not_before": {"utc_time": not_before},
            "not_after": {"utc_time": not_after},
        },
        "subject": subject,
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
                    "key_identifier": authki,
                    "authority_cert_issuer": authci,
                    "authority_cert_serial_number": authsn,
                },
            },
            {
                "extn_id": "basic_constraints",
                "critical": True,
                "extn_value": {
                    "ca": not rootcert,
                    "path_len_constraint": None,
                },
            },
        ],
    }
    return newcertcontent
