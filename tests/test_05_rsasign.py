from base64 import b64encode, b64decode
import hashlib

import asn1crypto.tsp

from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Util import number
import Crypto.Hash.SHA
import Crypto.Hash.SHA224
import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512

HasherToCryptoHash = {
    "sha1": Crypto.Hash.SHA,
    "sha224": Crypto.Hash.SHA224,
    "sha256": Crypto.Hash.SHA256,
    "sha384": Crypto.Hash.SHA384,
    "sha512": Crypto.Hash.SHA512,
}


def _sign(client, module, slot, params, bits):
    resp = client.post(f"/hsm/{module}/{slot}/sign", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    signature = resp["result"]
    assert len(b64decode(signature)) == bits / 8, "Length error RSA sign"
    return signature


def _verify(client, module, slot, params):
    resp = client.post(f"/hsm/{module}/{slot}/verify", json=params).json()
    assert resp["module"] == module
    assert resp["slot"] == slot
    verification = resp["result"]
    return verification


def test_default(client, module, slot):
    message = b"Hallo wereld"

    params = {"label": "RSAkey", "objtype": "PUBLIC_KEY"}
    pk = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0]
    bits = pk["MODULUS_BITS"]

    params = {
        "label": "RSAkey",
        "objtype": "PRIVATE_KEY",
        "data": b64encode(message).decode(),
    }

    params = {
        "label": "RSAkey",
        "objtype": "PUBLIC_KEY",
        "data": b64encode(message).decode(),
        "signature": _sign(client, module, slot, params, bits),
    }
    assert _verify(client, module, slot, params)


def test_pkcs(client, module, slot):
    message = b"Hallo wereld"
    params = {"label": "RSAkey", "objtype": "PUBLIC_KEY"}
    pk = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0]
    bits = pk["MODULUS_BITS"]
    publickey = pk["publickey"]

    mechanisms = [
        mechanism
        for mechanism in client.get(f"/hsm/{module}/{slot}").json()["mechanisms"]
        if mechanism.startswith("SHA") and mechanism.endswith("_RSA_PKCS")
    ]
    params = {}
    signature = None
    for mech in mechanisms:
        params = {
            "label": "RSAkey",
            "objtype": "PRIVATE_KEY",
            "data": b64encode(message).decode(),
            "mechanism": mech,
        }
        signature = _sign(client, module, slot, params, bits)

        params = {
            "label": "RSAkey",
            "objtype": "PUBLIC_KEY",
            "data": b64encode(message).decode(),
            "mechanism": mech,
            "signature": signature,
        }
        assert _verify(client, module, slot, params)

        hasher = getattr(hashlib, mech[: mech.index("_")].lower())
        pubkey = RSA.importKey(publickey)
        psig = number.long_to_bytes(
            pow(number.bytes_to_long(b64decode(signature)), pubkey.e, pubkey.n)
        )
        signedhash = psig[psig.index(b"\x00") + 1 :]
        assert (
            asn1crypto.tsp.MessageImprint().load(signedhash)["hashed_message"].native
            == hasher(message).digest()
        )


# in this function the signer does not receive the data,
# it does receive the constructed hash1asn message that needs to be signed.
# the verifier does receive the whole message and the hashing is done by the HSM
# this is deliberately different to show and test how it works.
def test_pkcshash(client, module, slot):
    message = b"Hallo wereld"
    params = {"label": "RSAkey", "objtype": "PUBLIC_KEY"}
    pk = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0]
    bits = pk["MODULUS_BITS"]

    mechanisms = [
        mechanism
        for mechanism in client.get(f"/hsm/{module}/{slot}").json()["mechanisms"]
        if mechanism.startswith("SHA") and mechanism.endswith("_RSA_PKCS")
    ]
    params = {}
    for mech in mechanisms:
        hashmethod = mech[: mech.index("_")].lower()
        hashasn1 = asn1crypto.tsp.MessageImprint(
            {
                "hash_algorithm": {"algorithm": hashmethod},
                "hashed_message": HasherToCryptoHash[hashmethod].new(message).digest(),
            }
        )
        params = {
            "label": "RSAkey",
            "objtype": "PRIVATE_KEY",
            "data": b64encode(hashasn1.dump()).decode(),
            "mechanism": mech[mech.index("_") + 1 :],
            "hashmethod": hashmethod,
        }

        params = {
            "label": "RSAkey",
            "objtype": "PUBLIC_KEY",
            "data": b64encode(message).decode(),
            "mechanism": mech,
            "signature": _sign(client, module, slot, params, bits),
        }
        assert _verify(client, module, slot, params)


def test_pss(client, module, slot):
    message = b"Hallo wereld"
    params = {"label": "RSAkey", "objtype": "PUBLIC_KEY"}
    pk = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0]
    bits = pk["MODULUS_BITS"]
    publickey = pk["publickey"]

    mechanisms = [
        mechanism
        for mechanism in client.get(f"/hsm/{module}/{slot}").json()["mechanisms"]
        if mechanism.startswith("SHA") and mechanism.endswith("_RSA_PKCS_PSS")
    ]
    for mech in mechanisms:
        hashmethod = mech[: mech.index("_")].lower()

        params = {
            "label": "RSAkey",
            "objtype": "PRIVATE_KEY",
            "data": b64encode(message).decode(),
            "mechanism": mech,
            "hashmethod": hashmethod,
        }
        signature = _sign(client, module, slot, params, bits)

        params = {
            "label": "RSAkey",
            "objtype": "PUBLIC_KEY",
            "data": b64encode(message).decode(),
            "mechanism": mech,
            "signature": signature,
            "hashmethod": hashmethod,
        }
        assert _verify(client, module, slot, params)

        pubkey = RSA.importKey(publickey)
        psig = number.long_to_bytes(
            pow(number.bytes_to_long(b64decode(signature)), pubkey.e, pubkey.n)
        )
        CryptoHash = HasherToCryptoHash[hashmethod]
        assert (
            pss._EMSA_PSS_VERIFY(
                CryptoHash.new(message),
                psig,
                bits - 1,
                lambda x, y: pss.MGF1(
                    x, y, CryptoHash.new()  # pylint: disable=cell-var-from-loop
                ),
                CryptoHash.digest_size,
            )
            is None
        ), "Non-HSM verify error"


def test_pss_hash(client, module, slot):
    message = b"Hallo wereld"
    params = {"label": "RSAkey", "objtype": "PUBLIC_KEY"}
    pk = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0]
    bits = pk["MODULUS_BITS"]

    mechanisms = [
        mechanism
        for mechanism in client.get(f"/hsm/{module}/{slot}").json()["mechanisms"]
        if mechanism.startswith("SHA") and mechanism.endswith("_RSA_PKCS_PSS")
    ]
    for mech in mechanisms:
        hashmethod = mech[: mech.index("_")].lower()
        params = {
            "label": "RSAkey",
            "objtype": "PRIVATE_KEY",
            "data": b64encode(
                HasherToCryptoHash[hashmethod].new(message).digest()
            ).decode(),
            "mechanism": mech[mech.index("_") + 1 :],
            "hashmethod": hashmethod,
        }
        params = {
            "label": "RSAkey",
            "objtype": "PUBLIC_KEY",
            "data": b64encode(message).decode(),
            "mechanism": mech,
            "signature": _sign(client, module, slot, params, bits),
            "hashmethod": hashmethod,
        }
        assert _verify(client, module, slot, params)


# in this function the signer does not receive the data,
# it does receive the constructed hash1asn message that needs to be signed.
# the verifier does receive the whole message and the hashing is done by the HSM
# this is deliberately different to show and test how it works.
# The difference with the PKCS and PSS methods is that there is not need
# to pack the hash into a structure, since PSS has an inherent checking function
# for length.


def test_pss_hashext(client, module, slot):
    message = b"Hallo wereld"
    params = {"label": "RSAkey", "objtype": "PUBLIC_KEY"}
    pk = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0]
    bits = pk["MODULUS_BITS"]

    mechanisms = [
        mechanism
        for mechanism in client.get(f"/hsm/{module}/{slot}").json()["mechanisms"]
        if mechanism.startswith("SHA") and mechanism.endswith("_RSA_PKCS_PSS")
    ]
    for mech in mechanisms:
        hashmethod = mech[: mech.index("_")].lower()
        CryptoHash = HasherToCryptoHash[hashmethod]
        with open("/dev/urandom", "rb") as randfile:
            rawencoded = pss._EMSA_PSS_ENCODE(
                CryptoHash.new(message),
                bits - 1,
                randfile.read,
                lambda x, y: pss.MGF1(
                    x, y, CryptoHash.new()  # pylint: disable=cell-var-from-loop
                ),
                CryptoHash.digest_size,
            )

        params = {
            "label": "RSAkey",
            "objtype": "PRIVATE_KEY",
            "data": b64encode(rawencoded).decode(),
            "mechanism": "RSA_X_509",
        }

        params = {
            "label": "RSAkey",
            "objtype": "PUBLIC_KEY",
            "data": b64encode(message).decode(),
            "mechanism": mech,
            "signature": _sign(client, module, slot, params, bits),
            "hashmethod": hashmethod,
        }
        assert _verify(client, module, slot, params)
