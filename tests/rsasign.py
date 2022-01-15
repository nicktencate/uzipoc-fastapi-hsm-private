from base64 import b64encode, b64decode
import hashlib

import asn1crypto.tsp

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
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


def testpkcs(
    session, baseurl, allmechanisms, bits, publickey
):  # pylint: disable=too-many-locals
    message = b"Hallo wereld"
    mechanisms = [
        mechanism
        for mechanism in allmechanisms
        if mechanism.startswith("SHA") and mechanism.endswith("_RSA_PKCS")
    ]
    params = {}
    signature = None
    for mech in mechanisms:
        print("Testing RSA sign: ", mech)
        params = {
            "label": "RSAkey",
            "objtype": "PRIVATE_KEY",
            "data": b64encode(message).decode(),
            "mechanism": mech,
        }
        signature = session.post(baseurl + "/sign", json=params).json()["result"]
        assert len(b64decode(signature)) is bits / 8, "Length error RSA encrypt"

        print("Testing RSA verify (hsm): ", mech)
        params = {
            "label": "RSAkey",
            "objtype": "PUBLIC_KEY",
            "data": b64encode(message).decode(),
            "mechanism": mech,
            "signature": signature,
        }
        decrypted = session.post(baseurl + "/verify", json=params).json()["result"]
        assert decrypted is True

        print("Testing RSA verify (external): ", mech)
        hashmethod = mech[: mech.index("_")].lower()
        hasher = getattr(hashlib, hashmethod)
        pubkey = RSA.importKey(publickey)
        psig = number.long_to_bytes(
            pow(number.bytes_to_long(b64decode(signature)), pubkey.e, pubkey.n)
        )
        signedhash = psig[psig.index(b"\x00") + 1 :]
        assert (
            asn1crypto.tsp.MessageImprint().load(signedhash)["hashed_message"].native
            is hasher(message).digest()
        )


def testpss(
    session, baseurl, allmechanisms, bits, publickey
):  # pylint: disable=too-many-locals
    message = b"Hallo wereld"
    mechanisms = [
        mechanism
        for mechanism in allmechanisms
        if mechanism.startswith("SHA") and mechanism.endswith("_RSA_PKCS_PSS")
    ]
    for mech in mechanisms:
        print("Testing RSA sign: ", mech)
        hashmethod = mech[: mech.index("_")].lower()
        params = {
            "label": "RSAkey",
            "objtype": "PRIVATE_KEY",
            "data": b64encode(message).decode(),
            "mechanism": mech,
            "hashmethod": hashmethod,
        }
        signature = session.post(baseurl + "/sign", json=params).json()["result"]
        assert len(b64decode(signature)) is bits / 8, "Length error RSA encrypt"

        print("Testing RSA verify: ", mech)
        params = {
            "label": "RSAkey",
            "objtype": "PUBLIC_KEY",
            "data": b64encode(message).decode(),
            "mechanism": mech,
            "signature": signature,
            "hashmethod": hashmethod,
        }
        decrypted = session.post(baseurl + "/verify", json=params).json()["result"]
        assert decrypted is True

        print("Testing RSA verify (external): ", mech)
        pubkey = RSA.importKey(publickey)
        psig = number.long_to_bytes(
            pow(number.bytes_to_long(b64decode(signature)), pubkey.e, pubkey.n)
        )
        CryptoHash = HasherToCryptoHash[hashmethod]
        assert (
            PKCS1_PSS.EMSA_PSS_VERIFY(
                CryptoHash.new(message),
                psig,
                4096 - 1,
                lambda x, y: PKCS1_PSS.MGF1(
                    x, y, CryptoHash.new()  # pylint: disable=cell-var-from-loop
                ),
                CryptoHash.digest_size,
            )
            is True
        ), "Non-HSM verify error"


def test(session, baseurl):

    message = b"Hallo wereld"
    params = {"label": "RSAkey", "objtype": "PUBLIC_KEY"}
    pk = session.post(baseurl, json=params).json()["objects"][0]
    bits = pk["MODULUS_BITS"]
    publickey = pk["publickey"]

    # Basic sign and verify
    # For a short message of 1 block it's MODULES_BITS long
    print("Testing RSA sign: default")
    params = {
        "label": "RSAkey",
        "objtype": "PRIVATE_KEY",
        "data": b64encode(message).decode(),
    }
    signature = session.post(baseurl + "/sign", json=params).json()["result"]
    assert len(b64decode(signature)) is bits / 8, "Length error RSA encrypt"

    print("Testing RSA verify: default")
    params = {
        "label": "RSAkey",
        "objtype": "PUBLIC_KEY",
        "data": b64encode(message).decode(),
        "signature": signature,
    }
    decrypted = session.post(baseurl + "/verify", json=params).json()["result"]
    assert decrypted is True

    allmechanisms = session.get(baseurl).json()["mechanisms"]
    testpkcs(session, baseurl, allmechanisms, bits, publickey)
    testpss(session, baseurl, allmechanisms, bits, publickey)

    return True
