from base64 import b64encode, b64decode
import asn1crypto.core
import nacl.public
import nacl.hash
from tests.hsalsa import hsalsa20

# How to use libsodium with a HSM :) (box and sealbox)


def test_box(client, module, slot):  # pylint: disable=too-many-locals
    if (
        not "EC_EDWARDS_KEY_PAIR_GEN"
        in client.get(f"/hsm/{module}/{slot}").json()["mechanisms"]
    ):
        return

    message = b"Hey dit is stoer"

    params = {"label": "X25519key", "objtype": "PUBLIC_KEY"}
    pk = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0][
        "EC_POINT"
    ]
    publickey = asn1crypto.core.load(bytes.fromhex(pk)).native

    hsmpub = nacl.public.PublicKey(publickey)

    naclkey = nacl.public.PrivateKey.generate()

    naclbox = nacl.public.Box(naclkey, hsmpub)

    # this is what a normal client would do to encrypt
    encrypted = naclbox.encrypt(message)

    # yes, we do need to know the other party for a box
    naclpub = naclkey.public_key.encode()

    params = {
        "label": "X25519key",
        "objtype": "PRIVATE_KEY",
        "otherpub": b64encode(naclpub).decode(),
        "size": nacl.bindings.crypto_box_PUBLICKEYBYTES * 8,
        "data": "",
        "mechanism": "ECDH1_DERIVE",
    }
    derivedkey = b64decode(
        client.post(f"/hsm/{module}/{slot}/derive", json=params).json()["result"]
    )
    sodiumkey = hsalsa20(derivedkey)

    assert sodiumkey == naclbox._shared_key  # pylint: disable=protected-access

    # Yes, loaded with random keys, because it will be overwritten with info from the HSM
    boxje = nacl.public.Box(
        nacl.public.PrivateKey.generate(), nacl.public.PrivateKey.generate().public_key
    )
    boxje._shared_key = sodiumkey  # pylint: disable=protected-access

    assert boxje.decrypt(encrypted) == message


def test_sealbox(client, module, slot):  # pylint: disable=too-many-locals
    if (
        not "EC_EDWARDS_KEY_PAIR_GEN"
        in client.get(f"/hsm/{module}/{slot}").json()["mechanisms"]
    ):
        return
    message = b"Hey dit is stoer"

    params = {"label": "X25519key", "objtype": "PUBLIC_KEY"}
    pk = client.post(f"/hsm/{module}/{slot}", json=params).json()["objects"][0][
        "EC_POINT"
    ]
    publickey = asn1crypto.core.load(bytes.fromhex(pk)).native

    hsmpub = nacl.public.PublicKey(publickey)

    sbox = nacl.public.SealedBox(hsmpub)
    sealencrypted = sbox.encrypt(message)

    sealpub = sealencrypted[: nacl.bindings.crypto_box_PUBLICKEYBYTES]

    params = {
        "label": "X25519key",
        "objtype": "PRIVATE_KEY",
        "otherpub": b64encode(sealpub).decode(),
        "size": nacl.bindings.crypto_box_PUBLICKEYBYTES * 8,
        "data": "",
        "mechanism": "ECDH1_DERIVE",
    }
    sealderivedkey = b64decode(
        client.post(f"/hsm/{module}/{slot}/derive", json=params).json()["result"]
    )
    sealsodiumkey = hsalsa20(sealderivedkey)

    unsealboxje = nacl.public.Box(
        nacl.public.PrivateKey.generate(), nacl.public.PrivateKey.generate().public_key
    )
    unsealboxje._shared_key = sealsodiumkey  # pylint: disable=protected-access

    unsealnonce = nacl.hash.blake2b(
        sealpub + publickey, unsealboxje.NONCE_SIZE, encoder=nacl.encoding.RawEncoder
    )

    todecrypt = unsealnonce + sealencrypted[hsmpub.SIZE :]
    assert unsealboxje.decrypt(todecrypt) == message
