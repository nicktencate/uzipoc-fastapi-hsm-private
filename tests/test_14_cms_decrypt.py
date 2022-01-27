from base64 import b64decode, b64encode
import os

import asn1crypto.pem
import asn1crypto.cms

from Crypto.Cipher import AES

import tests.asn1patches  # pylint: disable=unused-import


def test_decrypt(client, module, slot):
    os.system(
        'echo "test42424242" | openssl cms  -aes256 -encrypt -outform pem tests/test-leaf-cert-ec-sha256_ecdsa.pem > tests/cms-encrypted-sha256_ecdsa.pem'  # pylint: disable=line-too-long
    )
    os.system(
        'echo "test42424242" | openssl cms  -aes128 -encrypt -outform pem tests/test-leaf-cert-rsa-sha256_rsa.pem > tests/cms-encrypted-sha256_rsa.pem'  # pylint: disable=line-too-long
    )
    for file in [
        "tests/cms-encrypted-sha256_ecdsa.pem",
        "tests/cms-encrypted-sha256_rsa.pem",
    ]:
        _decrypt(client, module, slot, file)


def _decrypt(client, module, slot, file):  # pylint: disable=too-many-locals
    with open(file, "rb") as openfile:
        der = asn1crypto.pem.unarmor(openfile.read())[2]
    cms = asn1crypto.cms.ContentInfo.load(der)

    ri = cms["content"]["recipient_infos"][0].parse()
    version = ri["version"].native
    if version == "v3":
        enctype = ri["originator"].parse()["algorithm"]["algorithm"].native
        # print(enctype)
    if version == "v0":
        enctype = ri["key_encryption_algorithm"]["algorithm"].native

    if enctype == "ec":
        publickey = ri["originator"].parse()["public_key"].native
        kek_alg = ri["key_encryption_algorithm"]["algorithm"].native
        kek_aestype = ri["key_encryption_algorithm"]["parameters"]["algorithm"].native
        kek = ri["recipient_encrypted_keys"][0]["encrypted_key"].native
        params = {
            "label": "ECkey",
            "objtype": "PRIVATE_KEY",
            "otherpub": b64encode(publickey).decode(),
            "size": 256,
            "unwrap": kek_aestype,
            "data": b64encode(kek).decode(),
            "algorithm": kek_alg,
        }
        aeskey = b64decode(
            client.post(f"/hsm/{module}/{slot}/derive", json=params).json()["result"]
        )

    if enctype == "rsaes_pkcs1v15":
        ek = ri["encrypted_key"].native
        params = {
            "label": "RSAkey",
            "objtype": "PRIVATE_KEY",
            "mechanism": "RSA_PKCS",
            "data": b64encode(ek).decode(),
        }
        aeskey = b64decode(
            client.post(f"/hsm/{module}/{slot}/decrypt", json=params).json()["result"]
        )

    eci = cms["content"]["encrypted_content_info"]
    encmethod = eci["content_encryption_algorithm"]["algorithm"].native
    iv = eci["content_encryption_algorithm"]["parameters"].native
    enccontent = eci["encrypted_content"].native
    cipher = AES.new(aeskey, getattr(AES, "MODE_" + encmethod[-3:].upper()), iv)
    padded = cipher.decrypt(enccontent)
    padlen = padded[-1]
    decrypted = padded[:-padlen]
    assert decrypted == b"test42424242\r\n"
