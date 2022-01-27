from base64 import b64decode, b64encode
import asn1crypto.pem
import asn1crypto.cms

import tests.asn1patches

from Crypto.Cipher import AES

import pprint
def test_decrypt(client, module, slot):
    der = asn1crypto.pem.unarmor(open("tests/cms-encrypted-sha256_ecdsa.pem","rb").read())[2]
    cms = asn1crypto.cms.ContentInfo.load(der)


    ri = cms['content']['recipient_infos'][0].parse()
    enctype = ri['originator'].parse()['algorithm']['algorithm'].native
    if enctype == 'ec':
        publickey = ri['originator'].parse()['public_key'].native
        kek_alg = ri['key_encryption_algorithm']['algorithm'].native
        kek_aestype = ri['key_encryption_algorithm']['parameters']['algorithm'].native
        kek = ri['recipient_encrypted_keys'][0]['encrypted_key'].native
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

        eci = cms['content']['encrypted_content_info']
        encmethod = eci['content_encryption_algorithm']['algorithm'].native
        iv = eci['content_encryption_algorithm']['parameters'].native
        enccontent = eci['encrypted_content'].native
        pprint.pprint([encmethod, iv, enccontent])
        cipher = AES.new(aeskey, AES.MODE_CBC, iv)
        padded = cipher.decrypt(enccontent)
        padlen = padded[-1]
        decrypted = padded[:-padlen]
        assert decrypted == 'test42424242\r\n'

    assert False
