#!/usr/bin/env python3
import hashlib
import codecs
import struct
import pprint
import pkcs11
from pkcs11 import Mechanism
import pkcs11.util.ec
import asn1crypto.core
import asn1crypto.cms
import asn1crypto.pem
import yaml

with open('conf.yml', 'r', encoding='utf-8') as yamlfile:
    config = yaml.load(yamlfile ,Loader=yaml.Loader)



class SharedInfo(asn1crypto.core.Sequence):
    _fields = [
        ('algorithm', asn1crypto.cms.KeyEncryptionAlgorithm),
        ('entityUInfo', asn1crypto.core.OctetString, {'explicit': 1, 'optional': True}),
        ('suppPubInfo', asn1crypto.core.OctetString, {'explicit': 2})
    ]

kea_to_KDF = { 'dhSinglePass-stdDH-sha1kdf-scheme': pkcs11.KDF.SHA1,
               'dhSinglePass-stdDH-sha224kdf-scheme': pkcs11.KDF.SHA224,
               'dhSinglePass-stdDH-sha256kdf-scheme': pkcs11.KDF.SHA256,
               'dhSinglePass-stdDH-sha384kdf-scheme': pkcs11.KDF.SHA384,
               'dhSinglePass-stdDH-sha512kdf-scheme': pkcs11.KDF.SHA512
             }


lib = pkcs11.lib(config['modules'][0]['module'])
token = lib.get_token(token_label=config['modules'][0]['slots'][0]['slot'])
session = token.open(rw=True, user_pin=open(config['modules'][0]['slots'][0]['pinfile'],'r').read().rstrip())
rsapriv = list(session.get_objects( attrs={ pkcs11.Attribute.LABEL: "testkeyhsm", pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY }))[0]
ec_prv = list(session.get_objects({pkcs11.Attribute.LABEL: 'newec', pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY}))[0]


cms = asn1crypto.cms.ContentInfo().load(asn1crypto.pem.unarmor(open('msg.enc','rb').read())[2]).native['content']
ri = cms['recipient_infos']
enc = cms['encrypted_content_info']

rsa_enc = ri[0]
ec_enc = ri[1]
pprint.pprint(rsa_enc, width=178)
pprint.pprint(ec_enc, width=178)



rsa_enckey = rsa_enc['encrypted_key']

aeskey = rsapriv.decrypt(rsa_enckey, mechanism=pkcs11.Mechanism.RSA_PKCS)

ec_otherpub = ec_enc['originator']['public_key']
ridkey = ec_enc['recipient_encrypted_keys'][0]['encrypted_key']
ec_crypted_key = ec_enc['recipient_encrypted_keys'][0]['encrypted_key']
aesalgo = asn1crypto.cms.KeyEncryptionAlgorithmId().map(ec_enc['key_encryption_algorithm']['parameters']['0'])


# Dynamisch ophalen :)
aessize = int(aesalgo[3:6])
asn1typewrap = SharedInfo({'algorithm': {'algorithm': aesalgo}, 'suppPubInfo': struct.pack(">L", aessize)}).dump()

kea = ec_enc['key_encryption_algorithm']['algorithm']
theKDF = kea_to_KDF[kea]

newaes = ec_prv.derive_key(pkcs11.KeyType.AES, aessize, mechanism_param=(theKDF, asn1typewrap, ec_otherpub))
uitvoer = newaes.unwrap_key(pkcs11.ObjectClass.SECRET_KEY, pkcs11.KeyType.AES, ec_crypted_key, template={ pkcs11.Attribute.SENSITIVE: False, pkcs11.Attribute.EXTRACTABLE: True})

print("from-rsaaeskey =",len(aeskey),codecs.encode(aeskey,'hex'))
print("from-ec-aeskey =",len(aeskey),codecs.encode(uitvoer[pkcs11.Attribute.VALUE],'hex'))
