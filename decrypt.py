#!/usr/bin/env python3
import hashlib
import codecs
import pkcs11
from pkcs11 import Mechanism
import pkcs11.util.ec
from asn1crypto import core
from asn1crypto.algos import DigestAlgorithm, DigestAlgorithmId
from asn1crypto.tsp import MessageImprint
import asn1crypto, asn1crypto.pem, asn1crypto.cms, pprint
import yaml

with open('conf.yml', 'r', encoding='utf-8') as yamlfile:
    config = yaml.load(yamlfile ,Loader=yaml.Loader)



lib = pkcs11.lib(config['modules'][0]['module'])
token = lib.get_token(token_label=config['modules'][0]['slots'][0]['slot'])
session = token.open(rw=True, user_pin=open(config['modules'][0]['slots'][0]['pinfile'],'r').read().rstrip())
rsapriv = list(session.get_objects( attrs={ pkcs11.Attribute.LABEL: "testkeyhsm", pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY }))[0]
ec_prv = list(session.get_objects({pkcs11.Attribute.LABEL: 'newec', pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY}))[0]
#import pkcs11.util.ec
#parameters = session.create_domain_parameters(pkcs11.KeyType.EC, {pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters('secp256r1')}, local=True)
#public, private = parameters.generate_keypair()


cms = asn1crypto.cms.ContentInfo().load(asn1crypto.pem.unarmor(open('msg.enc','rb').read())[2]).native['content']
ri = cms['recipient_infos']
enc = cms['encrypted_content_info']
rsa_enc = ri[0]
ec_enc = ri[1]
pprint.pprint(rsa_enc, width=180)
pprint.pprint(ec_enc, width=180)



rsa_enckey = rsa_enc['encrypted_key']

aeskey = rsapriv.decrypt(rsa_enckey, mechanism=pkcs11.Mechanism.RSA_PKCS)

ec_otherpub = ec_enc['originator']['public_key']
ridkey = ec_enc['recipient_encrypted_keys'][0]['encrypted_key']
ec_crypted_key = ec_enc['recipient_encrypted_keys'][0]['encrypted_key']

#newaes = ec_prv.derive_key(pkcs11.KeyType.AES, 128, mechanism_param=(pkcs11.KDF.SHA1, None, ec_otherpub), template={ pkcs11.Attribute.SENSITIVE: False, pkcs11.Attribute.EXTRACTABLE: True})
newaes = ec_prv.derive_key(pkcs11.KeyType.AES, 256, mechanism_param=(pkcs11.KDF.NULL, None, ec_otherpub), template={ pkcs11.Attribute.SENSITIVE: False, pkcs11.Attribute.EXTRACTABLE: True})
#newaes = ec_prv.derive_key(pkcs11.KeyType.AES, 128, mechanism_param=(pkcs11.KDF.SHA1, None, ec_otherpub))
#newaes = ec_prv.derive_key(pkcs11.KeyType.AES, 128, mechanism_param=(pkcs11.KDF.SHA1_CONCATENATE, ec_crypted_key, ec_otherpub), template={ pkcs11.Attribute.SENSITIVE: False, pkcs11.Attribute.EXTRACTABLE: True})
#newaes.decrypt(ec_crypted_key)
#print(ec_otherpub)
print("Deze 2:")
print("newaes ding",codecs.encode(newaes[pkcs11.Attribute.VALUE], 'hex'), "256 bits, zo doet openssl dat ook, of het 256 of 128 moet zijn...")
print("ecaes  =",len(ec_crypted_key),codecs.encode(ec_crypted_key,'hex')," 24 == wrapped key")
print("Moet worden:")
print("aeskey =",len(aeskey),codecs.encode(aeskey,'hex'))
#newaes.unwrap_key(pkcs11.ObjectClass.SECRET_KEY, pkcs11.KeyType.AES, ec_crypted_key)
