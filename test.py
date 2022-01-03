#!/usr/bin/env python3
import hashlib
import codecs
import pkcs11
from pkcs11 import Mechanism
from Crypto.PublicKey import RSA
from Crypto.Util import number
from asn1crypto import core
from asn1crypto.algos import DigestAlgorithm, DigestAlgorithmId
from asn1crypto.tsp import MessageImprint
lib = pkcs11.lib('/usr/lib64/pkcs11/libsofthsm2.so')
token = lib.get_token(token_label='HSM-000')
session = token.open(rw=True, user_pin='1234')
priv, pub = list(session.get_objects(attrs={pkcs11.Attribute.LABEL: 'RSA-1'}))
pubkey = RSA.importKey(open('public.key','r').read())
message = b"Hello world"
hashstr = MessageImprint({'hash_algorithm': DigestAlgorithm({'algorithm': DigestAlgorithmId.unmap('sha256')}), 
                          'hashed_message': hashlib.sha256(message).digest()})
verf = number.long_to_bytes(pow(number.bytes_to_long(priv.sign(hashstr.dump(),mechanism=Mechanism.RSA_PKCS)),pubkey.e,pubkey.n))
verf2 = number.long_to_bytes(pow(number.bytes_to_long(priv.sign(message,mechanism=Mechanism.SHA256_RSA_PKCS)),pubkey.e,pubkey.n))
seq2 = core.load(verf2[verf2.index(b'\x00')+1:])
h = MessageImprint.load(verf2[verf2.index(b'\x00')+1:])
print(codecs.encode(verf[verf.index(b'\x00')+1:],'hex'))
print(codecs.encode(verf2[verf2.index(b'\x00')+1:],'hex'))
print(hashstr)
print(h)
print(h['hash_algorithm']['algorithm'].native, codecs.encode(h['hashed_message'].native,'hex'))
print('sha256', codecs.encode(seq2.native['1'],'hex'))

psigenc = codecs.decode("B0448693D7DBF281F83ECCD8EE831EA859F4D0FC587457F5B1D6EFB5F0EC9002FCFCED8465B00E15A84D4F692F0C977A5E7614B9B2B21EC3C84F10CA5EFFA50EB2514ED940AE5CE84D09FC40C85C574428AC739579C689C12BE67EFB517855FF2D48AB556D4724F75C87107DABB22DC3EE904CCEB77840A48589E208B17E406C43A580F78CEF05B85D28B2F5211733D49A00287C86133FECD19FB6CDE1699004D50401420B30060383A117EBFB0266DD21E80D4DE89D10B53CA4B6086EFDA16290E5ED14BAEFDB72F39B1CDA742B4F50ED6BBD1945909188F2BF5173481419CFD7862DF8B79D5F2C3B3C035A58D6FF0810CA29F049D4D39BE8E99D424E6DFA82","hex")
psig = number.long_to_bytes(pow(number.bytes_to_long(psigenc),pubkey.e,pubkey.n))
sha = hashlib.sha256()
digestsize = sha.digest_size

from Crypto.Util.number import ceil_shift, ceil_div, long_to_bytes
import Crypto.Util.number

pubkeysize = Crypto.Util.number.size(pubkey.n)

k = ceil_div(pubkeysize,8)

assert len(psig) == k

emLen = ceil_div(pubkeysize-1,8)
print(emLen)

print(psig)
psig = b'\x00'*(emLen-len(psig)) + psig
print(psig)

# EMSA_PSS_VERIFY(mhash, em, modBits-1, mgf, sLen)

#psig = priv.sign(message,mechanism=Mechanism.SHA1_RSA_PKCS_PSS,mechanism_param=(Mechanism.SHA_1,pkcs11.MGF.SHA1,20))

from Crypto.Hash import SHA
import Crypto.Signature.PKCS1_PSS

def retsalt(len):
    return  b'\x1f\x1f+\xb8:\xb9J3\x99\xfb\xb7\xe6C\xa8~\xcem\xa4\xa3v'

npsig = Crypto.Signature.PKCS1_PSS.EMSA_PSS_ENCODE(SHA.new(message),2047,retsalt,lambda x,y: Crypto.Signature.PKCS1_PSS.MGF1(x,y,SHA.new()),20)
signed_npsig = priv.sign(npsig,mechanism=Mechanism.RSA_X_509)


psig = b'\xa9\xb6\xf6~q\xfa+Z\x98C\xdd\xa0\xd9\x0e+\xc3w\xa6\xa8\xe9W,\xc2\xd4\x07\xc8\x84\xee{\xac\x19`\xe2e\x87\xc2\xe5\xf1\xfa\x802\xb4\x8d\x0c\xd7M\xe7l\x046h\xa2h\xfa\xbf\x97|=\x18\x14^\xd8\x86\xda^e\xbcG\x88B\xa8\xe6\xd2\xb1H\xbe\xf7\\;[\xbfS,\x86\x1d\xd7\x98\xaeo\xe9N\x83\xf4\xdb\xc0\x80\x05\x99itCH\xbf\x01\xd1\xa7\xf6\xc1\x0c\xd1\x857\xc4\x84\xb5\x0e\x86\x8f\xc9\xde\x11+6\x94\x8e\xaf\xe7\xb8\x99\x0fED\\R\x8e\xa9\x1e\x18V+\xc1|\t(\x83I\xf8\xe0E\x84\xe8[\x05\xbc\x9f.\xc6d\xc9\xd4DQ\x8c@\xf0\xa3\x88\xa60\xbb\xbb\xaa\xa1]\x07\xbc\xf6\xda\x8fJ\x12\x96\x1f\xb6cZ\xe0\xabF\xb0*\x915\x9c\xa1\x847\xbc\x8b/\xef\x84\xb7\xa4&YS-\xd1Q\xdfD\xf51\xf5\x99\x1b\xb1\xa2Q\x82`\x02\x90\xd2xv\xe2\xec\x8aZ\x92]\x1eE\xb8\xe3ya\x02\xd7\xae\xc7w\x19\xcc\x87\xef\xca\x16|y\xf2qj\x8e'
print("NPSIG =    ",npsig)
print("FromHSM  = ", number.long_to_bytes(pow(number.bytes_to_long(psig),pubkey.e,pubkey.n)))
print("FromHSM2 = ", number.long_to_bytes(pow(number.bytes_to_long(signed_npsig),pubkey.e,pubkey.n)))
print("HSM Verified",pub.verify(message,psig,mechanism=Mechanism.SHA1_RSA_PKCS_PSS,mechanism_param=(Mechanism.SHA_1,pkcs11.MGF.SHA1,20)))
print("HSM Verified (manual made)",pub.verify(message,signed_npsig,mechanism=Mechanism.SHA1_RSA_PKCS_PSS,mechanism_param=(Mechanism.SHA_1,pkcs11.MGF.SHA1,20)))
print("===== MANUAL ======")
print("Manual Verified", Crypto.Signature.PKCS1_PSS.EMSA_PSS_VERIFY(SHA.new(message),npsig,2047,lambda x,y: Crypto.Signature.PKCS1_PSS.MGF1(x,y,SHA.new()),20))
print("Manual Verified (manual made)", Crypto.Signature.PKCS1_PSS.EMSA_PSS_VERIFY(SHA.new(message),signed_npsig,2047,lambda x,y: Crypto.Signature.PKCS1_PSS.MGF1(x,y,SHA.new()),20))
print("===== /MANUAL ======")
h = SHA.new(b'Hello World')
verifier = Crypto.Signature.PKCS1_PSS.new(pubkey)
verifier.verify(h, psig)
exit()

print("============ NEW ==============")
print(psig)
from Crypto.Signature.PKCS1_PSS import PSS_SigScheme


#print(h)
#pss = PSS_SigScheme(pubkey, h, psig)
#print(pss)
#pss.verify(hashlib.sha256(message).digest(), psig)

#pubkey.verify(h.digest(),psig)
