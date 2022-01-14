#!/usr/bin/env python3
import codecs
import base64
import hashlib
from struct import pack

import pkcs11
import pkcs11.util
import pkcs11.util.rsa
import pkcs11.util.dsa
import pkcs11.types
from pkcs11 import Attribute
from pkcs11.util.ec import encode_named_curve_parameters

import asn1crypto.cms
import asn1crypto.core
import asn1crypto.pem
from asn1crypto.keys import ECDomainParameters


from .model import (
    HSMError,
    SearchObject,
    RSAGenParam,
    AESGenParam,
    ECGenParam,
    HashMethod,
)

class SharedInfo(asn1crypto.core.Sequence):
    _fields = [
        ('algorithm', asn1crypto.cms.KeyEncryptionAlgorithm),
        ('entityUInfo', asn1crypto.core.OctetString, {'explicit': 1, 'optional': True}),
        ('suppPubInfo', asn1crypto.core.OctetString, {'explicit': 2})
    ]

class KeyXchangeKDF:  # pylint: disable=too-few-public-methods
    @staticmethod
    def map(method: HashMethod):
        maps = { 'dhSinglePass-stdDH-sha1kdf-scheme': pkcs11.KDF.SHA1,
                 'dhSinglePass-stdDH-sha224kdf-scheme': pkcs11.KDF.SHA224,
                 'dhSinglePass-stdDH-sha256kdf-scheme': pkcs11.KDF.SHA256,
                 'dhSinglePass-stdDH-sha384kdf-scheme': pkcs11.KDF.SHA384,
                 'dhSinglePass-stdDH-sha512kdf-scheme': pkcs11.KDF.SHA512,
                 'sha1': pkcs11.KDF.SHA1,
                 'sha224': pkcs11.KDF.SHA224,
                 'sha256': pkcs11.KDF.SHA256,
                 'sha384': pkcs11.KDF.SHA384,
                 'sha512': pkcs11.KDF.SHA512
               }
        if method in maps:
            return maps[method]
        raise HSMError("Unsupported scheme")


class MethodMechanism:  # pylint: disable=too-few-public-methods
    @staticmethod
    def map(method: HashMethod):
        maps = {
            HashMethod.SHA1: pkcs11.Mechanism.SHA_1,
            HashMethod.SHA256: pkcs11.Mechanism.SHA256,
            HashMethod.SHA384: pkcs11.Mechanism.SHA384,
            HashMethod.SHA512: pkcs11.Mechanism.SHA512,
        }
        if method in maps:
            return maps[method]
        raise HSMError("Unsupported method")


class MethodMGF:  # pylint: disable=too-few-public-methods
    @staticmethod
    def map(method: HashMethod):
        maps = {
            HashMethod.SHA1: pkcs11.MGF.SHA1,
            HashMethod.SHA256: pkcs11.MGF.SHA256,
            HashMethod.SHA384: pkcs11.MGF.SHA384,
            HashMethod.SHA512: pkcs11.MGF.SHA512,
        }
        if method in maps:
            return maps[method]
        raise HSMError("Unsupported method")


class MethodSize:  # pylint: disable=too-few-public-methods
    @staticmethod
    def map(method: HashMethod):
        maps = {
            HashMethod.SHA1: hashlib.sha1().digest_size,
            HashMethod.SHA256: hashlib.sha256().digest_size,
            HashMethod.SHA384: hashlib.sha384().digest_size,
            HashMethod.SHA512: hashlib.sha512().digest_size,
        }
        if method in maps:
            return maps[method]
        raise HSMError("Unsupported method")


class HSMModule:
    modules = {}
    libs = {}

    def __init__(self, config):
        for module in config["modules"]:
            name = module["name"]
            libje = module["module"]
            self.modules[name] = {}
            slots = module["slots"]
            self._loadlib(name, libje, slots)

    def _loadlib(self, name, hsm_module, slots):
        if hsm_module not in self.libs:
            self.libs[name] = pkcs11.lib(hsm_module)
            for slot in slots:
                label = slot["slot"]
                pin = slot["pinfile"]
                token = self.libs[name].get_token(
                    token_label=label
                )  # pylint: disable=consider-using-with
                self.modules[name][label] = token.open(
                    rw=True, user_pin=open(pin, "r", encoding="utf-8").read().rstrip()
                )  # pylint: disable=consider-using-with

    def hsmlist(self):
        return list(self.modules)

    def is_module(self, modname):
        return modname in self.modules

    def is_slot(self, modname, slotname):
        return modname in self.modules and slotname in self.modules[modname]

    def list_slots(self, modname):
        return list(self.modules[modname])

    def _so_to_attr(self, so: SearchObject):
        attrs = {}
        if so.label:
            attrs[Attribute.LABEL] = so.label
        if so.objid:
            attrs[Attribute.ID] = so.objid.decode()
        if so.objtype:
            attrs[Attribute.CLASS] = getattr(pkcs11.ObjectClass, so.objtype)
        return attrs

    def _objtoobj(self, obj):
        retobj = {}
        for attr in pkcs11.Attribute:
            try:
                # print(attr, obj[attr])
                if str(attr).split(".")[1] in ["EC_PARAMS"]:
                    retobj[str(attr).split(".")[1]] = ECDomainParameters.load(
                        obj[attr]
                    ).native
                elif str(attr).split(".")[1] in [
                    "MODULUS",
                    "PUBLIC_EXPONENT",
                    "EC_POINT",
                    "PRIME",
                    "SUBPRIME",
                    "BASE"
                ]:
                    retobj[str(attr).split(".")[1]] = codecs.encode(obj[attr], "hex")
                else:
                    if obj[attr] and isinstance(obj[attr], bytes):
                        retobj[str(attr).split(".")[1]] = obj[attr].decode("utf-8")
                    elif obj[attr] is not None and "." in str(obj[attr]):
                        retobj[str(attr).split(".")[1]] = str(obj[attr]).split(".")[1]
                    elif obj[attr] is not None:
                        retobj[str(attr).split(".")[1]] = obj[attr]
            except:
                pass
        if obj.key_type == pkcs11.KeyType.RSA:
            try:
                retobj["publickey"] = asn1crypto.pem.armor(
                    "PUBLIC KEY", pkcs11.util.rsa.encode_rsa_public_key(obj)
                )
            except:
                pass
        if obj.key_type == pkcs11.KeyType.DSA:
            try:
                retobj["publickey"] = asn1crypto.pem.armor(
                    "PUBLIC KEY", pkcs11.util.dsa.encode_dsa_public_key(obj)
                )
            except:
                pass
        if (
            obj.key_type == pkcs11.KeyType.EC
            and obj.object_class == pkcs11.ObjectClass.PUBLIC_KEY
        ):
            try:
                retobj["publickey"] = asn1crypto.pem.armor(
                    "PUBLIC KEY", (pkcs11.util.ec.encode_ec_public_key(obj))
                )
            except:
                pass
        return retobj

    def gen_rsa(self, name, label, rsagen: RSAGenParam):
        public, private = self.modules[name][label].generate_keypair(
            pkcs11.KeyType.RSA, rsagen.bits, label=rsagen.label, store=True
        )
        return [self._objtoobj(obj) for obj in [public, private]]

    def gen_dsa(self, name, label, dsagen: RSAGenParam):
        public, private = self.modules[name][label].generate_keypair(
            pkcs11.KeyType.DSA, dsagen.bits, label=dsagen.label, store=True
        )
        return [self._objtoobj(obj) for obj in [public, private]]

    def gen_aes(self, name, label, aesgen: AESGenParam):
        private = self.modules[name][label].generate_key(
            pkcs11.KeyType.AES, aesgen.bits, label=aesgen.label, store=True
        )
        return [self._objtoobj(obj) for obj in [private]]

    def gen_ec(self, name, label, ecgen: ECGenParam):
        parameters = self.modules[name][label].create_domain_parameters(
            pkcs11.KeyType.EC,
            {Attribute.EC_PARAMS: encode_named_curve_parameters(ecgen.curve)},
            local=True,
        )
        public, private = parameters.generate_keypair(store=True, label=ecgen.label)
        return [self._objtoobj(obj) for obj in [public, private]]

    def gen_edwards(self, name, label, ecgen: ECGenParam):
        parameters = self.modules[name][label].create_domain_parameters(
            pkcs11.KeyType.EC_EDWARDS,
            {Attribute.EC_PARAMS: encode_named_curve_parameters(ecgen.curve)},
            local=True,
        )
        public, private = parameters.generate_keypair(store=True, label=ecgen.label)
        return [self._objtoobj(obj) for obj in [public, private]]

    def destroyobj(self, name, label, so: SearchObject):
        attrs = self._so_to_attr(so)
        for obj in self.modules[name][label].get_objects(attrs):
            obj.destroy()
            return {"removed": 1}
        return {"removed": 0}

    def wrap(self, name, label, so: SearchObject):
        return self._deencrypt("wrap", name, label, so)

    def unwrap(self, name, label, so: SearchObject):
        return self._deencrypt("unwrap", name, label, so)

    def sign(self, name, label, so: SearchObject):
        return self._deencrypt("sign", name, label, so)

    def verify(self, name, label, so: SearchObject):
        return self._deencrypt("verify", name, label, so)

    def encrypt(self, name, label, so: SearchObject):
        return self._deencrypt("encrypt", name, label, so)

    def decrypt(self, name, label, so: SearchObject):
        return self._deencrypt("decrypt", name, label, so)

    def derive(self, name, label, so: SearchObject):
        return self._deencrypt("derive_key", name, label, so)
# unwrap = optional ( aes128_wrap, aes192_wrap, aes256_wrap, aes128, aes192, aes256)
# wrap = optional ( aes128_wrap, aes192_wrap, aes256_wrap, aes128, aes192, aes256)
# sharedinfo = optional
# algorithm = optional  (dhSinglePass-stdDH-sha1kdf-scheme , 224, 256,384,512, of gewoon SHA1, SHA256, SHA512, SHA384, SHA224)
# otherpub = base64encoded
# data = base64encoded data
# size = number of returned bytes

# voor unwrap:
#   unwrap = aes128_wrap
#   algorithm = dhSinglePass-stdDH-sha1kdf-scheme  # RFC5753 compatible met CMS
#   otherpub = blablabla==
#   data = wrapped data
# returns
#   aeskey

# voor wrap:
#   wrap = aes128_wrap
#   algorithm = dhSinglePass-stdDH-sha1kdf-scheme
#   otherpub = blablabla==
#   data = (aes-key/data)-die-encrypted moet worden
# returns
#   wrapped_data


# voor normale ECDH key agreement:
#   otherpub = blablabla==
#   sharedinfo: indien gewenst
#   data: ""
#   size: aantal returned bits
#   algorithm: optioneel: SHA256 ofzoiets
    def _derive_key(self, so: SearchObject, toexec, data: bytes):
        # this seems counter intiutive, however if you want to return an AES key it should be extractable after
        # calculation
        publictemplate = {pkcs11.Attribute.SENSITIVE: False, pkcs11.Attribute.EXTRACTABLE: True}
        otherpub = base64.b64decode(so.otherpub)
        sharedinfo = so.sharedinfo if hasattr(so, 'sharedinfo') else None
        thekdf = KeyXchangeKDF(so.algorithm) if hasattr(so, 'algorithm') else pkcs11.KDF.NULL
        if hasattr(so, 'wrap') or hasattr(so, 'unwrap'):
            wrap = so.wrap if hasattr(so, 'wrap') else so.unwrap
            if hasattr(so, 'algorithm') and so.algorithm.startswith("dhSinglePass-stdDH-sha"):
                sharedinfo = SharedInfo({'algorithm': {'algorithm': wrap}, 'suppPubInfo': pack(">L", aessize)}).dump()
            aessize = int(so.wrap[3:6])
            newaes = toexec(pkcs11.KeyType.AES, aessize,
                            mechanism_param=(thekdf,
                                             sharedinfo,
                                             otherpub)
                           )
            if hasattr(so, 'wrap'):
                toexec_wrap = getattr(newaes, 'wrap_key')
            else:
                toexec_wrap = getattr(newaes, 'unwrap_key')
            return base64.b64encode(
                toexec_wrap(
                    pkcs11.ObjectClass.SECRET_KEY,
                    pkcs11.KeyType.AES,
                    data,
                    template=publictemplate
                )['pkcs11.Attribute.VALUE']
            )
        if hasattr(so, 'size'):
            return base64.b64encode(
                toexec(pkcs11.KeyType.AES, so.size, mechanism_param=(thekdf, sharedinfo, otherpub), template=publictemplate)['pkcs11.Attribute.VALUE']
            )
        return False

    def _dsa(self, so: SearchObject, toexec, data: bytes, thefunc: str):
        mechanism_param = None
        if so.mechanism:
            if thefunc == "verify":
                return toexec(
                    data,
                    base64.b64decode(so.signature),
                    mechanism=getattr(pkcs11.Mechanism, so.mechanism),
                    mechanism_param=mechanism_param,
                )
            return base64.b64encode(
                toexec(
                    data,
                    mechanism=getattr(pkcs11.Mechanism, so.mechanism),
                    mechanism_param=mechanism_param,
                )
            )
        return False

    def _rsa(self, so: SearchObject, toexec, data: bytes, thefunc: str):
        mechanism_param = None
        if so.mechanism in ["RSA_PKCS_OAEP", "RSA_PKCS_PSS"] and so.hashmethod:
            if MethodSize.map(so.hashmethod) is not len(data) and thefunc in ['verify', 'sign']:
                raise HSMError("Data length does not match hash method")
            mechanism_param = (
                MethodMechanism.map(so.hashmethod),
                MethodMGF.map(so.hashmethod),
                MethodSize.map(so.hashmethod) if thefunc in ['verify', 'sign'] else None,
            )
        if so.mechanism:
            if thefunc == "verify":
                return toexec(
                    data,
                    base64.b64decode(so.signature),
                    mechanism=getattr(pkcs11.Mechanism, so.mechanism),
                    mechanism_param=mechanism_param,
                )
            return base64.b64encode(
                toexec(
                    data,
                    mechanism=getattr(pkcs11.Mechanism, so.mechanism),
                    mechanism_param=mechanism_param,
                )
            )
        return False

    def _aes(self, so: SearchObject, toexec, data: bytes, thefunc: str, module):
        theiv = (
            base64.b64decode(so.iv)
            if hasattr(so, 'iv') and so.iv
            else module.generate_random(128)
        )
        if so.mechanism:
            if thefunc == "verify":
                return toexec(
                    data,
                    base64.b64decode(so.signature),
                    mechanism_param=theiv,
                    mechanism=getattr(pkcs11.Mechanism, so.mechanism),
                )
            retdata = base64.b64encode(
                toexec(
                    data,
                    mechanism_param=theiv,
                    mechanism=getattr(pkcs11.Mechanism, so.mechanism),
                )
            )
        elif thefunc == "verify":
            return toexec(
                data, base64.b64decode(so.signature), mechanism_param=theiv
            )
        retdata = base64.b64encode(toexec(data, mechanism_param=theiv))
        if thefunc == "encrypt":
            return {"iv": base64.b64encode(theiv), "data": retdata}
        if thefunc == "decrypt":
            return {"data": retdata}
        if thefunc == "verify":
            return {"data": retdata}
        return False

    def _deencrypt(self, thefunc: str, name: str, label: str, so: SearchObject):
        """
        Given search parameters, find the first object within a 'module:slot' that complies with
        this search. If it exists, execute the function using the provided searchobject. Where the following
        SearchObjects (and functions) may be used:

        wrap, unwrap:
            SearchObject

        decrypt, encrypt:
            DecryptEncryptObject

        verify:
            VerifyRSAObject, VerifyAESObject

        sign:
            SignRSAObject, SignAESObject
        """
        attrs = self._so_to_attr(so)
        data = base64.b64decode(so.data)
        objs = list(self.modules[name][label].get_objects(attrs))
        if objs:

            obj = objs[0]
            toexec = getattr(obj, thefunc)
            if toexec is None:
                # HSM API Module is used incorrectly:
                raise ValueError(f"Function {thefunc} is unknown.")
            if thefunc == "derive_key":
                return self._derive_key(so, toexec, data)
            if obj.key_type == pkcs11.KeyType.RSA:
                return self._rsa(so, toexec, data, thefunc)
            if obj.key_type == pkcs11.KeyType.DSA:
                return self._dsa(so, toexec, data, thefunc)
            if obj.key_type == pkcs11.KeyType.AES:
                return self._aes(so, toexec, data, thefunc, self.modules[name][label])
            if thefunc == "verify":
                return toexec(data, so.signature)
            retdata = toexec(data)
            return base64.b64encode(retdata)
        raise HSMError("No such key")

    def getobjdetails(self, name, label, so: SearchObject):
        attrs = self._so_to_attr(so)
        return [
            self._objtoobj(obj) for obj in self.modules[name][label].get_objects(attrs)
        ]

    def list_slot_mech(self, name, label):
        try:
            return [
                str(x).split(".")[1] if "." in str(x) else "mechtype-" + hex(x)
                for x in self.modules[name][label].token.slot.get_mechanisms()
            ]
        except Exception as mye:
            raise HSMError(mye) from mye

    def list_slot(self, name, label):
        usage_attr = [
            Attribute.ENCRYPT,
            Attribute.WRAP,
            Attribute.VERIFY,
            Attribute.DERIVE,
            Attribute.DECRYPT,
            Attribute.UNWRAP,
            Attribute.SIGN,
        ]
        flags_attr = [
            Attribute.NEVER_EXTRACTABLE,
            Attribute.ALWAYS_SENSITIVE,
            Attribute.MODIFIABLE,
            Attribute.COPYABLE,
            Attribute.EXTRACTABLE,
            Attribute.PRIVATE,
        ]
        wanted_attr = [
            Attribute.LABEL,
            Attribute.KEY_TYPE,
            Attribute.SUBJECT,
            Attribute.ID,
            Attribute.MODULUS_BITS,
        ]
        objs: dict = {}
        for obj in self.modules[name][label].get_objects():
            objtype = (
                str(obj.object_class).split(".")[1]
                if obj.object_class is not None
                else "DATA"
            )
            if objtype not in objs:
                objs[objtype] = []
            retobj: dict = {"flags": [], "usage": []}
            for want in wanted_attr:
                try:
                    if obj[want] and isinstance(obj[want], bytes):
                        retobj[str(want).split(".")[1]] = obj[want].decode("utf-8")
                    elif obj[want] is not None and "." in str(obj[want]):
                        retobj[str(want).split(".")[1]] = str(obj[want]).split(".")[1]
                    elif obj[want]:
                        retobj[str(want).split(".")[1]] = obj[want]
                except:
                    continue
            for want in flags_attr:
                try:
                    if obj[want]:
                        retobj["flags"].append(str(want).split(".")[1])
                except:
                    pass
            for want in usage_attr:
                try:
                    if obj[want]:
                        retobj["usage"].append(str(want).split(".")[1])
                except:
                    pass
            objs[objtype].append(retobj)
        return objs
