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
import pkcs11.util.x509

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
    ImportObject,
)

asn1crypto.keys.NamedCurve.register("curve25519", "1.3.101.110", 32)
asn1crypto.keys.NamedCurve.register("curve448", "1.3.101.111", 57)
asn1crypto.keys.NamedCurve.register("ed25519", "1.3.101.112", 32)
asn1crypto.keys.NamedCurve.register("ed448", "1.3.101.113", 57)
asn1crypto.keys.PublicKeyAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.110"
] = "x25519"
asn1crypto.keys.PublicKeyAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.111"
] = "x448"
asn1crypto.keys.PublicKeyAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.112"
] = "ed25519"
asn1crypto.keys.PublicKeyAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.113"
] = "ed448"


class SharedInfo(asn1crypto.core.Sequence):
    _fields = [
        ("algorithm", asn1crypto.cms.KeyEncryptionAlgorithm),
        ("entityUInfo", asn1crypto.core.OctetString, {"explicit": 1, "optional": True}),
        ("suppPubInfo", asn1crypto.core.OctetString, {"explicit": 2}),
    ]

class Mapper:
    maps = {}
    def map(self, method):
        if method in self.maps:
            return self.maps[method]
        raise HSMError("Value error")

class KeyXchangeKDF(Mapper):  # pylint: disable=too-few-public-methods
    maps = {
        "NULL": pkcs11.KDF.NULL,
        "dhSinglePass-stdDH-sha1kdf-scheme": pkcs11.KDF.SHA1,
        "dhSinglePass-stdDH-sha224kdf-scheme": pkcs11.KDF.SHA224,
        "dhSinglePass-stdDH-sha256kdf-scheme": pkcs11.KDF.SHA256,
        "dhSinglePass-stdDH-sha384kdf-scheme": pkcs11.KDF.SHA384,
        "dhSinglePass-stdDH-sha512kdf-scheme": pkcs11.KDF.SHA512,
        "sha1": pkcs11.KDF.SHA1,
        "sha224": pkcs11.KDF.SHA224,
        "sha256": pkcs11.KDF.SHA256,
        "sha384": pkcs11.KDF.SHA384,
        "sha512": pkcs11.KDF.SHA512,
    }


class KDFtoMech(Mapper):  # pylint: disable=too-few-public-methods
    maps = {
        pkcs11.KDF.NULL: "ECDSA",
        pkcs11.KDF.SHA1: "ECDSA_SHA1",
        pkcs11.KDF.SHA224: "ECDSA_SHA224",
        pkcs11.KDF.SHA256: "ECDSA_SHA256",
        pkcs11.KDF.SHA384: "ECDSA_SHA384",
        pkcs11.KDF.SHA512: "ECDSA_SHA512",
    }


class MethodMechanism(Mapper):  # pylint: disable=too-few-public-methods
    maps = {
        HashMethod.SHA1: pkcs11.Mechanism.SHA_1,
        HashMethod.SHA224: pkcs11.Mechanism.SHA224,
        HashMethod.SHA256: pkcs11.Mechanism.SHA256,
        HashMethod.SHA384: pkcs11.Mechanism.SHA384,
        HashMethod.SHA512: pkcs11.Mechanism.SHA512,
    }


class MethodMGF(Mapper):  # pylint: disable=too-few-public-methods
    maps = {
        HashMethod.SHA1: pkcs11.MGF.SHA1,
        HashMethod.SHA224: pkcs11.MGF.SHA224,
        HashMethod.SHA256: pkcs11.MGF.SHA256,
        HashMethod.SHA384: pkcs11.MGF.SHA384,
        HashMethod.SHA512: pkcs11.MGF.SHA512,
    }


class MethodSize(Mapper):  # pylint: disable=too-few-public-methods
    maps = {
        HashMethod.SHA1: hashlib.sha1().digest_size,
        HashMethod.SHA224: hashlib.sha224().digest_size,
        HashMethod.SHA256: hashlib.sha256().digest_size,
        HashMethod.SHA384: hashlib.sha384().digest_size,
        HashMethod.SHA512: hashlib.sha512().digest_size,
    }


# All public are public?
class HSMModule:  # pylint: disable=too-many-public-methods
    modules = {}
    libs = {}
    publictemplate = {
        pkcs11.Attribute.SENSITIVE: False,
        pkcs11.Attribute.EXTRACTABLE: True,
    }

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

    #    def is_module(self, modname):
    #        return modname in self.modules

    #    def is_slot(self, modname, slotname):
    #        return modname in self.modules and slotname in self.modules[modname]

    def list_slots(self, modname):
        return list(self.modules[modname])

    def _so_to_attr(self, so: SearchObject):  # pylint: disable=no-self-use
        attrs = {}
        if so.label:
            attrs[Attribute.LABEL] = so.label
        if so.objid:
            attrs[Attribute.ID] = so.objid.decode()
        if so.objtype:
            attrs[Attribute.CLASS] = getattr(pkcs11.ObjectClass, so.objtype)
        return attrs

    def _objtocontent(self, obj, want):  # pylint: disable=no-self-use
        try:
            attrname = str(want).split(".")[1]
            if obj[want] and isinstance(obj[want], bytes):
                return attrname, obj[want].decode("utf-8")
            if obj[want] is not None and "." in str(obj[want]):
                return attrname, str(obj[want]).split(".")[1]
            if obj[want]:
                return attrname, obj[want]
            return False, None
        except:  # pylint: disable=bare-except
            return False, None

    def _objtoobj(self, obj):  # pylint: disable=no-self-use
        retobj = {}
        for attr in pkcs11.Attribute:
            try:
                attrname = str(attr).split(".")[1]
                if attrname in ["EC_PARAMS"]:
                    retobj[attrname] = ECDomainParameters.load(obj[attr]).native
                elif attrname in [
                    "MODULUS",
                    "PUBLIC_EXPONENT",
                    "EC_POINT",
                    "PRIME",
                    "SUBPRIME",
                    "BASE",
                    "CHECK_VALUE",
                ]:
                    retobj[attrname] = codecs.encode(obj[attr], "hex")
                elif attrname in [
                    "SUBJECT",
                    "ISSUER",
                ]:
                    retobj[attrname] = asn1crypto.x509.Name().load(obj[attr]).native
                elif attrname in [
                    "SERIAL_NUMBER",
                ]:
                    retobj[attrname] = asn1crypto.core.Integer().load(obj[attr]).native
                else:
                    name, content = self._objtocontent(obj, attr)
                    if name:
                        retobj[name] = content
            except:  # pylint: disable=bare-except
                pass
        try:
            if obj.key_type == pkcs11.KeyType.RSA:
                retobj["publickey"] = asn1crypto.pem.armor(
                    "PUBLIC KEY", pkcs11.util.rsa.encode_rsa_public_key(obj)
                )
            if obj.key_type == pkcs11.KeyType.DSA:
                retobj["publickey"] = asn1crypto.pem.armor(
                    "PUBLIC KEY", pkcs11.util.dsa.encode_dsa_public_key(obj)
                )
            if (
                obj.key_type == pkcs11.KeyType.EC
                and obj.object_class == pkcs11.ObjectClass.PUBLIC_KEY
            ):
                retobj["publickey"] = asn1crypto.pem.armor(
                    "PUBLIC KEY", (pkcs11.util.ec.encode_ec_public_key(obj))
                )
        except:  # pylint: disable=bare-except
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

    def _import_publickey(self, attrs, content):  # pylint: disable=no-self-use
        # F*** ugly hack to fix asn1crypto outdated for edwards (25519,448)
        tmpdisable = (
            asn1crypto.keys.PublicKeyInfo._spec_callbacks  # pylint: disable=protected-access
        )
        asn1crypto.keys.PublicKeyInfo._spec_callbacks = (  # pylint: disable=protected-access
            None
        )
        keytype = asn1crypto.keys.PublicKeyInfo.load(content).native["algorithm"][
            "algorithm"
        ]
        asn1crypto.keys.PublicKeyInfo._spec_callbacks = (  # pylint: disable=protected-access
            tmpdisable
        )
        # End hackje

        if keytype == "rsa":
            attrs.update(
                pkcs11.util.rsa.decode_rsa_public_key(
                    asn1crypto.keys.RSAPublicKey(
                        asn1crypto.keys.PublicKeyInfo.load(content)["public_key"].native
                    ).dump()
                )
            )
        elif keytype == "ec":
            attrs.update(pkcs11.util.ec.decode_ec_public_key(content))
        elif keytype in ["ed25519", "x25519", "ed448", "x448"]:
            attrs.update(
                {
                    pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC_EDWARDS,
                    pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY,
                    pkcs11.Attribute.EC_POINT: asn1crypto.core.load(content)[1].dump(),
                    pkcs11.Attribute.EC_PARAMS: ECDomainParameters(
                        {"named": asn1crypto.core.load(content)[0].native["0"]}
                    ).dump(),
                }
            )
        else:
            raise HSMError(f"Can't import public key {keytype}")
        return attrs

    def importdata(self, name, label, so: ImportObject):
        storetemplate = {
            pkcs11.Attribute.TOKEN: True,
        }
        attrs = self._so_to_attr(so)
        data = base64.b64decode(so.data)
        attrs.update(storetemplate)
        if so.pem:
            datatype, _, content = asn1crypto.pem.unarmor(data)
            if datatype == "CERTIFICATE":
                attrs.update(pkcs11.util.x509.decode_x509_certificate(content))
            elif datatype == "RSA PRIVATE KEY":
                attrs.update(pkcs11.util.rsa.decode_rsa_private_key(content))
            elif datatype == "EC PRIVATE KEY":
                attrs.update(pkcs11.util.ec.decode_ec_private_key(content))
            elif datatype == "PRIVATE KEY":  # 25519 or 448
                attrs.update(
                    {
                        pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC_EDWARDS,
                        pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
                        pkcs11.Attribute.VALUE: asn1crypto.core.OctetString.load(
                            asn1crypto.core.load(content)[2].native
                        ).native,
                        pkcs11.Attribute.EC_PARAMS: ECDomainParameters(
                            {"named": asn1crypto.core.load(content)[1].native["0"]}
                        ).dump(),
                    }
                )
            elif datatype == "PUBLIC KEY":
                attrs = self._import_publickey(attrs, content)
            else:
                raise HSMError(f"Can't import {datatype}")
        if pkcs11.Attribute.CLASS in attrs:
            return [self._objtoobj(self.modules[name][label].create_object(attrs))]
        # TODO: AES import
        raise HSMError("Raw import not supported yet")

    def wrap(self, name, label, so: SearchObject):
        return self._deencrypt("wrap_key", name, label, so)

    def unwrap(self, name, label, so: SearchObject):
        return self._deencrypt("unwrap_key", name, label, so)

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
    # algorithm = optional  (dhSinglePass-stdDH-sha1kdf-scheme , 224, 256,384,512,
    #                        of gewoon SHA1, SHA256, SHA512, SHA384, SHA224)
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
    def _unsupported_hardware_derive(  # pylint: disable=too-many-arguments, too-many-locals
        self, toexec, keytype, aessize, mechanism_param, module, template=None
    ):
        mechs = self._list_slot_mech(module)
        kdf, sharedinfo, otherpub = mechanism_param
        mech = KDFtoMech().map(kdf)
        if mech in mechs:
            return toexec(
                keytype, aessize, mechanism_param=mechanism_param, template=template
            )

        hashmethod = mech[mech.index("_") + 1 :]
        hasher = getattr(hashlib, hashmethod.lower())
        sha = hasher()
        deriv = toexec(
            keytype,
            aessize,
            mechanism_param=(KeyXchangeKDF().map("NULL"), None, otherpub),
            template=self.publictemplate,
        )
        output = b""
        counter = 0
        while len(output) < aessize / 8:
            counter += 1
            sha = hasher()
            sha.update(deriv[pkcs11.Attribute.VALUE])
            sha.update(pack(">L", counter))
            sha.update(sharedinfo)
            output += sha.digest()
        attrs = {
            pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.AES,
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
            pkcs11.Attribute.VALUE: output[: int(aessize / 8)],
        }
        attrs.update(self.publictemplate)
        return module.create_object(attrs)

    def _derive_key(self, so: SearchObject, toexec, data: bytes, module: str):
        # this seems counter intiutive, however if you want to return an AES key it should be extractable after
        # calculation
        otherpub = base64.b64decode(so.otherpub)
        sharedinfo = so.sharedinfo if hasattr(so, "sharedinfo") else None

        thekdf = (
            KeyXchangeKDF().map(so.algorithm)
            if hasattr(so, "algorithm") and so.algorithm
            else pkcs11.KDF.NULL
        )
        if (hasattr(so, "wrap") and so.wrap) or (hasattr(so, "unwrap") and so.unwrap):
            wrap = so.wrap if hasattr(so, "wrap") and so.wrap else so.unwrap
            aessize = int(wrap[3:6])
            if (
                hasattr(so, "algorithm")
                and so.algorithm
                and so.algorithm.startswith("dhSinglePass-stdDH-sha")
            ):
                sharedinfo = SharedInfo(
                    {
                        "algorithm": {"algorithm": wrap},
                        "suppPubInfo": pack(">L", aessize),
                    }
                ).dump()
            newaes = self._unsupported_hardware_derive(
                toexec,
                pkcs11.KeyType.AES,
                aessize,
                mechanism_param=(thekdf, sharedinfo, otherpub),
                module=module,
            )
            if hasattr(so, "wrap") and so.wrap:
                toexec_wrap = getattr(newaes, "wrap_key")
                attrs = {
                    pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.AES,
                    pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                    pkcs11.Attribute.VALUE: data,
                }
                attrs.update(self.publictemplate)
                return base64.b64encode(
                    toexec_wrap(
                        module.create_object(attrs),
                    )
                )
            if hasattr(so, "unwrap") and so.unwrap:
                toexec_wrap = getattr(newaes, "unwrap_key")
                return base64.b64encode(
                    toexec_wrap(
                        pkcs11.ObjectClass.SECRET_KEY,
                        pkcs11.KeyType.AES,
                        data,
                        template=self.publictemplate,
                    )[pkcs11.Attribute.VALUE]
                )
        if hasattr(so, "size") and so.size:
            return base64.b64encode(
                self._unsupported_hardware_derive(
                    toexec,
                    pkcs11.KeyType.AES,
                    so.size,
                    mechanism_param=(thekdf, sharedinfo, otherpub),
                    module=module,
                    template=self.publictemplate,
                )[pkcs11.Attribute.VALUE]
            )
        raise HSMError("Not enought arguments")

    def _dsa(
        self, so: SearchObject, toexec, data: bytes, thefunc: str
    ):  # pylint: disable=no-self-use
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
        if thefunc == "verify":
            return toexec(data, base64.b64decode(so.signature))
        return base64.b64encode(
            toexec(
                data,
            )
        )

    def _ec(
        self, so: SearchObject, toexec, data: bytes, thefunc: str
    ):  # pylint: disable=no-self-use
        mechanism_param = None
        if so.mechanism:
            if thefunc == "verify":
                return toexec(
                    data,
                    pkcs11.util.ec.decode_ecdsa_signature(
                        base64.b64decode(so.signature)
                    ),
                    mechanism=getattr(pkcs11.Mechanism, so.mechanism),
                    mechanism_param=mechanism_param,
                )
            if thefunc == "sign":
                return base64.b64encode(
                    pkcs11.util.ec.encode_ecdsa_signature(
                        toexec(
                            data,
                            mechanism=getattr(pkcs11.Mechanism, so.mechanism),
                            mechanism_param=mechanism_param,
                        )
                    )
                )
            # Only sign and verify are supported because derived is handled elsewhere
            # return base64.b64encode(
            #    toexec(
            #        data,
            #        mechanism=getattr(pkcs11.Mechanism, so.mechanism),
            #        mechanism_param=mechanism_param,
            #    )
            # )
        if thefunc == "verify":
            return toexec(data, base64.b64decode(so.signature))
        return base64.b64encode(toexec(data))

    def _rsa(
        self, so: SearchObject, toexec, data: bytes, thefunc: str
    ):  # pylint: disable=no-self-use
        mechanism_param = None
        if (
            so.mechanism in ["RSA_PKCS_OAEP"]
            or (so.mechanism and so.mechanism.endswith("RSA_PKCS_PSS"))
        ) and so.hashmethod:
            if (
                MethodSize().map(so.hashmethod) is not len(data)
                and thefunc in ["verify", "sign"]
                and so.mechanism in ["RSA_PKCS_OAEP", "RSA_PKCS_PSS"]
            ):
                raise HSMError("Data length does not match hash method")
            mechanism_param = (
                MethodMechanism().map(so.hashmethod),
                MethodMGF().map(so.hashmethod),
                MethodSize().map(so.hashmethod)
                if thefunc in ["verify", "sign"]
                else None,
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
        if thefunc == "verify":
            return toexec(data, base64.b64decode(so.signature))
        return base64.b64encode(toexec(data))

    def _aes(
        self, so: SearchObject, toexec, data: bytes, thefunc: str, module
    ):  # pylint: disable=too-many-arguments
        theiv = (
            base64.b64decode(so.iv)
            if hasattr(so, "iv") and so.iv
            else module.generate_random(128)
        )
        mechanism = None
        mechanism_param = None
        if so.mechanism:
            if thefunc == "verify":
                mechanism_param = theiv
                mechanism = getattr(pkcs11.Mechanism, so.mechanism)
            if thefunc == "sign":
                mechanism = getattr(pkcs11.Mechanism, so.mechanism)

        if thefunc == "verify":
            retdata = toexec(
                data,
                base64.b64decode(so.signature),
                mechanism_param=mechanism_param,
                mechanism=mechanism,
            )
        elif thefunc == "wrap_key":
            attrs = {
                pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.AES,
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                pkcs11.Attribute.VALUE: data,
            }
            attrs.update(self.publictemplate)
            retdata = base64.b64encode(
                toexec(
                    module.create_object(attrs),
                    mechanism=mechanism,
                    mechanism_param=mechanism_param,
                )
            )
        elif thefunc == "unwrap_key":
            retdata = base64.b64encode(
                toexec(
                    pkcs11.ObjectClass.SECRET_KEY,
                    pkcs11.KeyType.AES,
                    data,
                    mechanism=mechanism,
                    template=self.publictemplate,
                )[pkcs11.Attribute.VALUE]
            )
        else:
            retdata = base64.b64encode(
                toexec(data, mechanism_param=theiv, mechanism=mechanism)
            )
        if thefunc == "encrypt":
            return {"iv": base64.b64encode(theiv), "data": retdata}
        return retdata if isinstance(retdata, bool) else {"data": retdata}

    def _deencrypt(
        self, thefunc: str, name: str, label: str, so: SearchObject
    ):  # pylint: disable=too-many-return-statements
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
            try:
                if thefunc == "derive_key":
                    return self._derive_key(so, toexec, data, self.modules[name][label])
                if obj.key_type == pkcs11.KeyType.RSA:
                    return self._rsa(so, toexec, data, thefunc)
                if obj.key_type == pkcs11.KeyType.DSA:
                    return self._dsa(so, toexec, data, thefunc)
                if obj.key_type == pkcs11.KeyType.EC:
                    return self._ec(so, toexec, data, thefunc)
                if obj.key_type == pkcs11.KeyType.AES:
                    return self._aes(
                        so, toexec, data, thefunc, self.modules[name][label]
                    )
                retdata = toexec(data)
                return base64.b64encode(retdata)
            except RuntimeError as error:
                raise HSMError(
                    "Failure at executing function: " + str(type(error))
                ) from error
            except Exception as error:
                raise error
                # raise HSMError("HSM error: " + str(error))
        raise HSMError("No such key")

    def getobjdetails(self, name, label, so: SearchObject):
        attrs = self._so_to_attr(so)
        return [
            self._objtoobj(obj) for obj in self.modules[name][label].get_objects(attrs)
        ]

    def list_slot_mech(self, name, label):
        return [
            # example: Mechanism.AES_CBC => AES_CBC
            str(x).split(".")[1] if "." in str(x) else "mechtype-" + hex(x)
            for x in self.modules[name][label].token.slot.get_mechanisms()
        ]

    def _list_slot_mech(self, module):  # pylint: disable=no-self-use
        return [
            # example: Mechanism.AES_CBC => AES_CBC
            str(x).split(".")[1] if "." in str(x) else "mechtype-" + hex(x)
            for x in module.token.slot.get_mechanisms()
        ]

    def list_slot(self, name, label):
        usage_attr = [
            "ENCRYPT",
            "WRAP",
            "VERIFY",
            "DERIVE",
            "DECRYPT",
            "UNWRAP",
            "SIGN",
        ]
        flags_attr = [
            "NEVER_EXTRACTABLE",
            "ALWAYS_SENSITIVE",
            "MODIFIABLE",
            "COPYABLE",
            "EXTRACTABLE",
            "PRIVATE",
        ]
        wanted_attr = [
            "LABEL",
            "KEY_TYPE",
            "SUBJECT",
            "ISSUER",
            "SERIAL_NUMBER",
            "ID",
            "MODULUS_BITS",
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
            dingen = self._objtoobj(obj)
            for want in wanted_attr:
                if want in dingen:
                    retobj[want] = dingen[want]
            for want in flags_attr:
                if want in dingen and dingen[want]:
                    retobj["flags"].append(want)
            for want in usage_attr:
                if want in dingen and dingen[want]:
                    retobj["usage"].append(want)

            objs[objtype].append(retobj)
        return objs
