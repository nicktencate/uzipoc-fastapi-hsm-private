#!/usr/bin/env python3
import codecs
import base64
import pkcs11

import pkcs11.util
import pkcs11.util.rsa
import pkcs11.types
from pkcs11 import Attribute
from pkcs11.util.ec import encode_named_curve_parameters
import asn1crypto.pem
from asn1crypto.keys import ECDomainParameters


from .model import HSMError, SearchObject, DataSearchObject, RSAGenParam, AESGenParam, ECGenParam

class HSMModule:
    modules = {}
    libs = {}
    def __init__(self, config):
        for module in config['modules']:
            name = module['name']
            libje = module['module']
            self.modules[name] = {}
            slots = module['slots']
            self.loadlib(name, libje, slots)

    def loadlib(self, name, hsm_module, slots):
        if hsm_module not in self.libs:
            self.libs[name] = pkcs11.lib(hsm_module)
            for slot in slots:
                label = slot['slot']
                pin = slot['pinfile']
                token = self.libs[name].get_token(token_label=label)
                self.modules[name][label] = token.open(rw=True, user_pin=open(pin, 'r', encoding='utf-8').read().rstrip())

    def hsmlist(self):
        return list(self.modules)

    def is_module(self, modname):
        return modname in self.modules
    def is_slot(self, modname, slotname):
        return modname in self.modules and slotname in self.modules[modname]

    def list_slots(self, modname):
        return list(self.modules[modname])

    def so_to_attr(self, so: SearchObject):
        attrs={}
        if so.label:
            attrs[Attribute.LABEL] = so.label
        if so.objid:
            attrs[Attribute.ID] = so.objid.decode()
        if so.objtype:
            attrs[Attribute.CLASS] = getattr(pkcs11.ObjectClass, so.objtype)
        return attrs

    def objtoobj(self, obj):
        retobj = {}
        for attr in pkcs11.Attribute:
            try:
                if str(attr).split(".")[1] in ['EC_PARAMS']:
                    retobj[str(attr).split(".")[1]] = ECDomainParameters.load(obj[attr]).native
                elif str(attr).split(".")[1] in ['MODULUS', 'PUBLIC_EXPONENT', 'EC_POINT']:
                    retobj[str(attr).split(".")[1]] = codecs.encode(obj[attr],'hex')
                else:
                    if obj[attr] and isinstance(obj[attr], bytes):
                        retobj[str(attr).split(".")[1]] = obj[attr].decode('utf-8')
                    elif obj[attr] is not None and '.' in str(obj[attr]):
                        retobj[str(attr).split(".")[1]] = str(obj[attr]).split(".")[1]
                    elif obj[attr] is not None:
                        retobj[str(attr).split(".")[1]] = obj[attr]
            except:
                pass
        if obj.key_type==pkcs11.KeyType.RSA:
            retobj['publickey'] = asn1crypto.pem.armor('PUBLIC KEY', pkcs11.util.rsa.encode_rsa_public_key(obj))
        return retobj

    def gen_rsa(self, name, label, rsagen: RSAGenParam):
        public, private = self.modules[name][label].generate_keypair(pkcs11.KeyType.RSA, rsagen.bits, label=rsagen.label, store=True)
        # not supported ?, public_template={pkcs11.Attribute.PUBLIC_EXPONENT: rsagen.public_exponent})
        return [self.objtoobj(obj) for obj in [public, private]]

    def gen_aes(self, name, label, aesgen: AESGenParam):
        private = self.modules[name][label].generate_key(pkcs11.KeyType.AES, aesgen.bits, label=aesgen.label, store=True)
        # not supported ?, public_template={pkcs11.Attribute.PUBLIC_EXPONENT: rsagen.public_exponent})
        return [self.objtoobj(obj) for obj in [private]]

    def gen_ec(self, name, label, ecgen: ECGenParam):
        parameters = self.modules[name][label].create_domain_parameters(pkcs11.KeyType.EC, { Attribute.EC_PARAMS: encode_named_curve_parameters(ecgen.curve) }, local=True)
        public, private = parameters.generate_keypair(store=True, label=ecgen.label)
        return [self.objtoobj(obj) for obj in [public, private]]

    def destroyobj(self, name, label, so: SearchObject):
        attrs = self.so_to_attr(so)
        for obj in self.modules[name][label].get_objects(attrs):
            obj.destroy()
            return {'removed': 1}
        return {'removed': 0}

    def wrap(self, name, label, so: DataSearchObject):
        return self.deencrypt("wrap", name, label, so)

    def unwrap(self, name, label, so: DataSearchObject):
        return self.deencrypt("unwrap", name, label, so)

    def sign(self, name, label, so: DataSearchObject):
        return self.deencrypt("sign", name, label, so)

    def verify(self, name, label, so: DataSearchObject):
        return self.deencrypt("verify", name, label, so)

    def encrypt(self, name, label, so: DataSearchObject):
        return self.deencrypt("encrypt", name, label, so)

    def decrypt(self, name, label, so: DataSearchObject):
        return self.deencrypt("decrypt", name, label, so)

    def deencrypt(self, thefunc: str, name: str, label: str, so: DataSearchObject) -> str:
        print(self.modules)
        for mod in self.modules['softhsm']:
            print(self.modules['softhsm'][mod])
        attrs = self.so_to_attr(so)
        data = base64.b64decode(so.data)
        objs = list(self.modules[name][label].get_objects(attrs))
        if objs:
            obj = objs[0]
            toexec = getattr(obj, thefunc)
            if obj.key_type==pkcs11.KeyType.RSA:
                if so.mechanism in ['RSA_PKCS_OAEP', 'RSA_PKCS_PSS'] and so.mechanismparam:
                    return base64.b64encode(toexec(data, mechanism=getattr(pkcs11.Mechanism, so.mechanism),
                                       mechanism_param=(getattr(pkcs11.Mechanism, so.mechanismparam[0]),
                                                        getattr(pkcs11.MGF, so.mechanismparam[1]),
                                                        so.mechanismparam[2]
                                                       )
                               ))
                if so.mechanism:
                    return base64.b64encode(toexec(data, mechanism=getattr(pkcs11.Mechanism, so.mechanism)))
            elif obj.key_type==pkcs11.KeyType.AES:
                theiv = base64.b64decode(so.iv) if so.iv else self.modules[name][label].generate_random(128)
                if so.mechanism:
                    retdata = base64.b64encode(toexec(data, mechanism_param = theiv, mechanism=getattr(pkcs11.Mechanism, so.mechanism)))
                else:
                    retdata = base64.b64encode(toexec(data, mechanism_param = theiv))
                if thefunc == 'encrypt':
                    return {'iv': base64.b64encode(theiv), 'data': retdata}
                if thefunc == 'decrypt':
                    return {'iv': base64.b64encode(theiv), 'data': retdata}
            retdata = toexec(data)
            return base64.b64encode(retdata)
        raise HSMError("No such key")

    def getobjdetails(self, name, label, so: SearchObject):
        attrs = self.so_to_attr(so)
        return [self.objtoobj(obj) for obj in self.modules[name][label].get_objects(attrs)]

    def list_slot_mech(self, name, label):
        try:
            return [str(x).split(".")[1] for x in self.modules[name][label].token.slot.get_mechanisms()]
        except Exception as mye:
            raise HSMError(mye) from mye

    def list_slot(self, name, label):
        usage_attr = [Attribute.ENCRYPT, Attribute.WRAP, Attribute.VERIFY, Attribute.DERIVE, Attribute.DECRYPT, Attribute.UNWRAP, Attribute.SIGN]
        flags_attr = [Attribute.NEVER_EXTRACTABLE, Attribute.ALWAYS_SENSITIVE, Attribute.MODIFIABLE, Attribute.COPYABLE, Attribute.EXTRACTABLE, Attribute.PRIVATE]
        wanted_attr = [Attribute.LABEL, Attribute.KEY_TYPE, Attribute.SUBJECT, Attribute.ID, Attribute.MODULUS_BITS]
        objs = {}
        for obj in self.modules[name][label].get_objects():
            objtype = str(obj.object_class).split(".")[1] if obj.object_class is not None else "DATA"
            if objtype not in objs:
                objs[objtype] = []
            retobj = {'flags': [], 'usage': []}
            for want in wanted_attr:
                try:
                    if obj[want] and isinstance(obj[want], bytes):
                        retobj[str(want).split(".")[1]] = obj[want].decode('utf-8')
                    elif obj[want] is not None and '.' in str(obj[want]):
                        retobj[str(want).split(".")[1]] = str(obj[want]).split(".")[1]
                    elif obj[want]:
                        retobj[str(want).split(".")[1]] = obj[want]
                except:
                    continue
            for want in flags_attr:
                try:
                    if obj[want]:
                        retobj['flags'].append(str(want).split(".")[1])
                except:
                    pass
            for want in usage_attr:
                try:
                    if obj[want]:
                        retobj['usage'].append(str(want).split(".")[1])
                except:
                    pass
            objs[objtype].append(retobj)
        print(objs)
        return objs