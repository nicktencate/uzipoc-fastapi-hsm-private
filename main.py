from fastapi import FastAPI
import yaml
import pkcs11
import pkcs11.util
import pkcs11.util.rsa
from pkcs11.util.ec import encode_named_curve_parameters
import asn1crypto.pem
from asn1crypto.keys import ECDomainParameters
from pkcs11 import Attribute
from typing import Optional
from pydantic import BaseModel, Field
import codecs

app = FastAPI()
with open('conf.yml','r') as yamlfile:
    config = yaml.load(yamlfile ,Loader=yaml.Loader)


class SearchObject(BaseModel):
    label: Optional[str] = None
    objtype: Optional[str] = None
    objid: Optional[str] = None

class RSAGenParam(BaseModel):
    label: Optional[str] = None
    objid: Optional[str] = None
    bits: Optional[int] = 2048
    public_exponent: Optional[int] = 65537

class ECGenParam(BaseModel):
    label: Optional[str] = None
    objid: Optional[str] = None
    curve: Optional[str] = None

class HSMModule:
    modules = {}
    def __init__(self,config):
        for module in config['modules']:
            name = module['name']
            libje = module['module']
            self.modules[name] = {}
            slots = module['slots']
            for slot in slots:
               label = slot['slot']
               pin = slot['pinfile']
               self.modules[name][label] = self.loadlib(libje,label,open(pin,'r').read().rstrip())
    
    def loadlib(self,hsm_module,hsm_slot_label,pin):
        lib = pkcs11.lib(hsm_module)
        token = lib.get_token(token_label=hsm_slot_label)
        return token.open(rw=True, user_pin=pin)

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
            attrs[Attribute.CLASS] = getattr(pkcs11.ObjectClass,so.objtype)
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
                    if obj[attr] and type(obj[attr])==bytes:
                        retobj[str(attr).split(".")[1]] = obj[attr].decode('utf-8')
                    elif obj[attr] and '.' in str(obj[attr]):
                        retobj[str(attr).split(".")[1]] = str(obj[attr]).split(".")[1]
                    elif obj[attr]:
                        retobj[str(attr).split(".")[1]] = obj[attr]
            except:
                pass
        if obj.key_type==pkcs11.KeyType.RSA:
            print(obj[Attribute.KEY_TYPE], obj[Attribute.CLASS])
            retobj['publickey'] = asn1crypto.pem.armor('PUBLIC KEY',pkcs11.util.rsa.encode_rsa_public_key(obj))
        return retobj

    def gen_rsa(self, name, label, rsagen: RSAGenParam):
        public, private = self.modules[name][label].generate_keypair(pkcs11.KeyType.RSA, rsagen.bits, label=rsagen.label, store=True)
        # not supported ?, public_template={pkcs11.Attribute.PUBLIC_EXPONENT: rsagen.public_exponent})
        return [self.objtoobj(obj) for obj in [public, private]]

    def gen_ec(self, name, label, ecgen: ECGenParam):
        parameters = self.modules[name][label].create_domain_parameters(pkcs11.KeyType.EC, { Attribute.EC_PARAMS: encode_named_curve_parameters(ecgen.curve) }, local=True)
        public, private = parameters.generate_keypair(store=True, label=ecgen.label)
        return [self.objtoobj(obj) for obj in [public, private]]

    def destroyobj(self, name, label, so: SearchObject):
        attrs = self.so_to_attr(so)
        objs = []
        for obj in self.modules[name][label].get_objects(attrs):
            obj.destroy()
            return {'removed': 1}
        return {'removed': 0}
   
    def getobjdetails(self, name, label, so: SearchObject):
        attrs = self.so_to_attr(so)
        return [self.objtoobj(obj) for obj in self.modules[name][label].get_objects(attrs)]

    def list_slot_mech(self, name, label):
        return [str(x).split(".")[1] for x in self.modules[name][label].token.slot.get_mechanisms()]

    def list_slot(self, name, label):
        usage_attr = [Attribute.ENCRYPT, Attribute.WRAP, Attribute.VERIFY, Attribute.DERIVE, Attribute.DECRYPT, Attribute.UNWRAP, Attribute.SIGN]
        flags_attr = [Attribute.NEVER_EXTRACTABLE, Attribute.ALWAYS_SENSITIVE, Attribute.MODIFIABLE, Attribute.COPYABLE, Attribute.EXTRACTABLE, Attribute.PRIVATE]
        wanted_attr = [Attribute.LABEL, Attribute.KEY_TYPE, Attribute.SUBJECT, Attribute.ID, Attribute.MODULUS_BITS]
        wanted_item = ['id', 'label', 'key_type', '_key_description', 'key_length']
        objs = {}
        for obj in self.modules[name][label].get_objects():
            print("=" * 56)
            objtype = str(obj.object_class).split(".")[1]
            if objtype not in objs:
                objs[objtype] = []
            retobj = {'flags': [], 'usage': []}
            for want in wanted_attr:
              try:
                if obj[want] and type(obj[want])==bytes:
                    retobj[str(want).split(".")[1]] = obj[want].decode('utf-8')
                elif obj[want]:
                    retobj[str(want).split(".")[1]] = obj[want]
              except:
                pass
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

#base64.b64encode(pkcs11.util.rsa.encode_rsa_public_key(pub))


hsm = HSMModule(config)


@app.get("/")
async def root():
    return {"error": 0, "message": "working", "data": config}

@app.get("/hsm/list")
async def hsmlist():
    return {'modules': hsm.hsmlist()}

@app.get("/hsm/{module}")
async def modlist(module):
    if not hsm.is_module(module):
        return {'error': 1, "message": "No such module"}
    return {'module': module, "slots": hsm.list_slots(module)}

@app.get("/hsm/{module}/{slot}")
async def slotlist(module, slot):
    if not hsm.is_module(module):
        return {'error': 1, "message": "No such module"}
    if not hsm.is_slot(module, slot):
        return {'error': 1, "message": "No such slot"}
    return {'module': module, "slot": slot, "objects": hsm.list_slot(module, slot), "mechanisms": hsm.list_slot_mech(module, slot)}

@app.post("/hsm/{module}/{slot}")
async def getobjdetails(module,slot,so: SearchObject):
    if not hsm.is_module(module):
        return {'error': 1, "message": "No such module"}
    if not hsm.is_slot(module, slot):
        return {'error': 1, "message": "No such slot"}
    return {'module': module, "slot": slot, "objects": hsm.getobjdetails(module,slot,so)}

@app.post("/hsm/{module}/{slot}/generate/rsa")
async def getobjdetails(module,slot,rsagen: RSAGenParam):
    if not hsm.is_module(module):
        return {'error': 1, "message": "No such module"}
    if not hsm.is_slot(module, slot):
        return {'error': 1, "message": "No such slot"}
    return {'module': module, "slot": slot, "result": hsm.gen_rsa(module,slot,rsagen)}

@app.post("/hsm/{module}/{slot}/generate/ec")
async def getobjdetails(module,slot,ecgen: ECGenParam):
    if not hsm.is_module(module):
        return {'error': 1, "message": "No such module"}
    if not hsm.is_slot(module, slot):
        return {'error': 1, "message": "No such slot"}
    return {'module': module, "slot": slot, "result": hsm.gen_ec(module,slot,ecgen)}

@app.post("/hsm/{module}/{slot}/destroy")
async def getobjdetails(module,slot,so: SearchObject):
    if not hsm.is_module(module):
        return {'error': 1, "message": "No such module"}
    if not hsm.is_slot(module, slot):
        return {'error': 1, "message": "No such slot"}
    return {'module': module, "slot": slot, "result": hsm.destroyobj(module,slot,so)}

