#!/usr/bin/env python3
from typing import Union

import yaml
from fastapi import FastAPI, HTTPException

from modules.hsm import HSMModule
from modules.model import (Modules, Slots, SearchObject, RSAGenParam, AESGenParam, ECGenParam,
                           DecryptEncryptObject, VerifyRSAObject, VerifyAESObject, SignRSAObject,
                           SignAESObject)

with open('conf.yml', 'r', encoding='utf-8') as yamlfile:
    config = yaml.load(yamlfile ,Loader=yaml.Loader)

hsm = HSMModule(config)

app = FastAPI()

@app.get("/")
async def root():
    return {"error": 0, "message": "working", "data": config}

@app.get("/hsm/list")
async def hsmlist():
    return {'modules': hsm.hsmlist()}

def doesexist(module, slot):
    if not hsm.is_module(module):
        raise HTTPException(status_code=404, detail="No such module")
    if not hsm.is_slot(module, slot):
        raise HTTPException(status_code=404, detail="No such slot")

@app.get("/hsm/{module}")
async def modlist(module: Modules):
    if not hsm.is_module(module):
        return {'error': 1, "message": "No such module"}
    return {'module': module, "slots": hsm.list_slots(module)}

@app.get("/hsm/{module}/{slot}")
async def slotlist(module: Modules, slot: Slots):
    doesexist(module, slot)
    return {'module': module, "slot": slot, "objects": hsm.list_slot(module, slot), "mechanisms": hsm.list_slot_mech(module, slot)}

@app.post("/hsm/{module}/{slot}")
async def getobjdetails(module: Modules, slot: Slots, so: SearchObject):
    doesexist(module, slot)
    return {'module': module, "slot": slot, "objects": hsm.getobjdetails(module, slot, so)}

@app.post("/hsm/{module}/{slot}/generate/rsa")
async def genrsa(module: Modules, slot: Slots, rsagen: RSAGenParam):
    doesexist(module, slot)
    return {'module': module, "slot": slot, "result": hsm.gen_rsa(module, slot, rsagen)}

@app.post("/hsm/{module}/{slot}/generate/aes")
async def genaes(module: Modules, slot: Slots, aesgen: AESGenParam):
    doesexist(module, slot)
    return {'module': module, "slot": slot, "result": hsm.gen_aes(module, slot, aesgen)}

@app.post("/hsm/{module}/{slot}/generate/ec")
async def genec(module: Modules, slot: Slots, ecgen: ECGenParam):
    doesexist(module, slot)
    return {'module': module, "slot": slot, "result": hsm.gen_ec(module, slot, ecgen)}

@app.post("/hsm/{module}/{slot}/generate/ec")
async def genedwards(module: Modules, slot: Slots, ecgen: ECGenParam):
    doesexist(module, slot)
    return {'module': module, "slot": slot, "result": hsm.gen_edwards(module, slot, ecgen)}

@app.post("/hsm/{module}/{slot}/destroy")
async def destroyobj(module: Modules, slot: Slots, so: SearchObject):
    doesexist(module, slot)
    return {'module': module, "slot": slot, "result": hsm.destroyobj(module, slot, so)}

@app.post("/hsm/{module}/{slot}/encrypt")
async def encrypt(module: Modules, slot: Slots, so: DecryptEncryptObject):
    doesexist(module, slot)
    return {'module': module, "slot": slot, "result": hsm.encrypt(module, slot, so)}

@app.post("/hsm/{module}/{slot}/decrypt")
async def decrypt(module: Modules, slot: Slots, so: DecryptEncryptObject):
    doesexist(module, slot)
    return {'module': module, "slot": slot, "result": hsm.decrypt(module, slot, so)}

@app.post("/hsm/{module}/{slot}/sign")
async def sign(module: Modules, slot: Slots, so: Union[SignRSAObject, SignAESObject]):
    doesexist(module, slot)
    return {'module': module, "slot": slot, "result": hsm.sign(module, slot, so)}

@app.post("/hsm/{module}/{slot}/verify")
async def verify(module: Modules, slot: Slots, so: Union[VerifyRSAObject, VerifyAESObject]):
    doesexist(module, slot)
    return {'module': module, "slot": slot, "result": hsm.verify(module, slot, so)}

@app.post("/hsm/{module}/{slot}/wrap")
async def wrap(module: Modules, slot: Slots, so: SearchObject):
    doesexist(module, slot)
    return {'module': module, "slot": slot, "result": hsm.wrap(module, slot, so)}

@app.post("/hsm/{module}/{slot}/unwrap")
async def unwrap(module: Modules, slot: Slots, so: SearchObject):
    doesexist(module, slot)
    return {'module': module, "slot": slot, "result": hsm.unwrap(module, slot, so)}

# import pkcs11
# import pkcs11.util
# import pkcs11.util.rsa
# from pkcs11.util.ec import encode_named_curve_parameters
# import asn1crypto.pem
# from asn1crypto.keys import ECDomainParameters
# lib = pkcs11.lib('/usr/lib64/pkcs11/libsofthsm2.so')
# token = lib.get_token(token_label='HSM-000')
# session = token.open(rw=True, user_pin='1234')
