#!/usr/bin/env python3
"""
This file contains the API setup to communicate with the configured HSM,
defined using the FastAPI library.
"""
import sys
from typing import Union

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .modules.hsm import HSMModule
from .modules.model import (
    BaseModules,
    BaseSlots,
    HSMError,
    SearchObject,
    RSAGenParam,
    DSAGenParam,
    AESGenParam,
    ECGenParam,
    DecryptEncryptObject,
    VerifyRSAObject,
    VerifyAESObject,
    SignRSAObject,
    SignAESObject,
    ImportObject,
    WrapAESObject,
)

with open("conf.yml", "r", encoding="utf-8") as yamlfile:
    config = yaml.load(yamlfile, Loader=yaml.Loader)

hsm = HSMModule(config)

Modules = BaseModules("Modules", {x: x for x in hsm.modules})
Slots = BaseSlots(
    "Slots", {item: item for module in hsm.modules.items() for item in module[1]}
)


description = """
The HSM Controller Unit allows communication with the configured Hardware Security Model through an API interface.\n To
summarize, there are three basic type of operations allowed through this API:

* **Listing of objects** Allows operations to be perfomed in order to list: modules, slots and objects.
* **Generation of keys** Allows the generation and storage of new keys in the configured Hardware Security Module.
* **Encryption & Signing of data** Allows the encryption and signing of data using one of the stored in the Hardware Securiy Module.
\n
\n
For those unfamiliar with a Hardware Security Modules, a short summary:\n
...\n
**wrap**\n
(for more details, see: )\n
"""

tags_metadata = [
    {
        "name": "Listing",
        "description": "List modules, slots and objects.",
    },
    {
        "name": "Key generation",
        "description": "Generate new keys: Elliptic Curves, RSA, AES",
    },
    {
        "name": "Object removal",
        "description": "Remove an object",
    },
    {
        "name": "Key usage",
        "description": "Use available keys to sign and encrypt data.",
        "externalDocs": {
            "description": "Items external docs",
            "url": "https://fastapi.tiangolo.com/",
        },
    },
]


app = FastAPI(
    title="HSM Controller Unit",
    description=description,
    version="0.0.1",
    terms_of_service="...",
    contact={
        "name": "RDO Beheer",
        "url": "https://helpdesk.rdobeheer.nl",
        "email": "helpdesk@rdobeheer.nl",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },
    openapi_tags=tags_metadata,
)


@app.exception_handler(HSMError)
async def fallback_exception_handler(_: Request, exc: HSMError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error": "Unprocessible HSM Request",
            "error_description": exc.message,
        },
    )


USERNAME = "Mendel"
PASSWORD = "BugBlue"


def is_authorized(request: Request):
    if "Authorization" not in request.headers:
        return False

    username, password = request.headers["Authorization"].split(":")
    if not (username == USERNAME and password == PASSWORD):
        return False

    return True


@app.middleware("http")
async def check_authorization(request: Request, call_next):
    if not is_authorized(request):
        raise HTTPException(401, detail="Not authorized")

    return await call_next(request)


@app.get("/")
async def root():
    return {"error": 0, "message": "working", "data": config}


@app.get("/hsm/list", tags=["Listing"])
async def hsmlist():
    return {"modules": hsm.hsmlist()}


def doesexist(module, slot):
    if not hsm.is_module(module):
        raise HTTPException(status_code=404, detail="No such module")
    if not hsm.is_slot(module, slot):
        raise HTTPException(status_code=404, detail="No such slot")


@app.get("/hsm/{module}", tags=["Listing"])
async def modlist(module: Modules):
    if not hsm.is_module(module):
        return {"error": 1, "message": "No such module"}
    return {"module": module, "slots": hsm.list_slots(module)}


@app.get("/hsm/{module}/{slot}", tags=["Listing"])
async def slotlist(module: Modules, slot: Slots):
    doesexist(module, slot)
    return {
        "module": module,
        "slot": slot,
        "objects": hsm.list_slot(module, slot),
        "mechanisms": hsm.list_slot_mech(module, slot),
    }


@app.post("/hsm/{module}/{slot}", tags=["Listing"])
async def getobjdetails(module: Modules, slot: Slots, so: SearchObject):
    doesexist(module, slot)
    return {
        "module": module,
        "slot": slot,
        "objects": hsm.getobjdetails(module, slot, so),
    }


@app.post("/hsm/{module}/{slot}/generate/rsa", tags=["Key generation"])
async def genrsa(module: Modules, slot: Slots, rsagen: RSAGenParam):
    doesexist(module, slot)
    return {"module": module, "slot": slot, "result": hsm.gen_rsa(module, slot, rsagen)}


@app.post("/hsm/{module}/{slot}/generate/dsa", tags=["Key generation"])
async def gendsa(module: Modules, slot: Slots, dsagen: DSAGenParam):
    doesexist(module, slot)
    return {"module": module, "slot": slot, "result": hsm.gen_dsa(module, slot, dsagen)}


@app.post("/hsm/{module}/{slot}/generate/aes", tags=["Key generation"])
async def genaes(module: Modules, slot: Slots, aesgen: AESGenParam):
    doesexist(module, slot)
    return {"module": module, "slot": slot, "result": hsm.gen_aes(module, slot, aesgen)}


# TODO: This endpoint is overwritten by the endpoint below (line: 122)
@app.post("/hsm/{module}/{slot}/generate/ec", tags=["Key generation"])
async def genec(module: Modules, slot: Slots, ecgen: ECGenParam):
    doesexist(module, slot)
    return {"module": module, "slot": slot, "result": hsm.gen_ec(module, slot, ecgen)}


@app.post("/hsm/{module}/{slot}/generate/edwards", tags=["Key generation"])
async def genedwards(module: Modules, slot: Slots, ecgen: ECGenParam):
    doesexist(module, slot)
    return {
        "module": module,
        "slot": slot,
        "result": hsm.gen_edwards(module, slot, ecgen),
    }


@app.post("/hsm/{module}/{slot}/destroy", tags=["Object removal"])
async def destroyobj(module: Modules, slot: Slots, so: SearchObject):
    doesexist(module, slot)
    return {"module": module, "slot": slot, "result": hsm.destroyobj(module, slot, so)}


@app.post("/hsm/{module}/{slot}/encrypt", tags=["Key usage"])
async def encrypt(module: Modules, slot: Slots, so: DecryptEncryptObject):
    doesexist(module, slot)
    return {"module": module, "slot": slot, "result": hsm.encrypt(module, slot, so)}


@app.post("/hsm/{module}/{slot}/decrypt", tags=["Key usage"])
async def decrypt(module: Modules, slot: Slots, so: DecryptEncryptObject):
    doesexist(module, slot)
    return {"module": module, "slot": slot, "result": hsm.decrypt(module, slot, so)}


@app.post("/hsm/{module}/{slot}/sign", tags=["Key usage"])
async def sign(module: Modules, slot: Slots, so: Union[SignRSAObject, SignAESObject]):
    doesexist(module, slot)
    return {"module": module, "slot": slot, "result": hsm.sign(module, slot, so)}


@app.post("/hsm/{module}/{slot}/verify", tags=["Key usage"])
async def verify(
    module: Modules, slot: Slots, so: Union[VerifyRSAObject, VerifyAESObject]
):
    doesexist(module, slot)
    return {"module": module, "slot": slot, "result": hsm.verify(module, slot, so)}


@app.post("/hsm/{module}/{slot}/wrap", tags=["Key usage"])
async def wrap(module: Modules, slot: Slots, so: WrapAESObject):
    doesexist(module, slot)
    return {"module": module, "slot": slot, "result": hsm.wrap(module, slot, so)}


@app.post("/hsm/{module}/{slot}/unwrap", tags=["Key usage"])
async def unwrap(module: Modules, slot: Slots, so: WrapAESObject):
    doesexist(module, slot)
    return {"module": module, "slot": slot, "result": hsm.unwrap(module, slot, so)}


@app.post("/hsm/{module}/{slot}/import", tags=["Import"])
async def importdata(module: Modules, slot: Slots, so: ImportObject):
    doesexist(module, slot)
    return {
        "module": module,
        "slot": slot,
        "objects": hsm.importdata(module, slot, so),
    }


@app.get("/stopandexit", tags=["Development only"])
async def stopandexit():
    sys.exit()
