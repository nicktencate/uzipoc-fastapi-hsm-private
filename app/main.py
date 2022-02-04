#!/usr/bin/env python3
"""
This file contains the API setup to communicate with the configured HSM,
defined using the FastAPI library.
"""
from typing import Union
from typing import Optional

from base64 import b64decode

import asn1crypto.x509

import yaml
from fastapi import FastAPI, Request, HTTPException, Header
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
    DeriveObject,
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


def isMatch(s, p):
    sl = len(s)
    pl = len(p)
    dp = [[False for i in range(pl + 1)] for j in range(sl + 1)]
    s = " " + s
    p = " " + p
    dp[0][0] = True
    for i in range(1, pl + 1):
        if p[i] == "*":
            dp[0][i] = dp[0][i - 1]
    for i in range(1, sl + 1):
        for j in range(1, pl + 1):
            if s[i] == p[j] or p[j] == "?":
                dp[i][j] = dp[i - 1][j - 1]
            elif p[j] == "*":
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    return dp[sl][pl]


def is_authorized(x_ssl_cert, module=None, slot=None, use=None, key=None):
    sslcert = (
        x_ssl_cert.replace(" ", "")
        .replace("-----BEGINCERTIFICATE-----", "")
        .replace("-----ENDCERTIFICATE-----", "")
    )
    der = b64decode(sslcert)
    subject = asn1crypto.x509.Certificate.load(der).subject.native["common_name"]

    ssl_module, ssl_slot, ssl_keyusage = subject.split("^")
    if not module:
        return True
    if not ssl_module == module:
        raise HTTPException(401, detail="Not authorized for module")

    if not slot:
        return True
    if not ssl_slot == slot:
        raise HTTPException(401, detail="Not authorized for slot")

    nlimits, ulimits = ssl_keyusage.split("=")
    ulimits = ulimits.split(",")
    nlimits = nlimits.split(",")

    if not use:
        return True
    if use not in ulimits:
        raise HTTPException(401, detail=f"Not authorized for usage: {use}")

    if not key:
        return True
    for nlimiter in nlimits:
        if isMatch(key, nlimiter):
            return True

    raise HTTPException(401, detail=f"Not authorized for key: {key}")


@app.get("/")
async def root(x_ssl_cert: Optional[str] = Header(None)):
    is_authorized(x_ssl_cert)
    return {"error": 0, "message": "working", "data": config}


@app.get("/hsm/list", tags=["Listing"])
async def hsmlist(x_ssl_cert: Optional[str] = Header(None)):
    is_authorized(x_ssl_cert)
    return {"modules": hsm.hsmlist()}


@app.get("/hsm/{module}", tags=["Listing"])
async def modlist(
    module: Modules,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module)
    return {"module": module, "slots": hsm.list_slots(module)}


@app.get("/hsm/{module}/{slot}", tags=["Listing"])
async def slotlist(
    module: Modules,
    slot: Slots,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot)
    return {
        "module": module,
        "slot": slot,
        "objects": hsm.list_slot(module, slot),
        "mechanisms": hsm.list_slot_mech(module, slot),
    }


@app.post("/hsm/{module}/{slot}", tags=["Listing"])
async def getobjdetails(
    module: Modules,
    slot: Slots,
    so: SearchObject,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "use", so.label)
    return {
        "module": module,
        "slot": slot,
        "objects": hsm.getobjdetails(module, slot, so),
    }


@app.post("/hsm/{module}/{slot}/generate/rsa", tags=["Key generation"])
async def genrsa(
    module: Modules,
    slot: Slots,
    rsagen: RSAGenParam,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "create", rsagen.label)
    return {"module": module, "slot": slot, "result": hsm.gen_rsa(module, slot, rsagen)}


@app.post("/hsm/{module}/{slot}/generate/dsa", tags=["Key generation"])
async def gendsa(
    module: Modules,
    slot: Slots,
    dsagen: DSAGenParam,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "create", dsagen.label)
    return {"module": module, "slot": slot, "result": hsm.gen_dsa(module, slot, dsagen)}


@app.post("/hsm/{module}/{slot}/generate/aes", tags=["Key generation"])
async def genaes(
    module: Modules,
    slot: Slots,
    aesgen: AESGenParam,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "create", aesgen.label)
    return {"module": module, "slot": slot, "result": hsm.gen_aes(module, slot, aesgen)}


@app.post("/hsm/{module}/{slot}/generate/ec", tags=["Key generation"])
async def genec(
    module: Modules,
    slot: Slots,
    ecgen: ECGenParam,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "create", ecgen.label)
    return {"module": module, "slot": slot, "result": hsm.gen_ec(module, slot, ecgen)}


@app.post("/hsm/{module}/{slot}/generate/edwards", tags=["Key generation"])
async def genedwards(
    module: Modules,
    slot: Slots,
    ecgen: ECGenParam,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "create", ecgen.label)
    return {
        "module": module,
        "slot": slot,
        "result": hsm.gen_edwards(module, slot, ecgen),
    }


@app.post("/hsm/{module}/{slot}/destroy", tags=["Object removal"])
async def destroyobj(
    module: Modules,
    slot: Slots,
    so: SearchObject,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "destroy", so.label)
    return {"module": module, "slot": slot, "result": hsm.destroyobj(module, slot, so)}


@app.post("/hsm/{module}/{slot}/encrypt", tags=["Key usage"])
async def encrypt(
    module: Modules,
    slot: Slots,
    so: DecryptEncryptObject,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "use", so.label)
    return {"module": module, "slot": slot, "result": hsm.encrypt(module, slot, so)}


@app.post("/hsm/{module}/{slot}/decrypt", tags=["Key usage"])
async def decrypt(
    module: Modules,
    slot: Slots,
    so: DecryptEncryptObject,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "use", so.label)
    return {"module": module, "slot": slot, "result": hsm.decrypt(module, slot, so)}


@app.post("/hsm/{module}/{slot}/sign", tags=["Key usage"])
async def sign(
    module: Modules,
    slot: Slots,
    so: Union[SignRSAObject, SignAESObject],
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "use", so.label)
    return {"module": module, "slot": slot, "result": hsm.sign(module, slot, so)}


@app.post("/hsm/{module}/{slot}/verify", tags=["Key usage"])
async def verify(
    module: Modules,
    slot: Slots,
    so: Union[VerifyRSAObject, VerifyAESObject],
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "use", so.label)
    return {"module": module, "slot": slot, "result": hsm.verify(module, slot, so)}


@app.post("/hsm/{module}/{slot}/wrap", tags=["Key usage"])
async def wrap(
    module: Modules,
    slot: Slots,
    so: WrapAESObject,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "use", so.label)
    return {"module": module, "slot": slot, "result": hsm.wrap(module, slot, so)}


@app.post("/hsm/{module}/{slot}/unwrap", tags=["Key usage"])
async def unwrap(
    module: Modules,
    slot: Slots,
    so: WrapAESObject,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "use", so.label)
    return {"module": module, "slot": slot, "result": hsm.unwrap(module, slot, so)}


@app.post("/hsm/{module}/{slot}/derive", tags=["Key usage"])
async def derive(
    module: Modules,
    slot: Slots,
    so: DeriveObject,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "use", so.label)
    return {"module": module, "slot": slot, "result": hsm.derive(module, slot, so)}


@app.post("/hsm/{module}/{slot}/import", tags=["Import"])
async def importdata(
    module: Modules,
    slot: Slots,
    so: ImportObject,
    x_ssl_cert: Optional[str] = Header(None),
):
    is_authorized(x_ssl_cert, module, slot, "import", so.label)
    return {
        "module": module,
        "slot": slot,
        "objects": hsm.importdata(module, slot, so),
    }
