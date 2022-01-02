#!/usr/bin/env python3
from typing import Optional, Union
from enum import Enum
from pydantic import BaseModel # pylint: disable=no-name-in-module

class HSMError(Exception):
    pass

class Modules(str, Enum):
    SOFTHSM = "softhsm"
    YUBIKEY = "yubikey"

class Slots(str, Enum):
    HSM0 = "HSM-000"
    HSM1 = "HSM-001"
    YK1 = "YubiKey PIV #9986290"

class SearchObject(BaseModel):  # pylint: disable=too-few-public-methods
    label: Optional[str] = None
    objtype: Optional[str] = None
    objid: Optional[str] = None

class DataSearchObject(BaseModel):  # pylint: disable=too-few-public-methods
    label: Optional[str] = None
    objtype: Optional[str] = None
    objid: Optional[str] = None
    data: Optional[str] = None
    mechanism: Optional[str] = None
    mechanismparam: Optional[Union[list, str]] = None
    iv: Optional[str] = None

class RSAAESGenParam(BaseModel):  # pylint: disable=too-few-public-methods
    label: Optional[str] = None
    objid: Optional[str] = None

class RSAGenParam(RSAAESGenParam):  # pylint: disable=too-few-public-methods
    bits: Optional[int] = 2048

class AESGenParam(RSAAESGenParam):  # pylint: disable=too-few-public-methods
    bits: Optional[int] = 256

class ECGenParam(BaseModel):  # pylint: disable=too-few-public-methods
    label: Optional[str] = None
    objid: Optional[str] = None
    curve: Optional[str] = None
