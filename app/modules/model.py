#!/usr/bin/env python3
from typing import Optional
from enum import Enum
from pydantic import BaseModel # pylint: disable=no-name-in-module

class HSMError(Exception):
    pass

class BaseModules(str, Enum):
    pass

class BaseSlots(str, Enum):
    pass

class RSAbits(int, Enum):
    B11 = 2**11
    B12 = 2**12
    B13 = 2**13
    B14 = 2**14

class AESbits(int, Enum):
    B256 = 256
    B192 = 192
    B128 = 128

class HashMethod(str, Enum):
    SHA1 = "sha1"
    SHA224 = "sha224"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"

class SearchObjectEnum(str, Enum):
    PUBLIC = "PUBLIC_KEY"
    PRIVATE = "PRIVATE_KEY"
    SECRET = "SECRET_KEY"
    DATA = "DATA"
    CERTIFICATE = "CERTIFICATE"

class SearchObject(BaseModel):  # pylint: disable=too-few-public-methods
    label: Optional[str] = None
    objtype: Optional[SearchObjectEnum] = None
    objid: Optional[str] = None

class DecryptEncryptObject(SearchObject):  # pylint: disable=too-few-public-methods
    data: Optional[str] = None
    mechanism: Optional[str] = None
    hashmethod: Optional[HashMethod] = None

class VerifyObject(SearchObject):  # pylint: disable=too-few-public-methods
    data: Optional[str] = None
    mechanism: Optional[str] = None
    signature: Optional[str] = None

class VerifyRSAObject(VerifyObject):  # pylint: disable=too-few-public-methods
    hashmethod: Optional[HashMethod] = None

class VerifyAESObject(VerifyObject):  # pylint: disable=too-few-public-methods
    iv: Optional[str] = None

class SignObject(SearchObject):  # pylint: disable=too-few-public-methods
    data: Optional[str] = None
    mechanism: Optional[str] = None

class SignRSAObject(SignObject):  # pylint: disable=too-few-public-methods
    hashmethod: Optional[HashMethod] = None

class SignAESObject(SignObject):  # pylint: disable=too-few-public-methods
    # We don't let users supply their own IV.
    pass

class RSAAESGenParam(BaseModel):  # pylint: disable=too-few-public-methods
    label: Optional[str] = None
    objid: Optional[str] = None

class RSAGenParam(RSAAESGenParam):  # pylint: disable=too-few-public-methods
    bits: RSAbits = RSAbits.B11

class AESGenParam(RSAAESGenParam):  # pylint: disable=too-few-public-methods
    bits: AESbits = AESbits.B256

class ECGenParam(BaseModel):  # pylint: disable=too-few-public-methods
    label: Optional[str] = None
    objid: Optional[str] = None
    curve: Optional[str] = None
