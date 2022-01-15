#!/usr/bin/env python3
"""
This file contains the models, defining what data is required for the requests defined in our FastAPI router.
"""
from typing import Optional
from enum import Enum
from pydantic import BaseModel  # pylint: disable=no-name-in-module


class HSMError(Exception):
    """
    Base Exception for HSM Errors.
    """

    def __init__(self, message):
        self.message = message
        super().__init__()


class BaseModules(str, Enum):
    """
    Dynamic Enum used for listing available modules in the HSM.
    """


class BaseSlots(str, Enum):
    """
    Dynamic Enum used for listing  available slots in all HSM Modules.
    """


class RSAbits(int, Enum):
    B11 = 2 ** 11
    B12 = 2 ** 12
    B13 = 2 ** 13
    B14 = 2 ** 14


class DSAbits(int, Enum):
    B10 = 2 ** 10
    B11 = 2 ** 11
    B12 = 2 ** 11


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
    # TODO: pydantic validators.
    label: Optional[str] = None
    objtype: Optional[SearchObjectEnum] = None
    objid: Optional[str] = None


class DecryptEncryptObject(SearchObject):  # pylint: disable=too-few-public-methods
    data: Optional[str] = None
    # TODO: Pydantic validator default mechanism: SHA256_RSA_PKCS_PSS
    mechanism: Optional[str] = None
    hashmethod: Optional[HashMethod] = None
    iv: Optional[str] = None


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


class DSAGenParam(RSAAESGenParam):  # pylint: disable=too-few-public-methods
    bits: RSAbits = DSAbits.B11


class ECGenParam(BaseModel):  # pylint: disable=too-few-public-methods
    # TODO: pydantic validators: secp256r1 == prime256v1 (alias)
    #
    label: Optional[str] = None
    objid: Optional[str] = None
    curve: Optional[str] = None
