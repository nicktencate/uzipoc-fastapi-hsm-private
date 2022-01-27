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
    NULL = "NULL"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA224 = "sha224"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    DHSHA1 = "dhSinglePass-stdDH-sha1kdf-scheme"
    DHSHA224 = "dhSinglePass-stdDH-sha224kdf-scheme"
    DHSHA256 = "dhSinglePass-stdDH-sha256kdf-scheme"
    DHSHA384 = "dhSinglePass-stdDH-sha384kdf-scheme"
    DHSHA512 = "dhSinglePass-stdDH-sha512kdf-scheme"


class SearchObjectEnum(str, Enum):
    PUBLIC = "PUBLIC_KEY"
    PRIVATE = "PRIVATE_KEY"
    SECRET = "SECRET_KEY"
    DATA = "DATA"
    CERTIFICATE = "CERTIFICATE"


class WrapObject(str, Enum):
    AES128W = "aes128_wrap"
    AES192W = "aes192_wrap"
    AES256W = "aes256_wrap"
    AES128 = "aes128"
    AES192 = "aes192"
    AES125 = "aes256"


class SearchObject(BaseModel):  # pylint: disable=too-few-public-methods
    # TODO: pydantic validators.
    label: Optional[str] = None
    objtype: Optional[SearchObjectEnum] = None
    objid: Optional[str] = None


class ImportObject(SearchObject):  # pylint: disable=too-few-public-methods
    data: Optional[str] = None
    pem: Optional[bool] = False


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


class DeriveObject(SearchObject):  # pylint: disable=too-few-public-methods
    wrap: Optional[WrapObject] = None
    unwrap: Optional[WrapObject] = None
    sharedinfo: Optional[str] = None
    algorithm: Optional[HashMethod] = None
    otherpub: Optional[str] = None
    size: Optional[int] = None
    data: Optional[str] = None


class SignRSAObject(SignObject):  # pylint: disable=too-few-public-methods
    hashmethod: Optional[HashMethod] = None


class SignAESObject(SignObject):  # pylint: disable=too-few-public-methods
    mechanism: Optional[str] = None
    hashmethod: Optional[HashMethod] = None


class WrapAESObject(SignObject):  # pylint: disable=too-few-public-methods
    data: str = None
    mechanism: Optional[str] = None


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
