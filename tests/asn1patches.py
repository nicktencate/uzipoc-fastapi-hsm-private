import asn1crypto.cms
import asn1crypto.algos
import asn1crypto.keys

asn1crypto.cms.CMSAttributeType._map[  # pylint: disable=protected-access
    "1.2.840.113549.1.9.15"
] = "smimeCapabilities"


extrakeai = {
  "1.3.133.16.840.63.0.2": "dhSinglePass-stdDH-sha1kdf-scheme",
  "1.3.132.1.11.0": "dhSinglePass-stdDH-sha224kdf-scheme",
  "1.3.132.1.11.1": "dhSinglePass-stdDH-sha256kdf-scheme",
  "1.3.132.1.11.2": "dhSinglePass-stdDH-sha384kdf-scheme",
  "1.3.132.1.11.3": "dhSinglePass-stdDH-sha512kdf-scheme",
}
asn1crypto.cms.KeyEncryptionAlgorithmId._map.update(extrakeai)   # pylint: disable=protected-access

extraea = {
    "dhSinglePass-stdDH-sha1kdf-scheme": asn1crypto.algos.EncryptionAlgorithm,
    "dhSinglePass-stdDH-sha224kdf-scheme": asn1crypto.algos.EncryptionAlgorithm,
    "dhSinglePass-stdDH-sha256kdf-scheme": asn1crypto.algos.EncryptionAlgorithm,
    "dhSinglePass-stdDH-sha384kdf-scheme": asn1crypto.algos.EncryptionAlgorithm,
    "dhSinglePass-stdDH-sha512kdf-scheme": asn1crypto.algos.EncryptionAlgorithm,
}
asn1crypto.cms.KeyEncryptionAlgorithm._oid_specs.update(extraea)   # pylint: disable=protected-access


class SMIMECapability(asn1crypto.core.SequenceOf):
    _child_spec = asn1crypto.algos.EncryptionAlgorithm


class SMIMECapabilities(asn1crypto.core.SetOf):
    _child_spec = SMIMECapability


asn1crypto.cms.CMSAttribute._oid_specs[  # pylint: disable=protected-access
    "smimeCapabilities"
] = SMIMECapabilities

asn1crypto.algos.EncryptionAlgorithm._oid_specs[  # pylint: disable=protected-access
    "rc2"
] = asn1crypto.core.Integer

# default asn1crypto does not know about. development on github version knows
extrapai = {
    "1.3.101.110": "x25519",
    "1.3.101.111": "x448",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
}
asn1crypto.keys.PublicKeyAlgorithmId._map.update(extrapai)  # pylint: disable=protected-access
extrasdai = {
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
}
asn1crypto.algos.SignedDigestAlgorithmId._map.update(extrasdai)  # pylint: disable=protected-access
asn1crypto.algos.SignedDigestAlgorithmId._reverse_map.update({extrasdai[x]:x for x in extrasdai.keys()})  # pylint: disable=protected-access

savecallback = None


def switchcallback():
    global savecallback  # pylint: disable=global-statement
    newsavecallback = (
        asn1crypto.keys.PublicKeyInfo._spec_callbacks  # pylint: disable=protected-access
    )
    asn1crypto.keys.PublicKeyInfo._spec_callbacks = (  # pylint: disable=protected-access
        savecallback
    )
    savecallback = newsavecallback
