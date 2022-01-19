import asn1crypto.cms
import asn1crypto.algos
import asn1crypto.keys

asn1crypto.cms.CMSAttributeType._map[  # pylint: disable=protected-access
    "1.2.840.113549.1.9.15"
] = "smimeCapabilities"


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
asn1crypto.keys.PublicKeyAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.110"
] = "x25519"
asn1crypto.keys.PublicKeyAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.111"
] = "x448"
asn1crypto.keys.PublicKeyAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.112"
] = "ed25519"
asn1crypto.keys.PublicKeyAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.113"
] = "ed448"
asn1crypto.algos.SignedDigestAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.112"
] = "ed25519"
asn1crypto.algos.SignedDigestAlgorithmId._map[  # pylint: disable=protected-access
    "1.3.101.113"
] = "ed448"
asn1crypto.algos.SignedDigestAlgorithmId._reverse_map[  # pylint: disable=protected-access
    "ed25519"
] = "1.3.101.112"
asn1crypto.algos.SignedDigestAlgorithmId._reverse_map[  # pylint: disable=protected-access
    "ed448"
] = "1.3.101.113"
asn1crypto.keys.PublicKeyInfo._spec_callbacks = None  # pylint: disable=protected-access
