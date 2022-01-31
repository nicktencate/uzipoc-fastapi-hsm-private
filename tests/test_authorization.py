from base64 import b64encode

import asn1crypto.keys
import asn1crypto.x509

import pytest

import tests.certgen


def makecert(name):
    asn1pk = asn1crypto.keys.PublicKeyInfo(
        {
            "algorithm": {"algorithm": "rsa", "parameters": None},
            "public_key": {"modulus": 0, "public_exponent": 0},
        }
    )
    thecert = asn1crypto.x509.Certificate(
        {
            "tbs_certificate": tests.certgen.certgen(
                name, asn1pk, {"algorithm": "md5_rsa"}
            ),
            "signature_value": b"\x00",
            "signature_algorithm": {"algorithm": "md5_rsa"},
        }
    )
    return b64encode(thecert.dump()).decode()


@pytest.mark.enable_authorization_middleware
def test_successful_authorization(client, module, slot):
    # Some random call that requires authentication:
    params = {"bits": 256, "label": "AESkey42"}
    headers = {"x-ssl-cert": makecert(f"{module}^{slot}^*=create")}
    resp = client.post(
        f"/hsm/{module}/{slot}/generate/aes", json=params, headers=headers
    ).json()
    assert len(resp) > 0


@pytest.mark.enable_authorization_middleware
def test_unsuccessful_authorization(client, module, slot):
    # Some random call that requires authentication:
    params = {"bits": 256, "label": "AESkey42"}
    headers = {"x-ssl-cert": makecert(f"{module}^{slot}^*=use")}
    assert client.post(
        f"/hsm/{module}/{slot}/generate/aes", json=params, headers=headers
    ).json() == {"detail": "Not authorized for usage: create"}
