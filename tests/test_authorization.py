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
    assert len(resp["result"]) > 0


@pytest.mark.enable_authorization_middleware
def test_successful_authorization2(client, module, slot):
    # Some random call that requires authentication:
    headers = {"x-ssl-cert": makecert(f"{module}^{slot}^*=use")}
    resp = client.get("/", headers=headers).json()
    assert len(resp["data"]) > 0


@pytest.mark.enable_authorization_middleware
def test_successful_authorization3(client, module, slot):
    # Some random call that requires authentication:
    params = {"bits": 256, "label": "AESkey43"}
    headers = {"x-ssl-cert": makecert(f"{module}^{slot}^AESkey??=create")}
    resp = client.post(
        f"/hsm/{module}/{slot}/generate/aes", json=params, headers=headers
    ).json()
    assert len(resp["result"]) > 0


@pytest.mark.enable_authorization_middleware
def test_successful_authorization4(client, module, slot):
    # Some random call that requires authentication:
    headers = {"x-ssl-cert": makecert(f"{module}^{slot}^*=use")}
    resp = client.get(f"/hsm/{module}", headers=headers).json()
    assert resp == {"module": module, "slots": [slot]}


@pytest.mark.enable_authorization_middleware
def test_successful_authorization5(client, module, slot):
    # Some random call that requires authentication:
    headers = {"x-ssl-cert": makecert(f"{module}^{slot}^*=use")}
    resp = client.get(f"/hsm/{module}/{slot}", headers=headers).json()
    assert len(resp["mechanisms"]) > 5


@pytest.mark.enable_authorization_middleware
def test_successful_authorization6(client, module, slot):
    # Some random call that requires authentication:
    params = {"label": None, "objtype": "PUBLIC_KEY"}
    headers = {"x-ssl-cert": makecert(f"{module}^{slot}^*=use")}
    resp = client.post(f"/hsm/{module}/{slot}", headers=headers, json=params).json()
    assert len(resp["objects"]) > 5


@pytest.mark.enable_authorization_middleware
def test_unsuccessful_authorization(client, module, slot):
    # Some random call that requires authentication:
    params = {"bits": 256, "label": "AESkey42"}
    headers = {"x-ssl-cert": makecert(f"{module}^{slot}^*=use")}
    assert client.post(
        f"/hsm/{module}/{slot}/generate/aes", json=params, headers=headers
    ).json() == {"detail": "Not authorized for usage: create"}


@pytest.mark.enable_authorization_middleware
def test_unsuccessful_authorization2(client, module, slot):
    # Some random call that requires authentication:
    headers = {"x-ssl-cert": makecert(f"no-{module}^{slot}^*=use")}
    resp = client.get(f"/hsm/{module}/{slot}", headers=headers).json()
    assert resp == {"detail": "Not authorized for module"}


@pytest.mark.enable_authorization_middleware
def test_unsuccessful_authorization3(client, module, slot):
    # Some random call that requires authentication:
    headers = {"x-ssl-cert": makecert(f"{module}^no-{slot}^*=use")}
    resp = client.get(f"/hsm/{module}/{slot}", headers=headers).json()
    assert resp == {"detail": "Not authorized for slot"}


@pytest.mark.enable_authorization_middleware
def test_unsuccessful_authorization7(client, module, slot):
    # Some random call that requires authentication:
    params = {"label": "RSAkey", "objtype": "PUBLIC_KEY"}
    headers = {"x-ssl-cert": makecert(f"{module}^{slot}^EC*=use")}
    resp = client.post(f"/hsm/{module}/{slot}", headers=headers, json=params).json()
    assert resp == {"detail": "Not authorized for key: RSAkey"}
