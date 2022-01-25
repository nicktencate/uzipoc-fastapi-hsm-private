from fastapi.exceptions import HTTPException

import pytest


def test_successful_authorization(client, module, slot):
    # Some random call that requires authentication:
    params = {"bits": 256, "label": "AESkey"}
    headers = {"Authorization": "Mendel:BugBlue"}
    resp = client.post(f"/hsm/{module}/{slot}/generate/aes", json=params, headers=headers).json()
    assert len(resp) > 0


def test_unsuccessful_authorization(client, module, slot):
    # Some random call that requires authentication:
    params = {"bits": 256, "label": "AESkey"}
    headers = {"Authorization": "Not:Valid"}
    with pytest.raises(HTTPException):
        client.post(f"/hsm/{module}/{slot}/generate/aes", json=params, headers=headers).json()
    
    
