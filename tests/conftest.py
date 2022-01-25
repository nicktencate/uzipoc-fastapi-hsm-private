from fastapi.testclient import TestClient

import pytest

from app.main import app, is_authorized


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def module(client, mocker):  # pylint: disable=redefined-outer-name
    # Skip authentication for this call
    mocker.patch("app.main.is_authorized", lambda x: True)
    resp = client.get("/hsm/list").json()["modules"][0]
    mocker.patch("app.main.is_authorized", is_authorized)
    return resp


@pytest.fixture
def slot(client, module, mocker):  # pylint: disable=redefined-outer-name
    # Skip authentication for this call
    mocker.patch("app.main.is_authorized", lambda x: True)
    resp = client.get(f"/hsm/{module}").json()["slots"][0]
    mocker.patch("app.main.is_authorized", is_authorized)
    return resp
