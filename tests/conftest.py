from fastapi.testclient import TestClient

import pytest

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def module(client):  # pylint: disable=redefined-outer-name
    return client.get("/hsm/list").json()["modules"][0]


@pytest.fixture
def slot(client, module):  # pylint: disable=redefined-outer-name
    return client.get(f"/hsm/{module}").json()["slots"][0]
