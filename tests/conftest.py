from fastapi.testclient import TestClient

import pytest

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def module(clientarg):
    return clientarg.get("/hsm/list").json()["modules"][0]


@pytest.fixture
def slot(clientarg, modulearg):
    return clientarg.get(f"/hsm/{modulearg}").json()["slots"][0]
