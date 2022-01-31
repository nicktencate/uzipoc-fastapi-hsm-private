from fastapi.testclient import TestClient

import pytest

from app.main import app, is_authorized


@pytest.fixture
def client():
    return TestClient(app)


def fakecheckcert(_ssl_cert, _module=None, _slot=None, _use=None, _key=None):
    return True

@pytest.fixture
def module(client, mocker):  # pylint: disable=redefined-outer-name
    # Skip authentication for this call always, but then return to
    # the implementation as it was before

    # pylint: disable=reimported, import-outside-toplevel
    from app.main import (
        is_authorized as tmp_is_authorized,
    )

    mocker.patch("app.main.is_authorized", fakecheckcert)
    resp = client.get("/hsm/list").json()["modules"][0]
    mocker.patch("app.main.is_authorized", tmp_is_authorized)
    return resp


@pytest.fixture
def slot(client, module, mocker):  # pylint: disable=redefined-outer-name
    # Skip authentication for this call always, but then return to
    # the implementation as it was before

    # pylint: disable=reimported, import-outside-toplevel
    from app.main import (
        is_authorized as tmp_is_authorized,
    )

    mocker.patch("app.main.is_authorized", fakecheckcert)
    resp = client.get(f"/hsm/{module}").json()["slots"][0]
    mocker.patch("app.main.is_authorized", tmp_is_authorized)
    return resp


@pytest.fixture(autouse=True)
def disable_authorization_middleware(mocker, request):
    """
    Only enable the authorization middleware layer in tests when explicitly
    requested

    Example:
    @pytest.mark.enable_authorization_middleware
    def test_something():
        # Authorization is active
        ...
    """
    if "enable_authorization_middleware" in request.keywords:
        mocker.patch("app.main.is_authorized", is_authorized)
        yield
    else:
        mocker.patch("app.main.is_authorized", fakecheckcert)
        yield
