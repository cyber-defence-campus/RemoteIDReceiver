from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.settings_api import init_router


def _client() -> TestClient:
    app = FastAPI()
    sniff_manager = MagicMock()
    app.include_router(init_router(sniff_manager), prefix="/api")
    return TestClient(app)


def test_get_interfaces_reloads_scapy_cache_before_listing():
    client = _client()
    with (
        patch("api.settings_api.conf.ifaces.reload") as reload_mock,
        patch("api.settings_api.get_if_list", return_value=["wlan0", "wlan1"]) as list_mock,
    ):
        response = client.get("/api/settings/interfaces")

    assert response.status_code == 200
    assert response.json() == ["wlan0", "wlan1"]
    reload_mock.assert_called_once_with()
    list_mock.assert_called_once_with()


def test_get_interfaces_returns_cached_list_if_reload_fails():
    client = _client()
    with (
        patch("api.settings_api.conf.ifaces.reload", side_effect=RuntimeError("boom")),
        patch("api.settings_api.get_if_list", return_value=["lo"]),
    ):
        response = client.get("/api/settings/interfaces")

    assert response.status_code == 200
    assert response.json() == ["lo"]
