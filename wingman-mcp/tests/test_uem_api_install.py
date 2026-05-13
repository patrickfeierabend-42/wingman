from wingman_mcp import uem_api


class _Auth:
    api_base_url = "https://example.awmdm.com"


def test_install_internal_app_builds_v1_install_request(monkeypatch):
    calls = {}

    def fake_get_device(auth, device_id):
        assert device_id == "12345"
        return {
            "Id": {"Value": 12345},
            "Udid": "udid-1",
            "SerialNumber": "serial-1",
            "MacAddress": "mac-1",
        }

    def fake_post(auth, path, body=None, accept=None):
        calls["path"] = path
        calls["body"] = body
        calls["accept"] = accept
        return {"status": "success", "http_status": 202}

    monkeypatch.setattr(uem_api, "get_device", fake_get_device)
    monkeypatch.setattr(uem_api, "_post", fake_post)

    result = uem_api.install_app(_Auth(), device_id="12345", app_id="67890", app_type="internal")

    assert calls["path"] == "/api/mam/apps/internal/67890/install"
    assert calls["accept"] == uem_api.ACCEPT_V1
    assert calls["body"] == {
        "DeviceId": 12345,
        "Udid": "udid-1",
        "SerialNumber": "serial-1",
        "MacAddress": "mac-1",
    }
    assert result["app_id"] == "67890"
    assert result["app_type"] == "internal"
    assert result["device_id"] == "12345"


def test_install_purchased_app_resolves_uuid_and_uses_v2(monkeypatch):
    calls = {}

    def fake_get_device(auth, device_id):
        return {
            "Id": {"Value": 12345},
            "Udid": "udid-1",
            "SerialNumber": "serial-1",
            "MacAddress": "mac-1",
        }

    def fake_search_purchased_apps(auth, **kwargs):
        assert kwargs["page"] == 0
        assert kwargs["pagesize"] == 500
        return {
            "Application": [
                {"Id": {"Value": 67892}, "Uuid": "11111111-2222-3333-4444-555555555555"},
            ],
            "Total": 1,
        }

    def fake_post(auth, path, body=None, accept=None):
        calls["path"] = path
        calls["body"] = body
        calls["accept"] = accept
        return {"status": "success", "http_status": 202}

    monkeypatch.setattr(uem_api, "get_device", fake_get_device)
    monkeypatch.setattr(uem_api, "search_purchased_apps", fake_search_purchased_apps)
    monkeypatch.setattr(uem_api, "_post", fake_post)

    result = uem_api.install_app(_Auth(), device_id="12345", app_id="67892", app_type="purchased")

    assert calls["path"] == "/api/mam/apps/purchased/11111111-2222-3333-4444-555555555555/install"
    assert calls["accept"] == uem_api.ACCEPT_V2
    assert result["app_uuid"] == "11111111-2222-3333-4444-555555555555"
    assert result["app_type"] == "purchased"
    assert result["device_id"] == "12345"
