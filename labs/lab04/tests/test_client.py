"""HTTP-клієнт з підміною Requests."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

CVE = "CVE-2099-10001"


@pytest.mark.parametrize("key", [None, "", "   ", " test-key "])
def test_request_arguments(monkeypatch, key):
    """Перевірити адресу, параметри, таймаут і заголовки."""
    if key is not None:
        monkeypatch.setenv("NVD_API_KEY", key)
    response = Mock(spec=requests.Response, status_code=200)
    response.json.return_value = {"vulnerabilities": []}
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    expected = {"Accept": "application/json"}
    if key == " test-key ":
        expected["apiKey"] = "test-key"
    assert api_client.fetch_response(CVE) == {"vulnerabilities": []}
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": CVE},
        headers=expected,
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (requests.Timeout, "час очікування"),
        (requests.ConnectionError, "підключитися"),
    ],
)
def test_network_error(monkeypatch, error, message):
    """Не розкривати початковий текст мережевого винятку."""
    monkeypatch.setattr(
        api_client.requests, "get", Mock(side_effect=error("private detail"))
    )
    with pytest.raises(api_client.NvdError, match=message) as caught:
        api_client.fetch_response(CVE)
    assert "private detail" not in str(caught.value)


@pytest.mark.parametrize(
    ("status", "message"),
    [(404, "HTTP 404"), (302, "статус NVD: 302"), (204, "статус NVD: 204")],
)
def test_unexpected_status(monkeypatch, status, message):
    """Відхилити HTTP-помилку, редирект і відповідь без тіла."""
    response = Mock(spec=requests.Response, status_code=status)
    if status == 404:
        response.raise_for_status.side_effect = requests.HTTPError(
            "private detail", response=response
        )
    monkeypatch.setattr(
        api_client.requests, "get", Mock(return_value=response)
    )
    with pytest.raises(api_client.NvdError, match=message):
        api_client.fetch_response(CVE)
    response.json.assert_not_called()


def test_malformed_http_json(monkeypatch):
    """Обробити помилку декодування тіла відповіді."""
    response = Mock(spec=requests.Response, status_code=200)
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    monkeypatch.setattr(
        api_client.requests, "get", Mock(return_value=response)
    )
    with pytest.raises(api_client.NvdError, match="JSON"):
        api_client.fetch_response(CVE)
