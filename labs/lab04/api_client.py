"""Один запит до публічного каталогу NVD."""

import os

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdError(ValueError):
    """Помилка отримання відповіді NVD."""


def build_headers() -> dict[str, str]:
    """Додати ключ із середовища, якщо його задано."""
    headers = {"Accept": "application/json"}
    key = os.getenv("NVD_API_KEY", "").strip()
    if key:
        headers["apiKey"] = key
    return headers


def fetch_response(cve_id: str) -> object:
    """Запросити один запис і декодувати відповідь JSON."""
    try:
        response = requests.get(
            NVD_URL,
            params={"cveId": cve_id},
            headers=build_headers(),
            timeout=(3.05, 10),
            allow_redirects=False,
        )
        response.raise_for_status()
    except requests.Timeout:
        raise NvdError("Вичерпано час очікування відповіді NVD.") from None
    except requests.HTTPError as error:
        status = (
            error.response.status_code if error.response is not None else "?"
        )
        raise NvdError(f"NVD повернув HTTP {status}.") from None
    except requests.ConnectionError:
        raise NvdError("Не вдалося підключитися до NVD.") from None
    except requests.RequestException:
        raise NvdError("Не вдалося виконати запит до NVD.") from None

    if response.status_code != 200:
        raise NvdError(f"Неочікуваний статус NVD: {response.status_code}.")
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        raise NvdError("Відповідь NVD не є правильним JSON.") from None
