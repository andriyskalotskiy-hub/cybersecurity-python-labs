"""Спільні дані та ізоляція тестів."""

import json
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Прибрати зовнішній ключ і заборонити справжні запити."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_path():
    """Повернути шлях до спільного навчального прикладу."""
    return Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


@pytest.fixture
def payload(sample_path):
    """Прочитати нову копію синтетичних даних для кожного тесту."""
    return json.loads(sample_path.read_text(encoding="utf-8"))
