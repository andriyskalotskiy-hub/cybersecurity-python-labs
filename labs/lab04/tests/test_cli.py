"""Локальний запуск, коди завершення й поділ потоків."""

import json
from unittest.mock import Mock

import pytest

from labs.lab04 import main

CVE = "CVE-2099-10001"


def test_local_report(monkeypatch, capsys, sample_path):
    """Перевірити звіт за файлом і відсутність виклику клієнта."""
    fetch = Mock(side_effect=AssertionError("Мережа у локальному режимі"))
    monkeypatch.setattr(main.api_client, "fetch_response", fetch)
    assert main.main(["--cve", CVE, "--input", str(sample_path)]) == 0
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert output.err == ""
    assert (report["variant"], report["score"], report["observed"]) == (
        13,
        9.8,
        "HIGH",
    )
    assert report["decision"] == "other"
    fetch.assert_not_called()


@pytest.mark.parametrize("content", [None, "{", "[]"])
def test_bad_input(tmp_path, capsys, content):
    """Помилка читання, JSON або структури йде тільки у stderr."""
    path = tmp_path / "input.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    assert main.main(["--cve", CVE, "--input", str(path)]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    expected = {None: "відкрити", "{": "JSON", "[]": "Некоректні дані"}
    assert expected[content] in output.err


@pytest.mark.parametrize("cve", ["cve-2099-10001", "CVE-2099-123", CVE + "x"])
def test_bad_cve(cve, capsys):
    """Некоректний ідентифікатор має дати код аргументів 2."""
    with pytest.raises(SystemExit) as caught:
        main.main(["--cve", cve])
    assert caught.value.code == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("variant", [True, 0, 16, "13"])
def test_bad_variant(monkeypatch, capsys, variant):
    """Відхилити некоректний номер до будь-якого читання."""
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)
    assert main.main(["--cve", CVE]) == 2
    assert "варіанта" in capsys.readouterr().err


def test_empty_http_result_is_success(monkeypatch, capsys):
    """Стан not_found є успішним аналізом, а не помилкою HTTP."""
    fetch = Mock(return_value={"vulnerabilities": []})
    monkeypatch.setattr(main.api_client, "fetch_response", fetch)
    assert main.main(["--cve", CVE]) == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out)["decision"] == "not_found"
    fetch.assert_called_once_with(CVE)
