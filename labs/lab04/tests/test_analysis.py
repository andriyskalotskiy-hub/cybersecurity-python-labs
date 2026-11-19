"""Рішення за правилом та помилки даних."""

from copy import deepcopy

import pytest

from labs.lab04.analysis import build_report, extract_record

CVE = "CVE-2099-10001"


def _cve(payload):
    return payload["vulnerabilities"][0]["cve"]


def _ratings(payload):
    return _cve(payload)["metrics"]["cvssMetricV31"]


def _decision(payload):
    return build_report(extract_record(payload, CVE), CVE, 13)["decision"]


@pytest.mark.parametrize(
    ("score", "impact", "expected"),
    [
        (5.9, "LOW", "other"),
        (6.0, "LOW", "review"),
        (6.1, "LOW", "review"),
        (9.8, "HIGH", "other"),
    ],
)
def test_variant_13_threshold(payload, score, impact, expected):
    """Перевірити обидві умови та включення межі 6.0."""
    _ratings(payload)[0]["cvssData"].update(
        baseScore=score, integrityImpact=impact
    )
    before = deepcopy(payload)
    assert _decision(payload) == expected
    assert payload == before


def test_not_found():
    """Повернути окремий стан для порожнього результату."""
    report = build_report(
        extract_record({"vulnerabilities": []}, CVE), CVE, 13
    )
    assert report == {
        "cve_id": CVE,
        "variant": 13,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {
            "threshold": 6.0,
            "field": "integrityImpact",
            "expected": "LOW",
        },
        "observed": None,
        "decision": "not_found",
    }


@pytest.mark.parametrize(
    ("status", "expected"),
    [("Rejected", "rejected"), (None, "insufficient_data")],
)
def test_decision_without_analyzing_ratings(payload, status, expected):
    """Не читати оцінки для відхиленого запису або відсутнього статусу."""
    cve = _cve(payload)
    if status is None:
        del cve["vulnStatus"]
    else:
        cve["vulnStatus"] = status
    cve["metrics"] = None
    report = build_report(extract_record(payload, CVE), CVE, 13)
    assert report["decision"] == expected
    assert report["vuln_status"] == status
    assert report["description"]
    assert report["score"] is report["observed"] is None


@pytest.mark.parametrize(
    "field", ["metrics", "cvssMetricV31", "integrityImpact"]
)
def test_missing_metric_or_impact(payload, field):
    """Відрізнити відсутність даних від помилкових значень."""
    cve = _cve(payload)
    if field == "metrics":
        del cve[field]
    elif field == "cvssMetricV31":
        del cve["metrics"][field]
    else:
        del _ratings(payload)[0]["cvssData"][field]
    assert _decision(payload) == "insufficient_data"


@pytest.mark.parametrize("value", [None, "MEDIUM", True, []])
def test_invalid_impact(payload, value):
    """Відхилити наявне, але неправильне поле правила."""
    _ratings(payload)[0]["cvssData"]["integrityImpact"] = value
    with pytest.raises(ValueError, match="integrityImpact"):
        _decision(payload)


@pytest.mark.parametrize(
    "value", [True, "9.8", -1, 11, float("nan"), float("inf")]
)
def test_invalid_score(payload, value):
    """Відхилити нечислові та неприпустимі оцінки."""
    _ratings(payload)[0]["cvssData"]["baseScore"] = value
    with pytest.raises(ValueError, match="baseScore"):
        extract_record(payload, CVE)


@pytest.mark.parametrize("kind", ["Primary", "Secondary"])
def test_metric_selection(payload, kind):
    """Вибрати першу Primary або перший елемент без Primary."""
    chosen = _ratings(payload)[0]
    chosen.update(type=kind, source="second")
    chosen["cvssData"].update(baseScore=6.5, integrityImpact="LOW")
    first = deepcopy(chosen)
    first.update(type="Secondary", source="first")
    first["cvssData"].update(baseScore=9.0, integrityImpact="HIGH")
    _ratings(payload).insert(0, first)
    _ratings(payload).append(deepcopy(chosen))
    _ratings(payload)[2]["source"] = "third"
    report = build_report(extract_record(payload, CVE), CVE, 13)
    if kind == "Primary":
        assert (
            report["score_source"],
            report["score"],
            report["decision"],
        ) == ("second", 6.5, "review")
    else:
        assert (
            report["score_source"],
            report["score"],
            report["decision"],
        ) == ("first", 9.0, "other")


@pytest.mark.parametrize(
    "payload",
    [[], {}, {"vulnerabilities": [None]}, {"vulnerabilities": [{}, {}]}],
)
def test_bad_envelope(payload):
    """Перевірити форму обгортки і кількість записів."""
    with pytest.raises(ValueError):
        extract_record(payload, CVE)


def test_wrong_id(payload):
    """Не приймати запис про інший CVE."""
    with pytest.raises(ValueError, match="id"):
        extract_record(payload, "CVE-2099-10002")


@pytest.mark.parametrize(
    ("field", "value"), [("version", "4.0"), ("vectorString", None)]
)
def test_bad_optional_metadata(payload, field, value):
    """Відхилити некоректні метадані вибраної оцінки."""
    _ratings(payload)[0]["cvssData"][field] = value
    with pytest.raises(ValueError):
        extract_record(payload, CVE)
