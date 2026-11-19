"""Перевірка відповіді NVD та відбір за CVSS 3.1."""

import math

IMPACTS = ("NONE", "LOW", "HIGH")
RULES = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}
ALLOWED_VALUES = {
    "attackVector": ("NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"),
    "attackComplexity": ("LOW", "HIGH"),
    "privilegesRequired": IMPACTS,
    "userInteraction": ("NONE", "REQUIRED"),
    "scope": ("UNCHANGED", "CHANGED"),
    "confidentialityImpact": IMPACTS,
    "integrityImpact": IMPACTS,
    "availabilityImpact": IMPACTS,
}


def valid_variant(variant: object) -> bool:
    """Перевірити номер варіанта без прийняття True за 1."""
    return type(variant) is int and variant in RULES


def _optional_text(obj: dict, key: str) -> str | None:
    if key not in obj:
        return None
    value = obj[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key}: очікувався непорожній рядок.")
    return value


def _english_description(cve: dict) -> str | None:
    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        raise ValueError("descriptions має бути списком.")
    english = None
    for item in descriptions:
        if not isinstance(item, dict) or not all(
            isinstance(item.get(key), str) for key in ("lang", "value")
        ):
            raise ValueError("Опис має містити рядки lang і value.")
        if english is None and item["lang"] == "en" and item["value"].strip():
            english = item["value"]
    return english


def _pick_metric(cve: dict) -> dict | None:
    metrics = cve.get("metrics", {})
    if not isinstance(metrics, dict):
        raise ValueError("metrics має бути об'єктом.")
    ratings = metrics.get("cvssMetricV31", [])
    if not isinstance(ratings, list) or not all(
        isinstance(item, dict) for item in ratings
    ):
        raise ValueError("cvssMetricV31 має бути списком об'єктів.")
    if not ratings:
        return None
    return next(
        (item for item in ratings if item.get("type") == "Primary"),
        ratings[0],
    )


def extract_record(payload: object, cve_id: str) -> dict | None:
    """Виділити опис, статус і вибрану оцінку або повернути None.

    Внутрішній словник містить поля звіту та копію вибраного cvssData
    для перевірки ознаки варіанта у build_report.
    """
    entries = (
        payload.get("vulnerabilities") if isinstance(payload, dict) else None
    )
    if not isinstance(entries, list) or len(entries) > 1:
        raise ValueError("Очікувався список із нуля або одного запису CVE.")
    if not entries:
        return None
    cve = entries[0].get("cve") if isinstance(entries[0], dict) else None
    if not isinstance(cve, dict) or cve.get("id") != cve_id:
        raise ValueError(
            "Запис cve відсутній або його id не збігається із запитом."
        )
    status = _optional_text(cve, "vulnStatus")
    record = {
        "description": _english_description(cve),
        "vuln_status": status,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "cvss_data": {},
    }
    if status is None or status == "Rejected":
        return record

    rating = _pick_metric(cve)
    if rating is None:
        return record
    data = rating.get("cvssData")
    if not isinstance(data, dict):
        raise ValueError("cvssData має бути об'єктом.")
    score = data.get("baseScore")
    if (
        type(score) not in (int, float)
        or not 0 <= score <= 10
        or not math.isfinite(score)
    ):
        raise ValueError("baseScore має бути скінченним числом від 0 до 10.")
    version = _optional_text(data, "version")
    if version is not None and version != "3.1":
        raise ValueError("Очікувалася версія CVSS 3.1.")
    record.update(
        cvss_version=version,
        score=score,
        score_source=_optional_text(rating, "source"),
        vector=_optional_text(data, "vectorString"),
        cvss_data=data.copy(),
    )
    return record


def build_report(record: dict | None, cve_id: str, variant: int) -> dict:
    """Зібрати звіт і визначити стан за правилом варіанта."""
    if not valid_variant(variant):
        raise ValueError("Номер варіанта має бути цілим числом від 1 до 15.")
    threshold, field, expected = RULES[variant]
    report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report
    report.update({key: record[key] for key in record if key != "cvss_data"})
    data = record["cvss_data"]
    if field in data and data[field] not in ALLOWED_VALUES[field]:
        raise ValueError(f"{field}: значення не відповідає CVSS 3.1.")

    observed = data.get(field)
    score = record["score"]
    if record["vuln_status"] == "Rejected":
        decision = "rejected"
    elif record["vuln_status"] is None or score is None or observed is None:
        decision = "insufficient_data"
    elif score >= threshold and observed == expected:
        decision = "review"
    else:
        decision = "other"
    report.update(observed=observed, decision=decision)
    return report
