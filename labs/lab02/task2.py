"""Пошук навчальних PII у текстових файлах варіанта 13."""

import ipaddress
import json
import logging
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)
REPORT_TOOL = "lab02_pii_scanner"
KINDS = ("emails", "cards", "phones", "ipv4")
PATTERNS = {
    "emails": re.compile(
        r"(?<![\w.+-])[A-Za-z0-9_.+-]+@"
        r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w.-])"
    ),
    "cards": re.compile(r"(?<!\w)(?:\d[ -]?){12,18}\d(?!\w)"),
    "phones": re.compile(r"(?<![\w.+])\+?\d(?:[ ()-]*\d){9,14}(?![\w.])"),
    "ipv4": re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
}


@dataclass
class Finding:
    """Місце й тип збігу; відкрите значення існує лише в пам'яті."""

    kind: str
    path: str
    line: int
    value: str


def card_is_valid(value):
    """Відсіяти випадкові числа через довжину та алгоритм Луна."""
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        number = int(digit)
        if index % 2:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def mask_value(kind, value):
    """Приховати основну частину знайденого значення."""
    if kind == "emails":
        name, domain = value.split("@", 1)
        return f"{name[0]}***@{domain}"
    if kind == "cards":
        digits = re.sub(r"\D", "", value)
        return f"{digits[:4]}-****-****-{digits[-4:]}"
    if kind == "phones":
        digits = re.sub(r"\D", "", value)
        return f"{'+' if value.startswith('+') else ''}***-***-{digits[-2:]}"
    return ".".join(value.split(".")[:2]) + ".*.*"


def find_in_line(text, path, line_number, selection="all"):
    """Знайти дані в рядку, виключивши збіги, що перекриваються."""
    found = []
    occupied = []
    # Картки мають пріоритет над схожими на них телефонами.
    for kind in ("emails", "cards", "ipv4", "phones"):
        for match in PATTERNS[kind].finditer(text):
            value = match.group()
            if kind == "cards" and not card_is_valid(value):
                continue
            if kind == "ipv4":
                try:
                    ipaddress.IPv4Address(value)
                except ipaddress.AddressValueError:
                    continue
            start, end = match.span()
            if any(start < right and end > left for left, right in occupied):
                continue
            occupied.append((start, end))
            if selection in ("all", kind):
                found.append((start, Finding(kind, path, line_number, value)))
    return [finding for _, finding in sorted(found, key=lambda pair: pair[0])]


def scan_directory(scan_dir, selection="all", output_path=None):
    """Рекурсивно прочитати текстові файли та зібрати збіги."""
    root = Path(scan_dir).resolve()
    if not root.is_dir():
        raise ValueError("Папку для сканування не знайдено.")
    if selection not in ("all", "cards", "emails"):
        raise ValueError("Тип пошуку: all, cards або emails.")
    output = Path(output_path).resolve() if output_path else None
    findings = []
    scanned = 0
    skipped = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file() or path.resolve() == output:
            continue
        try:
            text = path.read_text(encoding="utf-8")
            if "\x00" in text:
                raise ValueError("Бінарний файл")
        except (OSError, UnicodeError, ValueError):
            skipped += 1
            logger.warning(
                "Пропущено файл, який неможливо прочитати: %s", path
            )
            continue
        scanned += 1
        relative_path = path.relative_to(root).as_posix()
        file_findings = []
        for number, line in enumerate(text.splitlines(), 1):
            file_findings.extend(
                find_in_line(line, relative_path, number, selection)
            )
        if file_findings:
            logger.warning(
                "PII у %s: %d збігів", relative_path, len(file_findings)
            )
        findings.extend(file_findings)
    return findings, scanned, skipped


def save_report(output_path, findings, scanned, skipped, selection):
    """Зберегти JSON лише з маскованими значеннями."""
    counts = Counter(item.kind for item in findings)
    report = {
        "tool": REPORT_TOOL,
        "created_at_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "selection": selection,
        "scanned_files": scanned,
        "skipped_files": skipped,
        "total_matches": len(findings),
        "counts": {kind: counts[kind] for kind in KINDS},
        "findings": [
            {
                "type": item.kind,
                "file": item.path,
                "line": item.line,
                "value": mask_value(item.kind, item.value),
            }
            for item in findings
        ],
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False, indent=2)
    return report


def analyze(scan_dir, patterns, mask, out_json):
    """Провести сканування, вивести знахідки та записати звіт."""
    root = Path(scan_dir).resolve()
    output = Path(out_json).resolve()
    if output.is_relative_to(root) and output.exists():
        try:
            previous = json.loads(output.read_text(encoding="utf-8"))
        except (ValueError, OSError) as error:
            raise ValueError(
                "Вихідний файл збігається з вхідними даними."
            ) from error
        if (
            not isinstance(previous, dict)
            or previous.get("tool") != REPORT_TOOL
        ):
            raise ValueError("Не можна перезаписувати вхідний файл звітом.")
    logger.info("Сканування папки: %s", root)
    findings, scanned, skipped = scan_directory(root, patterns, output)
    report = save_report(output, findings, scanned, skipped, patterns)
    print(f"\nПрочитано файлів: {scanned}; пропущено: {skipped}")
    print("\nЗбіги за типами:")
    for kind, count in report["counts"].items():
        print(f"{kind:<8}: {count}")
    print(f"Усього: {len(findings)}")
    print("\nЗнайдені дані:")
    for item in findings:
        value = mask_value(item.kind, item.value) if mask else item.value
        print(f"{item.path}:{item.line} | {item.kind:<6} | {value}")
    print(f"\nМаскований JSON-звіт: {output}")
    return report
