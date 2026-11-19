"""Командний інтерфейс для перегляду одного CVE."""

import argparse
import json
import re
import sys
from pathlib import Path

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER


def load_response(path: Path) -> object:
    """Прочитати локальну відповідь NVD у UTF-8."""
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    """Запустити аналіз і повернути код завершення."""
    parser = argparse.ArgumentParser(description="Перегляд запису CVE")
    parser.add_argument("--cve", required=True, help="Ідентифікатор CVE")
    parser.add_argument("--input", type=Path, help="Локальна відповідь NVD")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", args.cve):
        parser.error("потрібен ідентифікатор у форматі CVE-РРРР-НОМЕР")
    if not analysis.valid_variant(VARIANT_NUMBER):
        print("Номер варіанта має бути від 1 до 15.", file=sys.stderr)
        return 2
    try:
        if args.input is None:
            payload = api_client.fetch_response(args.cve)
        else:
            payload = load_response(args.input)
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except api_client.NvdError as error:
        print(error, file=sys.stderr)
        return 1
    except (json.JSONDecodeError, UnicodeError):
        print("Не вдалося прочитати файл як JSON у UTF-8.", file=sys.stderr)
        return 1
    except OSError:
        print("Не вдалося відкрити локальний файл.", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"Некоректні дані: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
