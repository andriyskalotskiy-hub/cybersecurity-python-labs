"""Команди demo та analyze для лабораторної роботи 2."""

import argparse
import logging

from labs.lab02 import task1, task2
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def build_parser():
    """Описати команди й обов'язкові параметри сканера."""
    parser = argparse.ArgumentParser(
        description="Лабораторна 2: ООП і сканер PII"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo", help="Демонстрація класів і сеансів")
    scan = commands.add_parser("analyze", help="Пошук PII у навчальних файлах")
    scan.add_argument(
        "--scan-dir", required=True, help="Папка текстових файлів"
    )
    scan.add_argument(
        "--patterns", choices=("all", "cards", "emails"), default="all"
    )
    scan.add_argument(
        "--mask", action="store_true", help="Маскувати вивід у консоль"
    )
    scan.add_argument("--out-json", required=True, help="Шлях до JSON-звіту")
    return parser


def main():
    """Запустити команду та обробити очікувані помилки."""
    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO, format="[%(levelname)s] %(message)s"
    )
    print(f"{STUDENT_NAME} | {GROUP_NAME} | варіант {VARIANT_NUMBER}")
    try:
        if args.command == "demo":
            task1.run_demo()
        else:
            task2.analyze(
                args.scan_dir, args.patterns, args.mask, args.out_json
            )
    except (OSError, ValueError) as error:
        logging.error("%s", error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
