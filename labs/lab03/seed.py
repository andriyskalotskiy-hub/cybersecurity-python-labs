"""Перевірка JSON і початкове заповнення порожньої бази."""

import logging
import sqlite3
from contextlib import closing
from pathlib import Path

from pydantic import ValidationError

from labs.lab03.database import get_connection, initialize_database
from labs.lab03.schemas import SeedData

SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"


def seed_database(seed_path: Path = SEED_PATH) -> bool:
    """Додати початковий набір лише до повністю порожньої бази."""
    data = SeedData.model_validate_json(seed_path.read_text(encoding="utf-8"))
    initialize_database()
    with closing(get_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        categories = connection.execute(
            "SELECT COUNT(*) FROM categories"
        ).fetchone()[0]
        records = connection.execute(
            "SELECT COUNT(*) FROM records"
        ).fetchone()[0]
        if categories or records:
            return False
        connection.executemany(
            "INSERT INTO categories (id, name) VALUES (?, ?)",
            [(item.id, item.name) for item in data.categories],
        )
        connection.executemany(
            """INSERT INTO records (code, title, category_id, value, status)
               VALUES (?, ?, ?, ?, ?)""",
            [
                (
                    item.code,
                    item.title,
                    item.category_id,
                    item.value,
                    item.status,
                )
                for item in data.records
            ],
        )
    return True


def main() -> int:
    """Запустити заповнення та показати його результат."""
    try:
        if seed_database():
            print("Додано 3 категорії та 8 знахідок хмарного аудиту.")
        else:
            print("База вже містить дані. Початкове заповнення пропущено.")
    except (OSError, ValidationError, sqlite3.Error):
        logging.exception("Не вдалося виконати початкове заповнення")
        print("Не вдалося заповнити базу. Перевірте JSON та доступ до файлів.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
