"""Параметризовані SQL-запити без залежності від FastAPI."""

import sqlite3
from contextlib import closing

from labs.lab03.database import get_connection

RECORD_SELECT = """
    SELECT r.id, r.code, r.title, r.category_id, r.value, r.status,
           c.name AS category_name
    FROM records AS r
    JOIN categories AS c ON c.id = r.category_id
"""


def list_categories() -> list[dict]:
    """Повернути категорії за зростанням id."""
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]


def create_category(name: str) -> dict:
    """Додати категорію та повернути її створений id."""
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "INSERT INTO categories (name) VALUES (?)", (name,)
        )
        return {"id": cursor.lastrowid, "name": name}


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію або повідомити про відсутню."""
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "DELETE FROM categories WHERE id = ?", (category_id,)
        )
        if cursor.rowcount == 0:
            raise LookupError("Категорію не знайдено")


def _require_category(connection: sqlite3.Connection, category_id: int):
    row = connection.execute(
        "SELECT id FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if row is None:
        raise LookupError("Категорію не знайдено")


def _read_record(connection: sqlite3.Connection, record_id: int) -> dict:
    row = connection.execute(
        RECORD_SELECT + " WHERE r.id = ?", (record_id,)
    ).fetchone()
    if row is None:
        raise LookupError("Запис не знайдено")
    return dict(row)


def get_record(record_id: int) -> dict:
    """Отримати одну знахідку разом із назвою категорії."""
    with closing(get_connection()) as connection:
        return _read_record(connection, record_id)


def list_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    """Застосувати фільтри через AND і повернути сторінку записів."""
    clauses = []
    params = []
    if category_id is not None:
        clauses.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        clauses.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        clauses.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        clauses.append("instr(r.title, ?) > 0")
        params.append(q)
    query = RECORD_SELECT
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY r.id LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    with closing(get_connection()) as connection:
        return [dict(row) for row in connection.execute(query, params)]


def _insert_record(connection: sqlite3.Connection, record: dict) -> dict:
    _require_category(connection, record["category_id"])
    cursor = connection.execute(
        """INSERT INTO records (code, title, category_id, value, status)
           VALUES (?, ?, ?, ?, ?)""",
        (
            record["code"],
            record["title"],
            record["category_id"],
            record["value"],
            record["status"],
        ),
    )
    return _read_record(connection, cursor.lastrowid)


def create_record(record: dict) -> dict:
    """Додати одну знахідку в окремій транзакції."""
    with closing(get_connection()) as connection, connection:
        return _insert_record(connection, record)


def replace_record(record_id: int, record: dict) -> dict:
    """Замінити всі поля запису зі збереженням його id."""
    with closing(get_connection()) as connection, connection:
        _read_record(connection, record_id)
        _require_category(connection, record["category_id"])
        connection.execute(
            """UPDATE records
               SET code = ?, title = ?, category_id = ?, value = ?, status = ?
               WHERE id = ?""",
            (
                record["code"],
                record["title"],
                record["category_id"],
                record["value"],
                record["status"],
                record_id,
            ),
        )
        return _read_record(connection, record_id)


def delete_record(record_id: int) -> None:
    """Видалити запис або повідомити, що такого id немає."""
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "DELETE FROM records WHERE id = ?", (record_id,)
        )
        if cursor.rowcount == 0:
            raise LookupError("Запис не знайдено")


def create_records_bulk(records: list[dict]) -> list[dict]:
    """Зберегти весь пакет або скасувати всі його зміни."""
    with closing(get_connection()) as connection, connection:
        return [_insert_record(connection, record) for record in records]
