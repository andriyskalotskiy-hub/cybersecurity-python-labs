"""Перевірки API, початкових даних і транзакцій ЛР 3."""

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from labs.lab03 import database, seed
from labs.lab03.main import app


def sample_record(code="V13-09", **changes):
    """Підготувати коректну нову знахідку для запиту."""
    record = {
        "code": code,
        "title": "Відкритий доступ до сховища",
        "category_id": 2,
        "value": 8.5,
        "status": "new",
    }
    record.update(changes)
    return record


class CloudAuditChecks(unittest.TestCase):
    """Ізолювати кожну перевірку в окремій файловій базі."""

    def setUp(self):
        """Створити тимчасову базу та запустити життєвий цикл API."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_path = Path(self.temp.name) / "audit.sqlite3"
        target = patch.object(database, "DATABASE_PATH", self.db_path)
        target.start()
        self.addCleanup(target.stop)
        self.assertTrue(seed.seed_database())
        self.client = TestClient(app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def records(self):
        """Прочитати всі записи маленької тестової бази."""
        response = self.client.get("/records", params={"limit": 100})
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_seed_repeat_and_foreign_keys(self):
        """Зберегти 3 категорії, 8 записів і не додати дублікати."""
        before = self.records()
        self.assertFalse(seed.seed_database())
        self.assertEqual(self.records(), before)
        self.assertEqual(len(before), 8)
        self.assertEqual(
            [r["value"] for r in before],
            [8.0, 6.5, 4.0, 9.0, 7.5, 3.0, 7.0, 5.0],
        )
        self.assertEqual(len(self.client.get("/categories").json()), 3)
        with closing(database.get_connection()) as connection:
            self.assertEqual(
                connection.execute("PRAGMA foreign_keys").fetchone()[0], 1
            )

    def test_service_routes_and_docs(self):
        """Отримати дані студента, стан сервісу та OpenAPI."""
        self.assertEqual(self.client.get("/ping").json(), {"status": "ok"})
        info = self.client.get("/student")
        self.assertEqual(info.status_code, 200)
        self.assertEqual(info.json()["variant_number"], 13)
        self.assertEqual(
            set(info.json()), {"student_name", "group_name", "variant_number"}
        )
        self.assertEqual(self.client.get("/docs").status_code, 200)
        paths = self.client.get("/openapi.json").json()["paths"]
        self.assertIn("409", paths["/records/bulk"]["post"]["responses"])
        self.assertIn("404", paths["/records/{record_id}"]["put"]["responses"])

    def test_crud(self):
        """Пройти створення, читання, повну заміну й видалення."""
        response = self.client.post("/records", json=sample_record())
        self.assertEqual(response.status_code, 201)
        record = response.json()
        self.assertEqual(record["category_name"], "storage")
        url = f"/records/{record['id']}"
        self.assertEqual(self.client.get(url).json(), record)
        changed = sample_record(value=6.0, status="done", category_id=1)
        response = self.client.put(url, json=changed)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], record["id"])
        self.assertEqual(response.json()["category_name"], "iam")
        self.assertEqual(response.json()["value"], 6.0)
        partial = self.client.put(url, json={"status": "done"})
        self.assertEqual(partial.status_code, 422)
        deleted = self.client.delete(url)
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(deleted.content, b"")
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_filters_and_pages(self):
        """Перевірити AND, включення порога і сталий порядок сторінок."""
        response = self.client.get(
            "/records", params={"category_id": 1, "status": "new"}
        )
        self.assertEqual([r["id"] for r in response.json()], [1, 4])
        risk = self.client.get("/records", params={"min_value": 7.0})
        self.assertEqual([r["id"] for r in risk.json()], [1, 4, 5, 7])
        page = self.client.get("/records", params={"limit": 2, "offset": 2})
        self.assertEqual([r["id"] for r in page.json()], [3, 4])
        self.assertEqual(
            self.client.get("/records", params={"category_id": 999}).json(), []
        )

    def test_invalid_models_and_query(self):
        """Відхилити неправильні поля й параметри без зміни бази."""
        before = self.records()
        for changes in [
            {"value": -1},
            {"value": 10.1},
            {"value": "NaN"},
            {"value": "Infinity"},
            {"title": "   "},
            {"title": "x" * 121},
            {"code": "ab"},
            {"status": "closed"},
            {"category_id": 0},
            {"id": 20},
            {"unexpected": True},
        ]:
            with self.subTest(changes=changes):
                response = self.client.post(
                    "/records", json=sample_record(**changes)
                )
                self.assertEqual(response.status_code, 422)
        for query in [
            {"limit": 0},
            {"limit": 101},
            {"offset": -1},
            {"category_id": -1},
            {"min_value": 11},
            {"min_value": "nan"},
            {"q": ""},
            {"status": "closed"},
        ]:
            self.assertEqual(
                self.client.get("/records", params=query).status_code, 422
            )
        self.assertEqual(self.records(), before)

    def test_missing_records_and_categories(self):
        """Відрізнити відсутній ресурс 404 від неправильного id 422."""
        for method in ["get", "delete"]:
            self.assertEqual(
                getattr(self.client, method)("/records/999").status_code, 404
            )
            self.assertEqual(
                getattr(self.client, method)("/records/0").status_code, 422
            )
        self.assertEqual(
            self.client.put("/records/999", json=sample_record()).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                "/records", json=sample_record(category_id=999)
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.put(
                "/records/1", json=sample_record(category_id=999)
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.delete("/categories/999").status_code, 404
        )

    def test_duplicate_codes_and_names(self):
        """Повернути 409 і зберегти попередні значення."""
        before = self.records()
        self.assertEqual(
            self.client.post(
                "/records", json=sample_record(code="V13-01")
            ).status_code,
            409,
        )
        self.assertEqual(
            self.client.put(
                "/records/2", json=sample_record(code="V13-01")
            ).status_code,
            409,
        )
        response = self.client.post("/categories", json={"name": " iam "})
        self.assertEqual(response.status_code, 409)
        self.assertNotIn("UNIQUE", response.text)
        self.assertEqual(self.records(), before)

    def test_category_delete_restriction(self):
        """Заборонити видалення непорожньої й дозволити порожню."""
        self.assertEqual(self.client.delete("/categories/1").status_code, 409)
        response = self.client.post("/categories", json={"name": "backup"})
        self.assertEqual(response.status_code, 201)
        response = self.client.delete(f"/categories/{response.json()['id']}")
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.content, b"")
        self.assertEqual(len(self.records()), 8)

    def test_bulk_success(self):
        """Зберегти два нових записи одним пакетом."""
        response = self.client.post(
            "/records/bulk",
            json=[sample_record("BULK-01"), sample_record("BULK-02")],
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(response.json()), 2)
        self.assertEqual(len(self.records()), 10)

    def test_bulk_duplicate_rollback(self):
        """Скасувати першу вставку після дубліката у другій."""
        before = self.records()
        response = self.client.post(
            "/records/bulk",
            json=[sample_record("ROLL-01"), sample_record("V13-01")],
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.records(), before)
        response = self.client.post(
            "/records/bulk",
            json=[sample_record("SAME-01"), sample_record("SAME-01")],
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.records(), before)

    def test_bulk_missing_category_rollback(self):
        """Скасувати пакет із неіснуючою категорією другого запису."""
        before = self.records()
        response = self.client.post(
            "/records/bulk",
            json=[
                sample_record("ROLL-02"),
                sample_record("ROLL-03", category_id=999),
            ],
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.records(), before)

    def test_bulk_validation(self):
        """Перевірити весь пакет і межу кількості до запису в базу."""
        before = self.records()
        for records in [
            [],
            [sample_record()] * 101,
            [sample_record(), sample_record(value=-1)],
        ]:
            response = self.client.post("/records/bulk", json=records)
            self.assertEqual(response.status_code, 422)
        self.assertEqual(self.records(), before)

    def test_literal_search_and_injection(self):
        """Обробити SQL-текст і символи шаблонів як буквальні дані."""
        before = self.records()
        for q in ["' OR 1=1 --", "%", "_", "знахідка"]:
            response = self.client.get("/records", params={"q": q})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), [])
        self.assertEqual(self.records(), before)
        response = self.client.get("/records", params={"q": "аудиту 01"})
        self.assertEqual([r["id"] for r in response.json()], [1])

    def test_persistence_after_restart(self):
        """Прочитати запис новим клієнтом після нового lifespan."""
        record = self.client.post("/records", json=sample_record()).json()
        with TestClient(app) as another_client:
            response = another_client.get(f"/records/{record['id']}")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), record)

    def test_seed_error_rolls_back_categories_too(self):
        """Скасувати категорії та записи при помилці початкового JSON."""
        other = Path(self.temp.name) / "empty.sqlite3"
        content = json.loads(seed.SEED_PATH.read_text(encoding="utf-8"))
        content["records"][1]["code"] = content["records"][0]["code"]
        bad_seed = Path(self.temp.name) / "bad.json"
        bad_seed.write_text(json.dumps(content), encoding="utf-8")
        with patch.object(database, "DATABASE_PATH", other):
            with self.assertRaises(sqlite3.IntegrityError):
                seed.seed_database(bad_seed)
            with closing(database.get_connection()) as connection:
                for table in ["categories", "records"]:
                    count = connection.execute(
                        "SELECT COUNT(*) FROM " + table
                    ).fetchone()[0]
                    self.assertEqual(count, 0)

    def test_sqlite_checks_and_safe_server_error(self):
        """Перевірити обмеження SQLite й відсутність SQL у HTTP 500."""
        with closing(database.get_connection()) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                with connection:
                    connection.execute(
                        """INSERT INTO records
                           (code, title, category_id, value, status)
                           VALUES (?, ?, ?, ?, ?)""",
                        ("SQL-01", "Хибна оцінка", 1, 11, "new"),
                    )
        with patch(
            "labs.lab03.repository.get_connection",
            side_effect=sqlite3.OperationalError("private path and SQL"),
        ):
            with self.assertLogs("labs.lab03.main", level="ERROR"):
                response = self.client.get("/categories")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("private", response.text)


if __name__ == "__main__":
    unittest.main()
