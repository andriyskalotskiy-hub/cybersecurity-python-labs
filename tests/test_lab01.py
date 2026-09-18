"""Перевірки граничних умов та роботи з тимчасовими файлами."""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from labs.lab01 import task1, task2, task3


class PasswordChecks(unittest.TestCase):
    """Категорії, межі довжини та вплив повторів."""

    def test_categories(self):
        """Розрізнити всі п'ять категорій на конкретних прикладах."""
        examples = (
            ("weak", 1, "Заборонений"),
            ("Ax7!", 1, "Заборонений"),
            ("quietforest7", 1, "Слабкий"),
            ("Quietforest7", 1, "Середній"),
            ("Oak7!sun", 1, "Сильний"),
            ("Birch!123456", 1, "Дуже сильний"),
            ("Birch!123456", 2, "Сильний"),
        )
        for password, repeats, expected in examples:
            with self.subTest(password=password, repeats=repeats):
                self.assertEqual(
                    task1.rate_password(password, repeats)[0], expected
                )

    def test_demo_keeps_source_list(self):
        """Повторні демонстрації не накопичують дублікати в джерелі."""
        original = task1.passwords.copy()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            task1.run_demo(seed=13)
            first_run = output.getvalue()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            task1.run_demo(seed=13)
            self.assertEqual(output.getvalue(), first_run)
        self.assertEqual(task1.passwords, original)


class AccessChecks(unittest.TestCase):
    """Порядок перевірок і рішення для всіх заданих ресурсів."""

    def test_access_totals(self):
        """Перевірити кількість дозволів для кожного користувача."""
        expected = (10, 7, 5, 5, 0)
        for username, count in zip(task2.users, expected):
            allowed = sum(
                task2.check_access(username, resource)[0]
                for resource in task2.resources
            )
            self.assertEqual(allowed, count)

    def test_denial_order(self):
        """Раніша причина відмови має пріоритет над наступною."""
        resource = ("ai_models", 4)
        self.assertEqual(
            task2.check_access("model_theft", resource),
            (False, "User not found"),
        )
        self.assertEqual(
            task2.check_access("training_bot", resource),
            (False, "User is blocked"),
        )
        self.assertEqual(
            task2.check_access("training_bot", resource, blocked=set()),
            (False, "Account inactive"),
        )
        self.assertEqual(
            task2.check_access("data_engineer", resource),
            (False, "Insufficient clearance"),
        )


class StorageChecks(unittest.TestCase):
    """Хешування, вхід та помилки файлів без зміни робочої бази."""

    def setUp(self):
        """Спрямувати CSV і JSON у тимчасову папку."""
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name) / "data"
        for name, value in (
            ("USERS_FILE", root / "users.csv"),
            ("LOG_FILE", root / "log.json"),
            ("users_db", []),
        ):
            replacement = patch.object(task3, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)

    def prepare_db(self):
        """Створити й прочитати десять заданих користувачів."""
        self.assertEqual(task3.create_users(task3.users_to_register), 10)
        task3.read_users()

    def test_hash_and_length_boundary(self):
        """Зіставити хеш із hashlib і перевірити межу 13 та 14."""
        password = "12345678901234"
        expected = hashlib.sha3_256((password + "00013").encode()).hexdigest()
        self.assertEqual(task3.generate_hash(password, "00013"), expected)
        with self.assertRaises(task3.ValidationError):
            task3.generate_hash(password[:-1], "00013")
        self.assertEqual(len(task3.generate_hash(password)), 64)

    def test_empty_hash_arguments(self):
        """Порожні пароль або сіль мають окремий тип помилки."""
        for password, salt in (
            (None, "00013"),
            ("", "00013"),
            ("12345678901234", None),
            ("12345678901234", ""),
        ):
            with self.subTest(password=password, salt=salt):
                with self.assertRaises(ValueError):
                    task3.generate_hash(password, salt)

    def test_csv_roundtrip(self):
        """CSV містить десять хешів, а не відкриті паролі."""
        self.prepare_db()
        self.assertEqual(len(task3.users_db), 10)
        contents = task3.USERS_FILE.read_text(encoding="utf-8")
        for username, password in task3.users_to_register:
            self.assertIn(username, contents)
            self.assertNotIn(password, contents)

    def test_reject_bad_registrations(self):
        """Не записувати короткі паролі, порожні та повторні логіни."""
        records = (
            ("ok", "12345678901234"),
            ("short", "abc"),
            ("", "12345678901234"),
            ("ok", "12345678901234"),
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(task3.create_users(records), 1)
        self.assertEqual(len(task3.read_users()), 1)

    def test_login_and_redacted_logs(self):
        """Зберегти всі результати входу без паролів у JSON."""
        self.prepare_db()
        username, password = task3.users_to_register[0]
        self.assertTrue(task3.login(username, password))
        self.assertFalse(task3.login(username, "Wrong@Password2026"))
        self.assertFalse(task3.login("unknown", password))
        self.assertTrue(task3.login(username=username, password=password))
        for bad_name, bad_password, error in (
            (username, "short", task3.ValidationError),
            (username, "", ValueError),
            ("", password, ValueError),
        ):
            with self.assertRaises(error):
                task3.login(bad_name, bad_password)
        raw = task3.LOG_FILE.read_text(encoding="utf-8")
        events = json.loads(raw)
        self.assertEqual(len(events), 7)
        self.assertEqual(sum(e["result"] == "success" for e in events), 2)
        self.assertNotIn(password, raw)
        self.assertNotIn("Wrong@Password2026", raw)
        self.assertNotIn("short", raw)

    def test_missing_or_damaged_csv_clears_old_db(self):
        """Не залишати стару базу після невдалого читання."""
        self.prepare_db()
        task3.USERS_FILE.unlink()
        with self.assertRaises(FileNotFoundError):
            task3.read_users()
        self.assertEqual(task3.users_db, [])
        task3.USERS_FILE.write_text("broken,row,extra\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            task3.read_users()

    def test_damaged_log_is_preserved(self):
        """Не затерти пошкоджений журнал новою подією."""
        self.prepare_db()
        task3.LOG_FILE.write_text("not json", encoding="utf-8")
        with self.assertRaises(ValueError):
            task3.login(*task3.users_to_register[0])
        self.assertEqual(
            task3.LOG_FILE.read_text(encoding="utf-8"), "not json"
        )

    def test_permission_error_propagates(self):
        """Помилка доступу до журналу не має виглядати успіхом."""
        self.prepare_db()
        with patch.object(task3, "save_event", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                task3.login(*task3.users_to_register[0])


if __name__ == "__main__":
    unittest.main()
