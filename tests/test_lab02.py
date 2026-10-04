"""Перевірки автентифікації, сеансів і сканера PII."""

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from labs.lab02 import task1, task2

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "labs/lab02/data/data_v13/scan"


class AccountChecks(unittest.TestCase):
    """Правила email, хешування, облік сеансів та індексатори."""

    def setUp(self):
        """Створити ізольований обліковий запис."""
        self.user = task1.User("andriy", "andriy@example.test")
        self.user.set_password("Forest@Morning26")
        self.account = task1.UserAccount(self.user)

    def test_email_boundaries(self):
        """Прийняти локальні частини 3 і 64, відхилити порушення."""
        for name in ("abc", "a" * 64):
            self.user.email = name + "@example.test"
        for value in (
            "ab@example.test",
            "a" * 65 + "@example.test",
            "1abc@example.test",
            "abc.def@example.test",
            "abc@example",
            "abc@-example.test",
            "abc@example.test\n",
            None,
        ):
            with self.subTest(email=value), self.assertRaises(ValueError):
                self.user.email = value
        self.assertEqual(self.user.email, "a" * 64 + "@example.test")

    def test_password_salt_and_changes(self):
        """Однакові паролі мають різні хеші через випадкову сіль."""
        other = task1.User("marta", "marta@example.test")
        other.set_password("Forest@Morning26")
        self.assertNotEqual(
            self.user._User__password_hash, other._User__password_hash
        )
        self.assertTrue(self.user.check_password("Forest@Morning26"))
        self.assertFalse(self.user.check_password("wrong"))
        self.user.set_password("Fresh@Password26")
        self.assertFalse(self.user.check_password("Forest@Morning26"))
        self.assertTrue(self.user.check_password("Fresh@Password26"))
        self.assertNotIn("Fresh@Password26", str(self.user))

    def test_empty_or_unset_password(self):
        """Не дозволити вхід без установленого або непорожнього пароля."""
        empty = task1.User("empty", "empty@example.test")
        self.assertFalse(empty.check_password(""))
        for value in ("", None):
            with self.assertRaises(ValueError):
                empty.set_password(value)

    def test_login_failure_and_logout(self):
        """Побудувати сеанс після успіху та завершити його після відмови."""
        self.assertFalse(self.account.login("unknown", "x", "192.0.2.1"))
        self.assertIsNone(self.account.session)
        self.assertTrue(
            self.account.login("andriy", "Forest@Morning26", "192.0.2.1")
        )
        self.assertTrue(self.account.is_authenticated())
        self.assertFalse(self.account.login("andriy", "wrong", "192.0.2.1"))
        self.assertFalse(self.account.is_authenticated())
        self.account.logout()
        actions = [entry.action for entry in self.account.audit_log.entries]
        self.assertEqual(
            actions,
            ["login_failure", "login_success", "login_failure", "logout"],
        )

    def test_deactivation_blocks_existing_session(self):
        """Деактивація скасовує автентифікацію та нові входи."""
        self.account.login("andriy", "Forest@Morning26", "192.0.2.1")
        self.user.deactivate()
        self.assertFalse(self.account.is_authenticated())
        self.assertFalse(
            self.account.login("andriy", "Forest@Morning26", "192.0.2.1")
        )

    def test_timeout_is_not_refreshed_by_check(self):
        """Перевірка не подовжує сеанс; після 900 секунд він неактивний."""
        self.account.login("andriy", "Forest@Morning26", "192.0.2.1")
        session = self.account.session
        before = session.last_activity
        self.assertTrue(self.account.is_authenticated())
        self.assertEqual(session.last_activity, before)
        session.last_activity = datetime.now(timezone.utc) - timedelta(
            seconds=900
        )
        self.assertFalse(self.account.is_authenticated())
        self.assertIs(session.login_time.tzinfo, timezone.utc)
        for timeout in (0, -1):
            with self.assertRaises(ValueError):
                session.is_active(timeout)
        session.touch()
        self.assertTrue(session.is_active(900))

    def test_admin_permissions_are_independent(self):
        """Зміна прав одного адміністратора не змінює іншого."""
        first = task1.Admin("first", "first@example.test")
        second = task1.Admin("second", "second@example.test")
        first.grant_permission("read_logs")
        self.assertTrue(first.has_permission("read_logs"))
        self.assertFalse(second.has_permission("read_logs"))
        first.revoke_permission("read_logs")
        first.revoke_permission("missing")
        self.assertFalse(first.has_permission("read_logs"))
        self.assertIsInstance(first, task1.User)

    def test_component_types_and_private_keys(self):
        """Відхилити невідомі ключі й типи; заміна User завершує сеанс."""
        self.account.login("andriy", "Forest@Morning26", "192.0.2.1")
        other = task1.User("other", "other@example.test")
        self.account["user"] = other
        self.assertIs(self.account["user"], other)
        self.assertIsNone(self.account["session"])
        for key in ("password_hash", "__password_salt", "unknown"):
            with self.assertRaises(KeyError):
                self.account[key]
        for key in ("user", "session", "audit_log"):
            with self.assertRaises(TypeError):
                self.account[key] = "wrong type"

    def test_invalid_ip_cannot_create_session(self):
        """Не залишити сеанс після помилки адреси входу."""
        with self.assertRaises(ValueError):
            self.account.login("andriy", "Forest@Morning26", "999.1.1.1")
        self.assertIsNone(self.account.session)
        self.assertEqual(
            self.account.audit_log.entries[-1].action, "login_failure"
        )

    def test_audit_has_utc_and_no_password(self):
        """Записи аудиту мають часовий пояс і не містять пароль."""
        self.account.login("andriy", "Forest@Morning26", "192.0.2.1")
        with contextlib.redirect_stdout(io.StringIO()) as stream:
            self.account.audit_log.show_all()
        self.assertIn("login_success", stream.getvalue())
        self.assertNotIn("Forest@Morning26", stream.getvalue())
        self.assertIs(
            self.account.audit_log.entries[0].timestamp.tzinfo, timezone.utc
        )


class ScannerChecks(unittest.TestCase):
    """Результати на архіві та помилки текстових файлів."""

    def test_archive_results(self):
        """Зіставити знахідки з ручним підрахунком у файлах варіанта."""
        with self.assertLogs(task2.logger, level="WARNING"):
            found, scanned, skipped = task2.scan_directory(DATA)
        self.assertEqual((scanned, skipped), (4, 0))
        self.assertEqual(
            Counter(x.kind for x in found),
            {
                "emails": 4,
                "cards": 3,
                "phones": 4,
                "ipv4": 4,
            },
        )
        expected = {
            ("notes/users.txt", 2, "bob.smith@example.test"),
            ("notes/users.txt", 3, "+1-202-555-0147"),
            ("notes/users.txt", 4, "0501234567"),
            ("notes/users.txt", 5, "10.20.30.40"),
            ("notes/users.txt", 6, "5555 5555 5555 4444"),
        }
        actual = {
            (x.path, x.line, x.value)
            for x in found
            if x.path.startswith("notes/")
        }
        self.assertEqual(actual, expected)
        self.assertFalse(any(x.path == "clean.txt" for x in found))

    def test_filters(self):
        """Режими cards та emails повертають лише обрані типи."""
        for selection, count in (("cards", 3), ("emails", 4)):
            with self.assertLogs(task2.logger, level="WARNING"):
                found, scanned, _ = task2.scan_directory(DATA, selection)
            self.assertEqual(scanned, 4)
            self.assertEqual(len(found), count)
            self.assertTrue(all(x.kind == selection for x in found))

    def test_card_phone_overlap_and_false_patterns(self):
        """Картку не рахувати телефоном, дату й некоректний IP відкинути."""
        line = "2026-09-27 card=4111-1111-1111-1111 ip=999.2.3.4"
        found = task2.find_in_line(line, "sample.txt", 1)
        self.assertEqual([x.kind for x in found], ["cards"])
        self.assertFalse(task2.card_is_valid("4111-1111-1111-1112"))

    def test_report_is_masked_without_console_flag(self):
        """У JSON немає відкритих значень, навіть коли mask=False."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.json"
            with self.assertLogs(task2.logger, level="INFO"):
                with contextlib.redirect_stdout(io.StringIO()):
                    task2.analyze(DATA, "all", False, target)
            raw = target.read_text(encoding="utf-8")
            for value in (
                "alice@example.test",
                "4111-1111-1111-1111",
                "0501234567",
                "192.0.2.10",
            ):
                self.assertNotIn(value, raw)
            report = json.loads(raw)
            self.assertEqual(report["total_matches"], 15)
            self.assertEqual(report["counts"]["phones"], 4)

    def test_repeated_scan_excludes_own_report(self):
        """Вихідний звіт усередині папки не сканується повторно."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.txt").write_text(
                "alice@example.test", encoding="utf-8"
            )
            output = root / "report.json"
            for _ in range(2):
                with self.assertLogs(task2.logger, level="INFO"):
                    with contextlib.redirect_stdout(io.StringIO()):
                        report = task2.analyze(root, "all", True, output)
                self.assertEqual(report["scanned_files"], 1)
                self.assertEqual(report["total_matches"], 1)

    def test_do_not_overwrite_source_json(self):
        """Захистити початковий JSON, якщо його вказали як звіт."""
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "input.json"
            source.write_text(
                '{"email":"alice@example.test"}', encoding="utf-8"
            )
            before = source.read_bytes()
            with self.assertRaises(ValueError):
                task2.analyze(tmp, "all", True, source)
            self.assertEqual(source.read_bytes(), before)

    def test_skip_binary_and_unreadable_file(self):
        """Бінарний файл і помилка прав не зупиняють обхід."""
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "file.bin"
            source.write_bytes(b"\x00\xff")
            with self.assertLogs(task2.logger, level="WARNING"):
                self.assertEqual(task2.scan_directory(tmp)[1:], (0, 1))
            with patch.object(Path, "read_text", side_effect=PermissionError):
                with self.assertLogs(task2.logger, level="WARNING"):
                    self.assertEqual(task2.scan_directory(tmp)[1:], (0, 1))

    def test_cli_errors_and_import(self):
        """Помилки CLI мають код завершення, а імпорт не запускає demo."""
        result = subprocess.run(
            [sys.executable, "-m", "labs.lab02.main", "analyze"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--scan-dir", result.stderr)
        result = subprocess.run(
            [sys.executable, "-c", "import labs.lab02.task1"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            (result.returncode, result.stdout, result.stderr), (0, "", "")
        )
        with self.assertRaises(ValueError):
            task2.scan_directory(ROOT / "missing-lab02-folder")


if __name__ == "__main__":
    unittest.main()
