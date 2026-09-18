"""Навчальна реєстрація, SHA3-256, CSV та журнал спроб входу."""

import csv
import hashlib
import hmac
import json
from datetime import datetime
from functools import wraps
from pathlib import Path

from shared.student import VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 14
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)
DATA_DIR = Path(__file__).resolve().parent / "data"
USERS_FILE = DATA_DIR / "users.csv"
LOG_FILE = DATA_DIR / "log.json"

# Тільки вигадані облікові записи для демонстрації.
users_to_register = (
    ("andriy_lab", "RainyLviv@2026!"),
    ("marta_research", "Notebook@River7"),
    ("ostap_models", "Mountain@Trail8"),
    ("sofia_data", "Morning@Coffee9"),
    ("taras_audit", "Quiet@Library42"),
    ("ira_pipeline", "Autumn@Leaves26"),
    ("denys_ml", "Evening@Train17"),
    ("olena_registry", "Copper@Lantern6"),
    ("maksym_tests", "Forest@Walk1234"),
    ("nazar_backup", "Window@Sunrise5"),
)
users_db = []


class ValidationError(Exception):
    """Пароль не відповідає мінімальній довжині варіанта."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Перевірити пароль і повернути SHA3-256 від password + salt."""
    if not password or not salt:
        raise ValueError("Пароль і сіль не можуть бути порожніми.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError("Пароль має містити щонайменше 14 символів.")
    return hashlib.sha3_256((password + salt).encode("utf-8")).hexdigest()


def create_user(username, password):
    """Підготувати логін і хеш для запису в CSV."""
    if not username or not username.strip():
        raise ValueError("Логін не може бути порожнім.")
    return username, generate_hash(password, PERSONAL_SALT)


def create_users(users_list):
    """Записати коректні записи та пропустити помилкові рядки."""
    ready_users = []
    seen_names = set()
    for username, password in users_list:
        try:
            record = create_user(username, password)
            if username in seen_names:
                raise ValueError(f"Логін {username} уже використано.")
        except (ValidationError, ValueError) as error:
            print(f"Реєстрація {username!r}: {error}")
            continue
        ready_users.append(record)
        seen_names.add(username)

    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with USERS_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerows(ready_users)
    return len(ready_users)


def read_users():
    """Завантажити CSV у users_db та відхилити пошкоджені записи."""
    users_db.clear()
    loaded_users = []
    seen_names = set()
    with USERS_FILE.open(newline="", encoding="utf-8") as file:
        for row in csv.reader(file):
            if len(row) != 2:
                raise ValueError("Неправильний формат рядка users.csv.")
            username, saved_hash = row
            if not username.strip() or username in seen_names:
                raise ValueError("Порожній або повторний логін у базі.")
            if len(saved_hash) != 64 or any(
                symbol not in "0123456789abcdef" for symbol in saved_hash
            ):
                raise ValueError("Некоректний хеш у users.csv.")
            loaded_users.append((username, saved_hash))
            seen_names.add(username)
    users_db[:] = loaded_users
    return users_db


def save_event(event):
    """Додати подію до JSON-масиву, зберігши попередні спроби."""
    events = []
    try:
        with LOG_FILE.open(encoding="utf-8") as file:
            events = json.load(file)
    except FileNotFoundError:
        pass
    if not isinstance(events, list):
        raise ValueError("Журнал повинен містити JSON-масив подій.")
    events.append(event)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("w", encoding="utf-8") as file:
        json.dump(events, file, ensure_ascii=False, indent=2)


def log_event(function):
    """Записати результат входу, приховавши пароль в аргументах."""

    @wraps(function)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "")
        result = "failure"
        try:
            allowed = function(*args, **kwargs)
            if allowed:
                result = "success"
            return allowed
        finally:
            # Спроби з винятками також мають потрапити в журнал.
            safe_args = [
                value if index == 0 else "[REDACTED]"
                for index, value in enumerate(args)
            ]
            safe_kwargs = {
                key: "[REDACTED]" if key == "password" else value
                for key, value in kwargs.items()
            }
            save_event(
                {
                    "event": "login",
                    "user": username,
                    "result": result,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "args": safe_args,
                    "kwargs": safe_kwargs,
                }
            )

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Зіставити введений пароль із хешем користувача в users_db."""
    if not username or not username.strip() or not password:
        raise ValueError("Введіть непорожні логін і пароль.")
    entered_hash = generate_hash(password, PERSONAL_SALT)
    for saved_name, saved_hash in users_db:
        if saved_name == username:
            return hmac.compare_digest(entered_hash, saved_hash)
    return False


def run_demo():
    """Створити навчальну базу та виконати шість спроб входу."""
    print("\nЗавдання 3 | SHA3-256, CSV та JSON")
    print(f"Мінімальна довжина: {MIN_PASSWORD_LENGTH}; сіль: {PERSONAL_SALT}")
    registered = create_users(users_to_register)
    print(f"Зареєстровано користувачів: {registered}")
    read_users()
    print(f"{'Логін':<18} Хеш SHA3-256")
    print("-" * 83)
    for username, saved_hash in users_db:
        print(f"{username:<18} {saved_hash}")

    attempts = (
        ("andriy_lab", "RainyLviv@2026!", "правильний пароль"),
        ("andriy_lab", "Wrong@Password2026", "неправильний пароль"),
        ("unknown_user", "RainyLviv@2026!", "невідомий користувач"),
        ("andriy_lab", "short", "короткий пароль"),
        ("andriy_lab", "", "порожній пароль"),
        ("", "RainyLviv@2026!", "порожній логін"),
    )
    print("\nПеревірка входу:")
    for username, password, note in attempts:
        try:
            allowed = login(username, password)
        except (ValidationError, ValueError) as error:
            print(f"{note}: відмова - {error}")
        else:
            verdict = "успішний вхід" if allowed else "відмова"
            print(f"{note}: {verdict}")
    print(f"\nБаза: {USERS_FILE}")
    print(f"Журнал: {LOG_FILE}")
    print("Повторний запуск оновлює навчальну CSV-базу й доповнює журнал.")
