"""Модель облікового запису з паролем, сеансом та аудитом."""

import hashlib
import hmac
import ipaddress
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

PASSWORD_ITERATIONS = 600_000
SALT_BYTES = 16
SESSION_TIMEOUT_SEC = 900
EMAIL_PATTERN = re.compile(
    r"[A-Za-z][A-Za-z0-9_]{2,63}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
)


class User:
    """Користувач із перевірюваним email та прихованими даними пароля."""

    def __init__(self, username, email, role="user", active=True):
        """Зберегти дані користувача без початкового пароля."""
        self.username = username
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash = b""
        self.__password_salt = b""

    @property
    def email(self):
        """Повернути адресу електронної пошти."""
        return self._email

    @email.setter
    def email(self, value):
        """Прийняти адресу лише в заданому навчальному форматі."""
        if not isinstance(value, str) or not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("Некоректний email: перевірте логін і домен.")
        self._email = value

    def set_password(self, password: str):
        """Оновити пароль та створити для нього нову випадкову сіль."""
        if not isinstance(password, str) or not password:
            raise ValueError("Пароль не може бути порожнім.")
        self.__password_salt = os.urandom(SALT_BYTES)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            self.__password_salt,
            PASSWORD_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Перевірити пароль без розкриття хешу та солі."""
        if not isinstance(password, str) or not self.__password_hash:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            self.__password_salt,
            PASSWORD_ITERATIONS,
        )
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self):
        """Позначити користувача як неактивного."""
        self.active = False

    def __str__(self):
        """Показати відкриті дані користувача."""
        return (
            f"{self.username}: email={self.email}, role={self.role}, "
            f"active={self.active}"
        )


class Admin(User):
    """Користувач із набором адміністративних дозволів."""

    def __init__(self, username, email, permissions=None):
        """Ініціалізувати базового користувача й окремий набір прав."""
        super().__init__(username, email, role="admin")
        self.permissions = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str):
        """Додати дозвіл до набору."""
        self.permissions.add(permission)

    def revoke_permission(self, permission: str):
        """Вилучити дозвіл, якщо він був наданий."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевірити наявність конкретного дозволу."""
        return permission in self.permissions

    def __str__(self):
        """Доповнити дані користувача списком прав."""
        rights = ", ".join(sorted(self.permissions)) or "немає"
        return f"{super().__str__()}, permissions=[{rights}]"


class Session:
    """Сеанс із часовими мітками UTC."""

    def __init__(self, ip: str):
        """Створити сеанс для коректної IP-адреси."""
        ipaddress.ip_address(ip)
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self):
        """Оновити час останньої активності."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевірити час бездіяльності, не змінюючи його."""
        if timeout_sec <= 0:
            raise ValueError("Таймаут має бути додатним.")
        elapsed = datetime.now(timezone.utc) - self.last_activity
        return timedelta(0) <= elapsed < timedelta(seconds=timeout_sec)


@dataclass
class AuditEntry:
    """Одна дія користувача з часовою міткою UTC."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Послідовність дій без відкритих паролів."""

    def __init__(self):
        """Підготувати окремий список записів."""
        self.entries = []

    def add_log(self, username, action):
        """Додати дію з поточним часом UTC."""
        self.entries.append(
            AuditEntry(datetime.now(timezone.utc), username, action)
        )

    def show_all(self):
        """Вивести час, користувача та результат кожної дії."""
        for entry in self.entries:
            print(
                f"{entry.timestamp.isoformat(timespec='seconds')} | "
                f"{entry.username} | {entry.action}"
            )


class UserAccount:
    """Об'єднання користувача, поточного сеансу та журналу."""

    def __init__(self, user: User, session=None, audit_log=None):
        """Прийняти об'єкти або створити порожні сеанс і журнал."""
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()
        for key in ("user", "session", "audit_log"):
            self._check_value(key, getattr(self, key))

    @staticmethod
    def _check_value(key, value):
        """Перевірити дозволений ключ та тип переданого об'єкта."""
        types = {"user": User, "session": Session, "audit_log": AuditLog}
        if key not in types:
            raise KeyError(key)
        if key == "session" and value is None:
            return
        if not isinstance(value, types[key]):
            raise TypeError(
                f"Для {key} потрібен об'єкт {types[key].__name__}."
            )

    def login(self, username, password, ip):
        """Створити сеанс лише після успішної перевірки користувача."""
        if (
            not self.user.active
            or username != self.user.username
            or not self.user.check_password(password)
        ):
            self.session = None
            self.audit_log.add_log(username, "login_failure")
            return False
        try:
            session = Session(ip)
        except ValueError:
            self.session = None
            self.audit_log.add_log(username, "login_failure")
            raise
        session.touch()
        self.session = session
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        """Перевірити активність користувача та строк дії сеансу."""
        return bool(
            self.user.active
            and self.session is not None
            and self.session.is_active(SESSION_TIMEOUT_SEC)
        )

    def logout(self):
        """Завершити поточний сеанс і додати запис аудиту."""
        self.session = None
        self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key):
        """Отримати один із трьох відкритих компонентів облікового запису."""
        self._check_value(key, getattr(self, key, None))
        return getattr(self, key)

    def __setitem__(self, key, value):
        """Замінити компонент лише значенням правильного типу."""
        self._check_value(key, value)
        setattr(self, key, value)
        if key == "user":
            self.session = None


def run_demo():
    """Продемонструвати класи, перевірки та завершення сеансу."""
    user = User("andriy_lab", "andriy_lab@example.test")
    user.set_password("Morning@Lviv26")
    account = UserAccount(user)
    print("\nКористувач:", user)
    print(
        "Неправильний пароль:",
        account.login(user.username, "wrong", "192.0.2.10"),
    )
    print(
        "Правильний пароль:",
        account.login(user.username, "Morning@Lviv26", "192.0.2.10"),
    )
    print("Сеанс активний:", account.is_authenticated())

    user.email = "andriy_new@example.test"
    print("Новий email:", user.email)
    try:
        user.email = "1bad@example.test"
    except ValueError as error:
        print("Email відхилено:", error)

    admin = Admin("marta_admin", "marta_admin@example.test", {"read_audit"})
    admin.grant_permission("manage_users")
    print("\nАдміністратор:", admin)
    print("Право manage_users:", admin.has_permission("manage_users"))
    admin.revoke_permission("manage_users")
    print("Після відкликання:", admin.has_permission("manage_users"))

    print("\nЧерез індексатор:", account["user"].username)
    for key, value in (("password_hash", "hidden"), ("session", "text")):
        try:
            account[key] = value
        except (KeyError, TypeError) as error:
            print(f"{type(error).__name__}: {error}")

    # Імітуємо час бездіяльності, щоб не чекати 15 хвилин.
    account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    print("Після імітації таймауту:", account.is_authenticated())
    account.login(user.username, "Morning@Lviv26", "192.0.2.10")
    account.logout()
    print("Після logout:", account.is_authenticated())
    user.deactivate()
    print(
        "Вхід неактивного користувача:",
        account.login(user.username, "Morning@Lviv26", "192.0.2.10"),
    )
    print("\nЖурнал дій UTC:")
    account.audit_log.show_all()
