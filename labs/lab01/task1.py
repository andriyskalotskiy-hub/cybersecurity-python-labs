"""Оцінювання паролів за умовами варіанта 13."""

import random
import string
from collections import Counter

from shared.student import STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "Compli4nc3@Check",
    "weak",
    "Risk@Ass3ssment",
    "guest",
    "Vulner4bility@Scan",
    "temp",
    "P3netration@Test",
    "demo",
    "S3curity@Audit",
    "trial",
]
criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {"weak", "guest", "temp", "demo", "trial", "password"}


def rate_password(password, repeats):
    """Повернути категорію пароля та коротку причину оцінки."""
    if password in forbidden_passwords:
        return "Заборонений", "є у списку заборонених"
    if len(password) < criteria["min_length"]:
        return "Заборонений", "менше 8 символів"

    checks = []
    if criteria["require_digits"]:
        checks.append(any(letter.isdigit() for letter in password))
    if criteria["require_upper"]:
        checks.append(any(letter.isupper() for letter in password))
    if criteria["require_special"]:
        checks.append(any(letter in string.punctuation for letter in password))

    passed = sum(checks)
    if not all(checks):
        if passed <= 1:
            return "Слабкий", f"виконано {passed} з {len(checks)} вимог"
        return "Середній", f"виконано {passed} з {len(checks)} вимог"

    if len(password) >= criteria["min_length"] + 4 and repeats == 1:
        return "Дуже сильний", "усі вимоги, довгий та унікальний"
    if repeats > 1:
        return "Сильний", "усі вимоги, але пароль повторюється"
    return "Сильний", "усі вимоги, довжина від 8 до 11"


def run_demo(seed=None):
    """Додати три дублікати та показати оцінки всього списку."""
    print(f"\nЗавдання 1 | {STUDENT_NAME} | варіант {VARIANT_NUMBER}")
    # Беремо індекси саме з початкового списку, до додавання копій.
    chosen = random.Random(seed).sample(range(len(passwords)), 3)
    password_batch = passwords + [passwords[index] for index in chosen]
    counts = Counter(password_batch)
    print("Індекси скопійованих паролів (від 0):", chosen)
    print(f"{'Пароль':<23} {'Довжина':<8} {'Копій':<6} {'Оцінка':<14} Причина")
    print("-" * 100)
    for password in password_batch:
        rating, reason = rate_password(password, counts[password])
        print(
            f"{password:<23} {len(password):<8} {counts[password]:<6} "
            f"{rating:<14} {reason}"
        )

    print("\nОкремі приклади для перевірки проміжних категорій:")
    for password in (
        "quietforest",
        "quietforest7",
        "Quietforest7",
        "Oak7!sun",
    ):
        rating, reason = rate_password(password, 1)
        print(f"{password:<23} {rating:<14} {reason}")
