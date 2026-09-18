"""Перевірка допуску користувачів до ресурсів AI та ML."""

users = {
    "ai_security_expert": {
        "role": "ai_security",
        "clearance": 4,
        "department": "AI Security",
        "active": True,
    },
    "ml_engineer": {
        "role": "ml_engineer",
        "clearance": 3,
        "department": "Machine Learning",
        "active": True,
    },
    "data_engineer": {
        "role": "data_engineer",
        "clearance": 2,
        "department": "Data Engineering",
        "active": True,
    },
    "research_assistant": {
        "role": "researcher",
        "clearance": 2,
        "department": "Research",
        "active": True,
    },
    "training_bot": {
        "role": "bot_account",
        "clearance": 1,
        "department": "Automation",
        "active": False,
    },
}
resources = [
    ("ai_models", 4),
    ("training_datasets", 3),
    ("data_pipelines", 2),
    ("research_notebooks", 2),
    ("model_artifacts", 4),
    ("synthetic_data", 1),
    ("adversarial_tests", 3),
    ("model_registry", 4),
    ("feature_stores", 2),
    ("public_models", 1),
]
security_levels = (
    "Open Source",
    "Internal Research",
    "Proprietary",
    "Trade Secret",
)
blocked_users = {"training_bot", "model_theft", "data_poisoning_acc"}


def check_access(username, resource, accounts=None, blocked=None):
    """Перевірити доступ у порядку, заданому в методичці."""
    if accounts is None:
        accounts = users
    if blocked is None:
        blocked = blocked_users

    if username not in accounts:
        return False, "User not found"
    if username in blocked:
        return False, "User is blocked"
    account = accounts[username]
    if not account["active"]:
        return False, "Account inactive"
    if account["clearance"] >= resource[1]:
        return True, ""
    return False, "Insufficient clearance"


def show_access(username, resource, accounts=None, blocked=None):
    """Вивести рішення та причину відмови в заданому форматі."""
    allowed, reason = check_access(username, resource, accounts, blocked)
    verdict = "ALLOW" if allowed else f"DENY ({reason})"
    print(f"user={username} resource={resource[0]} -> {verdict}")


def run_demo():
    """Показати ресурси, 50 перевірок та два додаткові випадки."""
    print("\nЗавдання 2 | Контроль доступу")
    print(f"{'Ресурс':<24} Рівень безпеки")
    print("-" * 47)
    for name, level in resources:
        print(f"{name:<24} {security_levels[level - 1]}")

    for username in users:
        print()
        for resource in resources:
            show_access(username, resource)

    print("\nДодаткові перевірки:")
    show_access("unknown_researcher", ("public_models", 1))
    # training_bot уже заблокований: для окремої перевірки active
    # передаємо порожню множину, не змінюючи дані варіанта.
    show_access("training_bot", ("public_models", 1), blocked=set())
