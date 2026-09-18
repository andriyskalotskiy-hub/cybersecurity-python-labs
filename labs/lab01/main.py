"""Запуск демонстрацій лабораторної роботи 1."""

import argparse

from labs.lab01 import task1, task2, task3
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def main():
    """Обрати завдання та повідомити про помилки без трасування."""
    parser = argparse.ArgumentParser(description="Лабораторна 1, варіант 13")
    parser.add_argument(
        "--task", choices=("all", "1", "2", "3"), default="all"
    )
    parser.add_argument("--seed", type=int, help="Фіксувати вибір дублікатів")
    options = parser.parse_args()

    print(f"{STUDENT_NAME} | {GROUP_NAME} | варіант {VARIANT_NUMBER}")
    try:
        if options.task in ("all", "1"):
            task1.run_demo(options.seed)
        if options.task in ("all", "2"):
            task2.run_demo()
        if options.task in ("all", "3"):
            task3.run_demo()
    except FileNotFoundError:
        print("Файл не знайдено. Перевірте наявність навчальної бази.")
        return 1
    except PermissionError:
        print("Немає доступу до файлів. Перевірте права на папку data.")
        return 1
    except IOError as error:
        print(f"Не вдалося прочитати або записати файл: {error.strerror}")
        return 1
    except (task3.ValidationError, ValueError) as error:
        print(f"Помилка даних: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
