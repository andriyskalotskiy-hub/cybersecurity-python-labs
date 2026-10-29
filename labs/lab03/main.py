"""FastAPI-застосунок реєстру ризиків хмарної конфігурації."""

import logging
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from labs.lab03.config import RISK_THRESHOLD, UNIT
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Створити відсутні таблиці перед початком обробки запитів."""
    initialize_database()
    yield


app = FastAPI(
    title="Реєстр ризиків хмарної конфігурації",
    description=(
        "Навчальні знахідки аудиту IAM, сховищ і мережі. "
        f"Оцінка ризику: 0–10 {UNIT}; поріг варіанта: {RISK_THRESHOLD}. "
        "Для вибірки за порогом задайте min_value=7.0."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(categories.router)
app.include_router(records.router)


@app.exception_handler(LookupError)
def missing_item(request: Request, exc: LookupError) -> JSONResponse:
    """Перетворити відсутній запис чи категорію на HTTP 404."""
    return JSONResponse(status_code=404, content={"detail": str(exc)})


@app.exception_handler(sqlite3.IntegrityError)
def integrity_error(
    request: Request, exc: sqlite3.IntegrityError
) -> JSONResponse:
    """Показати конфлікт даних без тексту SQL-помилки."""
    if "records.code" in str(exc):
        message = "Код знахідки вже існує"
    elif "categories.name" in str(exc):
        message = "Назва категорії вже існує"
    elif "FOREIGN KEY" in str(exc):
        message = "Категорія містить записи"
    else:
        message = "Дані порушують обмеження бази"
    return JSONResponse(status_code=409, content={"detail": message})


@app.exception_handler(sqlite3.Error)
def database_error(request: Request, exc: sqlite3.Error) -> JSONResponse:
    """Записати технічні деталі й повернути загальну помилку клієнту."""
    logger.error("Помилка роботи з SQLite", exc_info=exc)
    return JSONResponse(
        status_code=500, content={"detail": "Не вдалося виконати операцію"}
    )


@app.get("/ping", tags=["Сервіс"], summary="Перевірка доступності")
def ping() -> dict[str, str]:
    """Повідомити, що API приймає запити."""
    return {"status": "ok"}


@app.get("/student", tags=["Сервіс"], summary="Дані студента")
def student() -> dict[str, str | int]:
    """Повернути дані зі спільного модуля попередніх робіт."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
