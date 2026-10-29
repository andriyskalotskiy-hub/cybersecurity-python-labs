"""Маршрути знахідок хмарного аудиту."""

from typing import Annotated

from fastapi import APIRouter, Body, Path, Query, Response

from labs.lab03 import repository
from labs.lab03.config import MAX_VALUE, MIN_VALUE
from labs.lab03.schemas import (
    RecordCreate,
    RecordRead,
    RecordReplace,
    RecordStatus,
)

router = APIRouter(prefix="/records", tags=["Знахідки"])
RecordId = Annotated[int, Path(gt=0, description="Додатний id знахідки")]
ERRORS = {
    404: {"description": "Запису або категорії немає"},
    409: {"description": "Код знахідки вже існує"},
}


@router.get("", response_model=list[RecordRead], summary="Список і фільтри")
def list_records(
    category_id: Annotated[
        int | None, Query(gt=0, description="Напрям перевірки")
    ] = None,
    status: Annotated[
        RecordStatus | None, Query(description="Стан опрацювання")
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=MIN_VALUE,
            le=MAX_VALUE,
            allow_inf_nan=False,
            description="Мінімальна оцінка ризику; поріг варіанта 7.0",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=120,
            description="Буквальний підрядок у назві",
        ),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Поєднати фільтри через AND та повернути сторінку результатів."""
    return repository.list_records(
        category_id, status, min_value, q, limit, offset
    )


@router.post(
    "",
    response_model=RecordRead,
    status_code=201,
    summary="Створити знахідку",
    responses=ERRORS,
)
def create_record(record: RecordCreate):
    """Перевірити вхідну модель і додати знахідку."""
    return repository.create_record(record.model_dump())


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=201,
    summary="Додати пакет знахідок",
    responses=ERRORS,
)
def create_records_bulk(
    records: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
):
    """Додати від 1 до 100 знахідок в одній транзакції."""
    return repository.create_records_bulk(
        [record.model_dump() for record in records]
    )


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати знахідку",
    responses={404: {"description": "Запису немає"}},
)
def get_record(record_id: RecordId):
    """Отримати один запис за додатним id."""
    return repository.get_record(record_id)


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повністю оновити знахідку",
    responses=ERRORS,
)
def replace_record(record_id: RecordId, record: RecordReplace):
    """Замінити всі змінювані поля наявної знахідки."""
    return repository.replace_record(record_id, record.model_dump())


@router.delete(
    "/{record_id}",
    status_code=204,
    response_class=Response,
    summary="Видалити знахідку",
    responses={404: {"description": "Запису немає"}},
)
def delete_record(record_id: RecordId) -> Response:
    """Видалити запис і повернути порожню відповідь."""
    repository.delete_record(record_id)
    return Response(status_code=204)
