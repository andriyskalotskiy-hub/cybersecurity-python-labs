"""Маршрути роботи з категоріями аудиту."""

from typing import Annotated

from fastapi import APIRouter, Path, Response

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["Категорії"])
CategoryId = Annotated[int, Path(gt=0, description="Додатний id категорії")]


@router.get("", response_model=list[CategoryRead], summary="Список категорій")
def list_categories():
    """Повернути категорії в порядку їхніх ідентифікаторів."""
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=201,
    summary="Створити категорію",
    responses={409: {"description": "Назва категорії вже існує"}},
)
def create_category(category: CategoryCreate):
    """Зберегти категорію з унікальною назвою."""
    return repository.create_category(category.name)


@router.delete(
    "/{category_id}",
    status_code=204,
    response_class=Response,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорії немає"},
        409: {"description": "Категорія містить записи"},
    },
)
def delete_category(category_id: CategoryId) -> Response:
    """Не дозволити видалення категорії зі знахідками."""
    repository.delete_category(category_id)
    return Response(status_code=204)
