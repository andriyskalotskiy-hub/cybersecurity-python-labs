"""Моделі запитів, відповідей і початкових даних."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03.config import MAX_VALUE, MIN_VALUE

RecordStatus = Literal["new", "in_progress", "done"]


class CategoryCreate(BaseModel):
    """Назва нової категорії без ідентифікатора."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=2, max_length=40, examples=["iam"])


class CategoryRead(CategoryCreate):
    """Категорія, збережена в базі."""

    id: int = Field(gt=0)


class RecordCreate(BaseModel):
    """Знахідка хмарного аудиту для створення."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    code: str = Field(min_length=3, max_length=40, examples=["V13-09"])
    title: str = Field(
        min_length=3,
        max_length=120,
        examples=["Відкритий доступ до сховища"],
    )
    category_id: int = Field(gt=0, examples=[2])
    value: float = Field(
        ge=MIN_VALUE, le=MAX_VALUE, allow_inf_nan=False, examples=[8.5]
    )
    status: RecordStatus


class RecordReplace(RecordCreate):
    """Повна заміна всіх змінюваних полів знахідки."""


class RecordRead(RecordCreate):
    """Знахідка разом із назвою категорії та ідентифікатором."""

    id: int = Field(gt=0)
    category_name: str


class SeedData(BaseModel):
    """Три категорії та вісім записів початкового набору."""

    model_config = ConfigDict(extra="forbid")
    categories: list[CategoryRead] = Field(min_length=3, max_length=3)
    records: list[RecordCreate] = Field(min_length=8, max_length=8)
