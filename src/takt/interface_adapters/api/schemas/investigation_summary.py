from __future__ import annotations

from pydantic import BaseModel, Field

from takt.application.use_cases.investigation_summary import CONFIDENCE_LEVELS, MAX_SECTION_LENGTH


class SummarySaveBody(BaseModel):
    """Редакция итогового описания.

    Разделы приходят словарём по ключам каталога; неизвестные ключи продукт отбрасывает, а не
    сохраняет молча — состав описания в доказательном пакете обязан совпадать с каталогом.
    """

    sections: dict[str, str] = Field(
        description="Разделы описания: ключ каталога → текст аналитика",
    )
    confidence: str = Field(
        description=f"Уверенность аналитика в оценке: {' | '.join(CONFIDENCE_LEVELS)}",
        examples=list(CONFIDENCE_LEVELS),
    )

    model_config = {
        "json_schema_extra": {
            "description": f"Предел одного раздела — {MAX_SECTION_LENGTH} знаков",
        }
    }


class SummaryApproveBody(BaseModel):
    """Утверждение конкретной редакции.

    Номер обязателен: между чтением и нажатием состав мог смениться, и утвердить вслепую
    чужую правку нельзя.
    """

    version: int = Field(ge=1, description="Номер утверждаемой редакции")
