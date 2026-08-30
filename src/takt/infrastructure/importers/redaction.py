"""Маскирование секретов в документах источников до записи в `payload`.

Требование ТЗ §8.7: секреты и конфиденциальные данные не попадают в открытые логи и подсказки
ИИ-модели. Здесь оно выполняется один раз для всех коннекторов: список имён и обход документа
общие, потому что источники разные, а цена пропуска одна — пароль в хранилище кейсов,
доказательном пакете и экспорте.

Список имён составлен по фактическим схемам стенда PT NAD (`nad_table_schemas.json`, 38 таблиц):
именно трафик несёт восстановленные пароли и ключи сессий. В таксономии PT SIEM (сборка
27.0.859, 331 поле) полей-паролей не объявлено, но маскирование применяется и к её документам —
как страховка на поля вне таксономии: выгрузка несёт свободные `datafield*` и вложенные записи
нормализатора, куда секрет может попасть без объявления в схеме.
"""

from __future__ import annotations

import json
from typing import Any

# Имена полей, значения которых нельзя сохранять и журналировать. Маскирование идёт по имени
# поля, а не по фиксированному пути: путь зависит от протокола, и новая таблица иначе молча
# принесла бы пароль в `payload`.
#
# Настройки политики паролей (`max_password_age`, `min_password_length`,
# `last_password_change`) в список намеренно не входят: это состояние домена, а не значения
# паролей, и ради этого признака событие и принимается.
REDACTED_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "account_password",
        "case_insensitive_password",
        "case_sensitive_password",
        "session_key",
        "encryption_key",
        "x_csrf_token",
        # Сессионные cookie — такой же предъявитель доступа, как пароль: перехваченная из
        # трафика сессия даёт вход без него. По схемам стенда `cookie` объявлен в `rqs`
        # таблицы HTTP и отдельной колонкой в RDP, `set_cookie` — в ответе HTTP.
        "cookie",
        "set_cookie",
    }
)
REDACTED_MARKER = "[redacted]"


def redact(doc: dict[str, Any]) -> dict[str, Any]:
    """Копия документа без секретов: паролей и ключей, восстановленных из трафика.

    Обход рекурсивный и проходит массивы. Прецедент: маскирование по фиксированному пути
    `credentials.password` работало только на форме записи «объект», а в схеме стенда
    `credentials` объявлено как `array(row("login", "valid", "password"))` — пароль
    доходил до `payload` целиком.
    """

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            return {
                key: REDACTED_MARKER
                if key in REDACTED_FIELD_NAMES and value not in (None, "")
                else walk(value)
                for key, value in node.items()
            }
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return walk(json.loads(json.dumps(doc, ensure_ascii=False, default=str)))


__all__ = ["REDACTED_FIELD_NAMES", "REDACTED_MARKER", "redact"]
