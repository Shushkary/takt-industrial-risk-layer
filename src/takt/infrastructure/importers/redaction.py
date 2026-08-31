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

Способов маскирования два, и различие между ними существенно. Поле с известным именем
(`password`, `session_key`, `cookie`) заменяется маркером целиком: содержимого, кроме
секрета, у него нет. Командная строка процесса — случай другой: в ней секрет соседствует с
тем, ради чего событие и принимается (двоичный файл, ключи запуска, пути), поэтому из неё
вычищаются только значения известных ключей передачи пароля.
"""

from __future__ import annotations

import json
import re
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
        # Пароль простой привязки LDAP. Имя поля в схеме — `simple` (по названию механизма
        # привязки), и оно единственное в 38 таблицах: путь `rqs.bind.simple`.
        "simple",
        # SNMP. `community` в версиях 1 и 2c — и есть пароль доступа к устройству;
        # `auth_params`, `privacy_params` и `security_parameters` в версии 3 — материал
        # аутентификации и шифрования. Имя пользователя (`user_name`) не маскируется: по нему
        # идёт корреляция.
        "community",
        "auth_params",
        "privacy_params",
        "security_parameters",
        # Заголовки HTTP: базовая аутентификация несёт пару «логин:пароль» в base64.
        "authorization",
        "proxy_authorization",
        # Сессионные cookie — такой же предъявитель доступа, как пароль: перехваченная из
        # трафика сессия даёт вход без него. По схемам стенда `cookie` объявлен в `rqs`
        # таблицы HTTP и отдельной колонкой в RDP, `set_cookie` — в ответе HTTP.
        "cookie",
        "set_cookie",
    }
)
REDACTED_MARKER = "[redacted]"

# Поля, которые нельзя маскировать целиком: в них секрет соседствует с тем, ради чего событие и
# принимается. Командная строка процесса — признак «процесс» из ТЗ §4.2: по ней видно, какой
# двоичный файл запущен, с какими ключами и над чем. Заменив её маркером, продукт закрыл бы
# секрет ценой самого события, поэтому из неё вычищаются только значения известных ключей
# передачи пароля.
COMMAND_LINE_FIELD_NAMES: frozenset[str] = frozenset({"cmdline", "command_line"})

# Ключи, после которых в командной строке идёт пароль. Список намеренно узкий: маскирование по
# первым двум символам (`-p`) съело бы `-path` и `-port`, а такая правка данных хуже, чем
# оставленный ключ, — она молча искажает доказательство. Ключ распознаётся целиком, а значение
# должно быть отделено разделителем.
CREDENTIAL_ARGUMENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    # --password=..., /pass:..., -pwd ...
    re.compile(
        r"(?i)(?<![\w-])(?:--?|/)(?:password|passwd|pass|pwd)(?:[:=]|\s+)(?P<secret>\S+)"
    ),
    # Короткие ключи, отведённые под пароль: psexec/mysql `-p`, sqlcmd `-P`, schtasks `/rp`.
    # `/p` в этот перечень не входит: в Windows это постраничный вывод (`dir /p`), и
    # маскирование съедало бы следующий за ним путь.
    re.compile(r"(?i)(?<![\w-])(?:-p|/rp)(?:[:=]|\s+)(?P<secret>\S+)"),
    # `net user <учётная запись> <пароль>` — пароль здесь позиционный, ключа у него нет.
    re.compile(r"(?i)(?<![\w-])net\s+user\s+\S+\s+(?P<secret>(?!/)\S+)"),
    # `net use \\srv\c$ /user:CORP\svc <пароль>` — пароль идёт следом за учётной записью.
    # Правило привязано к `net use`: у `runas /user:X "cmd.exe"` в том же месте стоит
    # запускаемая программа, и общее правило по `/user:` стирало бы её.
    re.compile(r"(?i)(?<![\w-])net\s+use\b[^\n]*?/user:\S+\s+(?P<secret>(?![-/])\S+)"),
    # PowerShell: пароль передаётся строкой в `ConvertTo-SecureString ... -AsPlainText`.
    re.compile(r"""(?i)ConvertTo-SecureString\s+(?P<secret>"[^"]*"|'[^']*'|\S+)"""),
    # `-u <логин>:<пароль>` — форма curl и smbclient.
    re.compile(r"(?i)(?<![\w-])-u\s+[^\s:]+:(?P<secret>\S+)"),
)


def mask_command_line(value: str) -> str:
    """Вычистить из командной строки значения известных ключей передачи пароля.

    Маскирование заведомо неполное: способов передать пароль аргументом больше, чем известных
    ключей, и позиционный пароль неизвестной программы отличить от имени файла нечем. Это
    осознанный размен — полное маскирование строки закрыло бы и секрет, и событие. Ключи
    перечислены в `CREDENTIAL_ARGUMENT_PATTERNS` и расширяются без правки логики.
    """
    masked = value
    for pattern in CREDENTIAL_ARGUMENT_PATTERNS:
        masked = pattern.sub(_replace_secret_group, masked)
    return masked


def _replace_secret_group(match: re.Match[str]) -> str:
    """Заменить в найденном фрагменте только группу `secret`, сохранив сам ключ."""
    text = match.group(0)
    start, end = match.span("secret")
    offset = match.start()
    return text[: start - offset] + REDACTED_MARKER + text[end - offset :]


def _field_name(key: str) -> str:
    """Имя поля из ключа документа.

    Выгрузка встречается в двух формах записи, и в плоской имя поля — последний сегмент
    ключа: `subject.process.cmdline` — это один ключ, а не вложенная запись.
    """
    return key.rsplit(".", 1)[-1]


def redact(doc: dict[str, Any]) -> dict[str, Any]:
    """Копия документа без секретов: паролей и ключей, восстановленных из трафика.

    Обход рекурсивный и проходит массивы. Прецедент: маскирование по фиксированному пути
    `credentials.password` работало только на форме записи «объект», а в схеме стенда
    `credentials` объявлено как `array(row("login", "valid", "password"))` — пароль
    доходил до `payload` целиком.
    """

    def value_of(key: str, value: Any) -> Any:
        name = _field_name(key)
        if name in REDACTED_FIELD_NAMES and value not in (None, ""):
            return REDACTED_MARKER
        if name in COMMAND_LINE_FIELD_NAMES and isinstance(value, str):
            return mask_command_line(value)
        return walk(value)

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            return {key: value_of(key, value) for key, value in node.items()}
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return walk(json.loads(json.dumps(doc, ensure_ascii=False, default=str)))


__all__ = [
    "COMMAND_LINE_FIELD_NAMES",
    "CREDENTIAL_ARGUMENT_PATTERNS",
    "REDACTED_FIELD_NAMES",
    "REDACTED_MARKER",
    "mask_command_line",
    "redact",
]
