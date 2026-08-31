"""Маскирование секретов в документах источников.

Требование ТЗ §8.7: секреты и конфиденциальные данные не попадают в открытые логи и подсказки
ИИ-модели. Здесь проверяются два разных способа маскирования и граница между ними.

Поля с известным именем (`password`, `session_key`, `cookie`) маскируются целиком: у них нет
содержимого, кроме секрета. **Командная строка процесса — случай другой**: в ней секрет
соседствует с тем, ради чего событие и принимается (двоичный файл, ключи запуска, пути), и
маскировать её целиком значит потерять главный признак процессного события. Поэтому из неё
вычищаются значения известных ключей передачи пароля, а остальное сохраняется.
"""

from __future__ import annotations

import pytest

from takt.infrastructure.importers.redaction import (
    REDACTED_MARKER,
    mask_command_line,
    redact,
)


@pytest.mark.parametrize(
    ("command_line", "secret"),
    [
        (r'net use \\srv\share /user:CORP\svc_admin --password P@ssw0rd', "P@ssw0rd"),
        (r"mysql -h db01 -u root --password=P@ssw0rd billing", "P@ssw0rd"),
        (r"psexec \\ws-17 -u CORP\admin -p P@ssw0rd cmd.exe", "P@ssw0rd"),
        (r"sqlcmd -S db01 -U sa -P P@ssw0rd -Q \"select 1\"", "P@ssw0rd"),
        (r"schtasks /create /tn upd /ru CORP\svc /rp P@ssw0rd /tr calc.exe", "P@ssw0rd"),
        (r"net user backdoor P@ssw0rd /add", "P@ssw0rd"),
        (r'ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force', "P@ssw0rd"),
        (r"curl -u svc_admin:P@ssw0rd https://api.corp.local/v1", "P@ssw0rd"),
        (r"smbclient //srv/share --pass P@ssw0rd -c ls", "P@ssw0rd"),
        (r"net use \\srv\c$ /user:CORP\svc_admin P@ssw0rd", "P@ssw0rd"),
    ],
)
def test_known_credential_keys_are_stripped_from_the_command_line(
    command_line: str, secret: str
) -> None:
    """Значение известного ключа передачи пароля из командной строки вычищается."""
    masked = mask_command_line(command_line)

    assert secret not in masked
    assert REDACTED_MARKER in masked


def test_the_rest_of_the_command_line_survives() -> None:
    """Всё, кроме самого пароля, остаётся: без этого событие теряет смысл.

    Двоичный файл, учётная запись, узел и ключи запуска — это и есть признак процессного
    события по ТЗ §4.2. Маскирование строки целиком закрыло бы секрет ценой самого события.
    """
    masked = mask_command_line(r"psexec \\ws-17 -u CORP\admin -p P@ssw0rd cmd.exe /c whoami")

    assert "psexec" in masked
    assert r"CORP\admin" in masked
    assert "cmd.exe /c whoami" in masked
    assert "P@ssw0rd" not in masked


@pytest.mark.parametrize(
    "command_line",
    [
        r"C:\Windows\System32\cmd.exe /c dir C:\Temp",
        r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Temp\update.ps1",
        r"robocopy C:\data D:\backup /mir /r:3",
        # `-path` начинается с `-p`, но паролем не является: ключ узнаётся целиком,
        # а не по первым двум символам.
        r"tool.exe -path C:\Temp\payload.bin -port 8080",
        # `/p` в Windows — постраничный вывод, а не пароль: за паролем закреплён `/rp`.
        r"cmd.exe /c dir /p C:\Temp",
        # У `runas` после `/user:` идёт запускаемая программа, а не пароль.
        r'runas /user:CORPdmin "cmd.exe /c whoami"',
    ],
)
def test_ordinary_command_line_is_untouched(command_line: str) -> None:
    """Обычная командная строка не меняется: маскирование не должно портить данные."""
    assert mask_command_line(command_line) == command_line


def test_command_line_is_masked_inside_a_document() -> None:
    """Маскирование срабатывает по имени поля в документе, в обеих формах записи.

    Выгрузка PT SIEM называет поле плоским ключом `subject.process.cmdline`, экспорт в JSON —
    вложенным `cmdline`. Разбор только одной формы оставил бы пароль в хранилище.
    """
    document = {
        "subject.process.cmdline": r"net user backdoor P@ssw0rd /add",
        "subject": {"process": {"parent": {"cmdline": r"cmd.exe /c net user svc P@ssw0rd"}}},
        "object.process.cmdline": r"powershell -File C:\Temp\a.ps1",
    }

    masked = redact(document)

    assert "P@ssw0rd" not in str(masked)
    assert masked["subject.process.cmdline"].startswith("net user backdoor")
    assert masked["object.process.cmdline"] == r"powershell -File C:\Temp\a.ps1"


def test_secret_field_is_recognised_by_a_flat_dotted_key() -> None:
    """Поле-секрет узнаётся и в плоском ключе с точкой.

    Имя поля берётся из последнего сегмента ключа: в выгрузке с плоскими ключами
    `credentials.password` — это один ключ, а не вложенная запись.
    """
    masked = redact({"credentials.password": "P@ssw0rd", "credentials.login": "svc_admin"})

    assert masked["credentials.password"] == REDACTED_MARKER
    assert masked["credentials.login"] == "svc_admin"
