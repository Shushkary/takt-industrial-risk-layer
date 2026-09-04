"""Точечная правка `config/risk_weights.yaml` без потери комментариев.

Файл конфигурации — это ещё и запись решений: у порогов классов риска стоит, когда и почему
они откатывались, у корреляции — почему правило ограничено списком источников. Перезапись
через `yaml.safe_dump` стёрла бы всё это молча, а вместе с этим — единственное объяснение,
почему числа именно такие. Поэтому меняются только скалярные значения названных ключей:
строка находится по имени ключа, заменяется её правая часть, остальной файл не трогается.

Веса — конфигурация, а не состояние обучаемой модели: у неё есть версия, и она уходит в отчёт
разметки (`GET /analytics/invariant-feedback`). Поэтому правка без поднятия версии здесь
невозможна — иначе два разных набора весов назывались бы в отчётах одинаково.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

# Веса факторов Risk = F(R, G, C, U, DQ). Правятся из окна; остальные ключи файла — нет.
EDITABLE_WEIGHTS: tuple[str, ...] = ("rhythm", "graph", "context", "user", "data_quality")

# Пороги классов риска. Порядок — от старшего к младшему, он же порядок проверки.
EDITABLE_THRESHOLDS: tuple[str, ...] = ("critical", "high", "medium")

# Сумма весов держится равной единице: балл риска — доля шкалы 0..1, и при другой сумме
# пороги классов перестают означать проценты шкалы, на которых они откалиброваны.
_WEIGHT_SUM_TOLERANCE = 0.001


class WeightsRewriteError(ValueError):
    """Набор не прошёл проверку или ключ не найден в файле."""


def validate(weights: dict[str, float], thresholds: dict[str, float]) -> None:
    """Проверяет набор до записи: ошибка в весах портит все последующие оценки."""
    missing = [name for name in EDITABLE_WEIGHTS if name not in weights]
    if missing:
        raise WeightsRewriteError(f"не заданы веса: {', '.join(missing)}")
    missing = [name for name in EDITABLE_THRESHOLDS if name not in thresholds]
    if missing:
        raise WeightsRewriteError(f"не заданы пороги: {', '.join(missing)}")

    for name in EDITABLE_WEIGHTS:
        value = float(weights[name])
        if not 0.0 <= value <= 1.0:
            raise WeightsRewriteError(f"вес {name} вне диапазона 0..1: {value}")
    total = sum(float(weights[name]) for name in EDITABLE_WEIGHTS)
    if abs(total - 1.0) > _WEIGHT_SUM_TOLERANCE:
        raise WeightsRewriteError(f"сумма весов должна равняться 1.000, получено {total:.3f}")

    critical = float(thresholds["critical"])
    high = float(thresholds["high"])
    medium = float(thresholds["medium"])
    if not 0.0 < medium < high < critical <= 1.0:
        raise WeightsRewriteError(
            "пороги должны идти по возрастанию в пределах 0..1: "
            f"средний {medium:.2f} < высокий {high:.2f} < критический {critical:.2f}"
        )


def next_version(current: str, today: date) -> str:
    """Следующая метка версии в формате ГГГГ.ММ.N.

    Внутри одного месяца растёт порядковый номер; в новом месяце счёт начинается заново.
    Нераспознанная метка не разбирается по частям и не «чинится»: с ней версия просто
    начинается с первой в текущем месяце, и по отчётам видно, что нумерация прервалась.
    """
    prefix = f"{today.year:04d}.{today.month:02d}"
    match = re.fullmatch(r"(\d{4})\.(\d{2})\.(\d+)", str(current).strip())
    if match and f"{match.group(1)}.{match.group(2)}" == prefix:
        return f"{prefix}.{int(match.group(3)) + 1}"
    return f"{prefix}.1"


def _replace_scalar(lines: list[str], index: int, value: str) -> None:
    """Меняет правую часть строки `ключ: значение`, сохраняя отступ, ключ и хвостовой комментарий."""
    line = lines[index]
    match = re.match(r"^(\s*[A-Za-z_][A-Za-z0-9_]*:\s*)(.*?)(\s*#.*)?$", line)
    if match is None:  # pragma: no cover - строку сюда приводит _find_key
        raise WeightsRewriteError(f"строка не разбирается как «ключ: значение»: {line!r}")
    lines[index] = f"{match.group(1)}{value}{match.group(3) or ''}"


def _find_top_level(lines: list[str], key: str) -> int:
    for index, line in enumerate(lines):
        if re.match(rf"^{re.escape(key)}:\s", line) or line.rstrip() == f"{key}:":
            return index
    raise WeightsRewriteError(f"ключ верхнего уровня не найден: {key}")


def _find_nested(lines: list[str], parent: str, key: str) -> int:
    start = _find_top_level(lines, parent)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[:1].isspace():  # вышли из блока родителя
            break
        if re.match(rf"^\s+{re.escape(key)}:\s", line):
            return index
    raise WeightsRewriteError(f"ключ не найден: {parent}.{key}")


def _number(value: float) -> str:
    """Число в том же виде, в каком его пишут в файле руками.

    Двузначная дробь остаётся двузначной (`0.20`, а не `0.2`): в столбце весов выровненные
    значения читаются как набор, а разнобой в разрядах — как случайные числа. Более точное
    значение показывается как есть, без хвостовых нулей `0.22000000000000003`.
    """
    number = float(value)
    if round(number, 2) == number:
        return f"{number:.2f}"
    return f"{number:.6f}".rstrip("0").rstrip(".") or "0"


def read_source(path: Path) -> tuple[str, str]:
    """Текст файла с переводами строк, приведёнными к `\\n`, и исходный перевод строки.

    Перевод строки возвращается отдельно и восстанавливается при записи: правка одного числа
    не должна показывать в `git diff` весь файл как изменённый.
    """
    with path.open(encoding="utf-8", newline="") as source:
        raw = source.read()
    newline = "\r\n" if "\r\n" in raw else "\n"
    return raw.replace("\r\n", "\n"), newline


def write_source(path: Path, text: str, newline: str) -> None:
    with path.open("w", encoding="utf-8", newline="") as target:
        target.write(text.replace("\n", newline) if newline != "\n" else text)


def rewrite_risk_weights(
    text: str,
    *,
    weights: dict[str, float],
    thresholds: dict[str, float],
    version: str,
) -> str:
    """Возвращает содержимое файла с новыми весами, порогами и версией.

    Набор проверяется до записи целиком: частично применённая правка оставила бы файл
    в наборе, которого никто не назначал.
    """
    validate(weights, thresholds)
    lines = text.split("\n")

    for name in EDITABLE_WEIGHTS:
        _replace_scalar(lines, _find_top_level(lines, name), _number(weights[name]))
    for name in EDITABLE_THRESHOLDS:
        _replace_scalar(lines, _find_nested(lines, "risk_class_thresholds", name), _number(thresholds[name]))
    _replace_scalar(lines, _find_top_level(lines, "version"), f'"{version}"')

    return "\n".join(lines)
