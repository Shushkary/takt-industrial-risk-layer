"""Образ обязан находить конфигурацию продукта.

Прецедент 2026-08-21: контейнер, собранный по `Dockerfile` из репозитория, падал на старте:

    FileNotFoundError: risk weights config not found:
    /usr/local/lib/python3.13/config/risk_weights.yaml

Корень проекта вычисляется от расположения модуля (`app.py`, `_ROOT = parents[4]`). Для
раскладки `src/` это верно, но у пакета, установленного в каталог библиотек интерпретатора,
корнем оказывается сам этот каталог, где `config/` нет. `TAKT_CONFIG` не спасал:
`ensure_explicit_takt_config_under_project` требует, чтобы путь лежал внутри того же — ложного —
корня.

Лечится тем, что исходная раскладка идёт в `sys.path` раньше установленной копии. Тест
закрепляет оба конца связки: и вычисление корня, и переменную в образе. Проверка статическая —
сборка образа в тестах не запускается.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_DOCKERFILE = _ROOT / "Dockerfile"


def test_dockerfile_puts_source_layout_ahead_of_site_packages() -> None:
    text = _DOCKERFILE.read_text(encoding="utf-8")

    assert re.search(r"^\s*PYTHONPATH=/app/src\s*\\?\s*$", text, re.MULTILINE), (
        "в образе не задан PYTHONPATH=/app/src — контейнер снова будет искать config/"
        " рядом с интерпретатором и падать на старте"
    )


def test_dockerfile_copies_the_config_next_to_the_source() -> None:
    """Каталог `config/` обязан попасть в образ: без него нечего находить."""
    text = _DOCKERFILE.read_text(encoding="utf-8")

    assert re.search(r"^COPY\s+config\s+\./config\s*$", text, re.MULTILINE), text
    assert re.search(r"^COPY\s+src\s+\./src\s*$", text, re.MULTILINE), text
    assert re.search(r"^WORKDIR\s+/app\s*$", text, re.MULTILINE), text


def test_image_installs_the_export_extra() -> None:
    """Без `export` выгрузка PDF отвечает 501, а сводка для ЛПР — её основной выход."""
    text = _DOCKERFILE.read_text(encoding="utf-8")

    match = re.search(r'pip install --no-cache-dir "\.\[([a-z,]+)\]"', text)
    assert match is not None, "не найдена установка пакета с extras"
    extras = set(match.group(1).split(","))
    assert {"metrics", "export"} <= extras, extras


def test_image_provides_a_cyrillic_font_under_the_project_root() -> None:
    """Путь к шрифту проверяется на принадлежность корню проекта — файл обязан лежать в /app."""
    text = _DOCKERFILE.read_text(encoding="utf-8")

    assert "fonts-dejavu-core" in text
    assert "/app/assets/fonts/" in text


def test_config_points_at_that_font() -> None:
    """Иначе шрифт в образе есть, а PDF всё равно выходит в latin-1."""
    import yaml

    weights = yaml.safe_load((_ROOT / "config" / "risk_weights.yaml").read_text(encoding="utf-8"))
    font = str(weights.get("export", {}).get("pdf_unicode_font", ""))

    dockerfile = _DOCKERFILE.read_text(encoding="utf-8")

    assert font, "export.pdf_unicode_font не задан — кириллица в PDF станет «?»"
    assert not Path(font).is_absolute(), "путь обязан быть относительным корню проекта"
    # Имя файла и каталог назначения обязаны совпасть с тем, что кладёт образ: разъехавшись,
    # они дадут «шрифт есть, но не найден» — то есть тихий откат на latin-1.
    assert Path(font).name in dockerfile, Path(font).name
    assert f"/app/{Path(font).parent.as_posix()}/" in dockerfile


def test_project_root_is_four_levels_above_the_api_module() -> None:
    """Вторая половина связки: если правило вычисления корня изменится, PYTHONPATH не поможет."""
    from takt.interface_adapters.api import app as api_app

    module_path = Path(api_app.__file__).resolve()

    assert module_path.parents[4] == api_app._ROOT
    assert (api_app._ROOT / "config" / "risk_weights.yaml").is_file()

def test_build_revision_metadata_comes_after_the_expensive_layers() -> None:
    """Метка ревизии не имеет права ронять кэш установки зависимостей.

    `TAKT_BUILD_REVISION` меняется на каждой сборке. Пока `ARG`, `LABEL` и `ENV` с ним стояли
    до `pip install` и `apt-get`, смена одного значения инвалидировала кэш всех последующих
    слоёв, и пересборка ради строки метаданных лезла в pypi и в зеркала Debian.

    Прецедент 2026-08-27: образ `3bc35a5` собрали на стенде с ревизией `d816f4e` в метке, и
    исправить её пересборкой не вышло — у стенда нет выхода в сеть. Метку пришлось чинить
    производным образом. Метаданные в конце файла делают такую пересборку офлайновой.
    """
    text = _DOCKERFILE.read_text(encoding="utf-8")

    def position(pattern: str) -> int:
        match = re.search(pattern, text, re.MULTILINE)
        assert match is not None, f"в Dockerfile не найдено: {pattern}"
        return match.start()

    pip_install = position(r"^RUN pip install ")
    apt_get = position(r"^RUN apt-get update")
    last_expensive = max(pip_install, apt_get)

    arg = position(r"^ARG TAKT_BUILD_REVISION")
    label = position(r"^LABEL org\.opencontainers\.image\.revision")
    env = position(r"^\s*(?:ENV\s+)?TAKT_BUILD_REVISION=")

    for name, offset in (("ARG", arg), ("LABEL", label), ("ENV", env)):
        assert offset > last_expensive, (
            f"{name} с ревизией стоит до установки зависимостей — смена метки уронит кэш"
            " и потребует сети"
        )

    # ARG обязан быть объявлен раньше тех инструкций, которые его подставляют, иначе
    # значение молча станет пустым.
    assert arg < label, "LABEL подставляет ARG раньше его объявления"
    assert arg < env, "ENV подставляет ARG раньше его объявления"


def test_backtest_demo_dataset_ships_with_the_image() -> None:
    """`POST /backtest/fixture` обязан работать в образе, а не только в рабочем дереве.

    Датасет лежал в `tests/fixtures/`, а `.dockerignore` исключает `tests`. Эндпойнт описан в
    `docs/api_reference.md` как рабочий, но в любом собранном образе отвечал 500 «fixture
    missing». Перенос в `config/` лечит это: каталог копируется в образ.
    """
    dataset = _ROOT / "config" / "demo" / "plc_polling_demo.csv"

    assert dataset.is_file(), "демо-датасет бэктеста пропал из config/"

    ignored = (_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert "config" not in {line.strip() for line in ignored}
