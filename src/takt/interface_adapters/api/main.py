from __future__ import annotations

import sys

from . import app as _app
from .app import app, create_app  # noqa: F401  — имена, которые импортируют снаружи

# Модуль подменяет собой `app`: тесты и код обращаются к `api.main.<имя>`, а реализация
# живёт в `app.py`. Импорт выше нужен проверке типов — сквозь подмену она не видит имён.
sys.modules[__name__] = _app
