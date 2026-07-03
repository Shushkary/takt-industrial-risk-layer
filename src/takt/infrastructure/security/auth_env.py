"""Переменные окружения для режима аутентификации API (Спринт 1)."""

from __future__ import annotations

import logging
import os
from typing import Literal

AuthMode = Literal["required", "optional", "disabled"]

_log = logging.getLogger("takt.auth")


def takt_profile_from_env() -> str:
    """**TAKT_PROFILE**: **dev** | **prod** | **airgap** и др.; по умолчанию **prod**."""
    raw = os.environ.get("TAKT_PROFILE", "").strip().lower()
    return raw if raw else "prod"


def takt_auth_required_from_env() -> bool:
    """
    **TAKT_AUTH_REQUIRED**: по умолчанию **True** (строгий режим: нужен **TAKT_API_KEY** на старте).
    Выключение: **0**, **false**, **no**, **off** (без учёта регистра).
    """
    raw = os.environ.get("TAKT_AUTH_REQUIRED", "").strip().lower()
    if raw in ("", "1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return True


def takt_api_key_value() -> str:
    return os.environ.get("TAKT_API_KEY", "").strip()


def auth_mode_for_health() -> AuthMode:
    required = takt_auth_required_from_env()
    key = takt_api_key_value()
    if required:
        return "required"
    if key:
        return "optional"
    return "disabled"


def _cors_all_origins_from_env() -> bool:
    raw = os.environ.get("TAKT_CORS_ORIGINS", "").strip()
    if not raw:
        return False
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return parts == ["*"]


def takt_api_keys_raw_configured() -> bool:
    """Задан ли **TAKT_API_KEYS** (непустая строка); валидность отдельных записей не проверяется здесь."""
    return bool(os.environ.get("TAKT_API_KEYS", "").strip())


def validate_startup_auth_or_raise() -> None:
    """
    Fail-closed: при включённом **TAKT_AUTH_REQUIRED** без **TAKT_API_KEY**/**TAKT_API_KEYS** — исключение,
    кроме **TAKT_PROFILE=dev** (единственный поддерживаемый режим запуска без секрета; в лог — WARNING).
    """
    if not takt_auth_required_from_env():
        if _cors_all_origins_from_env():
            raise RuntimeError(
                "FATAL: TAKT_CORS_ORIGINS=* is not allowed when TAKT_AUTH_REQUIRED is disabled."
            )
        _log.warning("TAKT_AUTH_REQUIRED отключён — режим не для промышленной эксплуатации КИИ без иных мер.")
        return
    if takt_api_key_value() or takt_api_keys_raw_configured():
        return
    if takt_profile_from_env() == "dev":
        _log.warning(
            "TAKT_PROFILE=dev: процесс запущен без TAKT_API_KEY (только для разработки; mutating-запросы по-прежнему требуют ключ при его настройке)."
        )
        return
    raise RuntimeError(
        "FATAL: TAKT_API_KEY or TAKT_API_KEYS must be set when TAKT_AUTH_REQUIRED is enabled. "
        "Use TAKT_PROFILE=dev only for local development without a secret, or set TAKT_AUTH_REQUIRED=0 (not for production)."
    )
