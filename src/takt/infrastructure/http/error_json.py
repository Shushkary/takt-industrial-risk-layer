from __future__ import annotations

from starlette.requests import Request


def error_json_content(detail: str, request: Request) -> dict[str, str]:
    """Тело **JSON** для ответов ошибок middleware: **`detail`** и при наличии **`request_id`** из **`request.state`**."""
    rid = getattr(request.state, "request_id", None)
    out: dict[str, str] = {"detail": detail}
    if isinstance(rid, str) and rid.strip():
        out["request_id"] = rid.strip()
    return out
