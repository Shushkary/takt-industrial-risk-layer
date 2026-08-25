from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable
from typing import Literal, TypeVar
from urllib.parse import urlunparse

import httpx
from pydantic import BaseModel, Field

from takt.domain.entities.case import Case
from takt.domain.invariants.catalog import invariant_titles_by_id
from takt.infrastructure.security.webhook_allowlist import (
    assert_egress_ips_allowed,
    takt_security_profile_from_env,
)

T = TypeVar("T")

ResolveFn = Callable[[str, int], list[str]]


class SiemDataQualityBlock(BaseModel):
    dq_score: float
    partial_observability: bool
    reasons: list[str]


class SiemInvariantDetailItem(BaseModel):
    id: str = Field(..., description="Идентификатор инварианта")
    title_ru: str


class SiemPdfEvidenceBlock(BaseModel):
    sha256: str
    generated_at: str


class SiemCaseExportPayload(BaseModel):
    """Тело **`GET /cases/{id}/export/siem.json`** и JSON, отправляемый в SIEM webhook."""

    product: Literal["TAKT-MVP"] = "TAKT-MVP"
    case_id: str
    status: str
    risk_class: str
    risk_score: float
    data_quality: SiemDataQualityBlock
    title: str
    primary_asset_id: str
    last_event_source: str
    trigger_operation: str
    fingerprint: str
    xai_summary: str
    event_ids: list[str]
    invariant_hits: list[str]
    invariant_details: list[SiemInvariantDetailItem]
    audit_tail: list[str]
    pdf_evidence: SiemPdfEvidenceBlock | None = None


def case_to_siem_payload(case: Case) -> SiemCaseExportPayload:
    titles = invariant_titles_by_id()
    hits = list(case.invariant_hits)
    details = [SiemInvariantDetailItem(id=h, title_ru=titles.get(h, "") or h) for h in hits]
    return SiemCaseExportPayload(
        case_id=case.case_id,
        status=case.status.value,
        risk_class=case.risk_class,
        risk_score=case.risk_score,
        data_quality=SiemDataQualityBlock(
            dq_score=case.dq_score,
            partial_observability=case.dq_partial,
            reasons=list(case.dq_reasons),
        ),
        title=case.title,
        primary_asset_id=case.primary_asset_id,
        last_event_source=case.last_event_source,
        trigger_operation=case.trigger_operation,
        fingerprint=case.burst_fingerprint,
        xai_summary=case.xai_summary,
        event_ids=list(case.normalized_event_ids),
        invariant_hits=hits,
        invariant_details=details,
        audit_tail=list(case.audit_log[-20:]),
        pdf_evidence=(
            SiemPdfEvidenceBlock(sha256=case.pdf_last_sha256, generated_at=case.pdf_last_generated_at)
            if case.pdf_last_sha256 and case.pdf_last_generated_at
            else None
        ),
    )


def default_resolve_tcp_addrs(hostname: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    out: list[str] = []
    seen: set[str] = set()
    for _fam, _ty, _proto, _canon, sockaddr in infos:
        ip = str(sockaddr[0])
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _netloc_for_pinned_ip(ip: str, port: int, scheme: str) -> str:
    def_p = 443 if scheme == "https" else 80
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return f"{ip}:{port}" if port != def_p else ip
    h = f"[{addr.compressed}]" if isinstance(addr, ipaddress.IPv6Address) else str(addr)
    if port == def_p:
        return h
    return f"{h}:{port}"


def _build_pinned_request_url(
    *,
    scheme: str,
    hostname: str,
    port: int,
    path: str,
    params: str,
    query: str,
    fragment: str,
    pinned_ip: str,
) -> str:
    netloc = _netloc_for_pinned_ip(pinned_ip, port, scheme)
    return urlunparse((scheme, netloc, path, params, query, fragment))


def _with_retries(
    op: Callable[[], T],
    *,
    retries: int,
    backoff_sec: float,
) -> T:
    attempts = max(1, retries)
    for attempt in range(attempts):
        try:
            return op()
        except httpx.HTTPError:
            if attempt + 1 >= attempts:
                raise
            time.sleep(backoff_sec)
    raise RuntimeError("цикл повторов завершился без результата и без исключения")


async def post_case_to_webhook(
    case: Case,
    target_url: str,
    *,
    timeout_sec: float = 8.0,
    retries: int = 3,
    backoff_sec: float = 0.35,
    resolve_fn: ResolveFn | None = None,
) -> int:
    payload = case_to_siem_payload(case).model_dump(mode="json")
    profile = takt_security_profile_from_env()
    resolver = resolve_fn or default_resolve_tcp_addrs
    from urllib.parse import urlparse

    p = urlparse(target_url.strip())
    host = (p.hostname or "").strip()
    scheme = (p.scheme or "https").lower()
    port = p.port if p.port is not None else (443 if scheme == "https" else 80)
    path = p.path or "/"
    ips = resolver(host, port)
    if not ips:
        raise ValueError("webhook: DNS не вернул адресов")
    assert_egress_ips_allowed(ips, profile=profile)
    pinned = ips[0]
    pinned_url = _build_pinned_request_url(
        scheme=scheme,
        hostname=host,
        port=port,
        path=path,
        params=p.params or "",
        query=p.query or "",
        fragment=p.fragment or "",
        pinned_ip=pinned,
    )
    host_header = host if port == (443 if scheme == "https" else 80) else f"{host}:{port}"
    verify: bool | ssl.SSLContext = True
    if scheme == "https" and pinned != host:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        verify = ctx

    for attempt in range(max(1, retries)):
        try:
            async with httpx.AsyncClient(timeout=timeout_sec, verify=verify) as client:
                r = await client.post(
                    pinned_url,
                    json=payload,
                    headers={"Host": host_header},
                )
                r.raise_for_status()
                return r.status_code
        except (httpx.HTTPError, httpx.RequestError):
            if attempt + 1 >= retries:
                raise
            await asyncio.sleep(backoff_sec)

    raise RuntimeError("webhook: retries exhausted")  # pragma: no cover


def post_case_to_webhook_sync(
    case: Case,
    target_url: str,
    *,
    timeout_sec: float = 8.0,
    retries: int = 3,
    backoff_sec: float = 0.35,
    resolve_fn: ResolveFn | None = None,
) -> int:
    payload = case_to_siem_payload(case).model_dump(mode="json")
    profile = takt_security_profile_from_env()
    resolver = resolve_fn or default_resolve_tcp_addrs
    from urllib.parse import urlparse

    p = urlparse(target_url.strip())
    host = (p.hostname or "").strip()
    scheme = (p.scheme or "https").lower()
    port = p.port if p.port is not None else (443 if scheme == "https" else 80)
    path = p.path or "/"
    ips = resolver(host, port)
    if not ips:
        raise ValueError("webhook: DNS не вернул адресов")
    assert_egress_ips_allowed(ips, profile=profile)
    pinned = ips[0]
    pinned_url = _build_pinned_request_url(
        scheme=scheme,
        hostname=host,
        port=port,
        path=path,
        params=p.params or "",
        query=p.query or "",
        fragment=p.fragment or "",
        pinned_ip=pinned,
    )
    host_header = host if port == (443 if scheme == "https" else 80) else f"{host}:{port}"
    verify: bool | ssl.SSLContext = True
    if scheme == "https" and pinned != host:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        verify = ctx

    def _post() -> int:
        with httpx.Client(timeout=timeout_sec, verify=verify) as client:
            r = client.post(
                pinned_url,
                json=payload,
                headers={"Host": host_header},
            )
            r.raise_for_status()
            return r.status_code

    return _with_retries(_post, retries=retries, backoff_sec=backoff_sec)
