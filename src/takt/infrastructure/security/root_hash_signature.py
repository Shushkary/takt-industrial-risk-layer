from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

import httpx

_HMAC_ENV = "TAKT_FORENSIC_HMAC_SECRET"
_SIGN_URL_ENV = "TAKT_FORENSIC_SIGN_URL"
_VERIFY_URL_ENV = "TAKT_FORENSIC_VERIFY_URL"
_HTTP_TIMEOUT_ENV = "TAKT_FORENSIC_SIGNATURE_TIMEOUT_SEC"
_MODE_ENV = "TAKT_FORENSIC_CRYPTO_MODE"


@dataclass(frozen=True, slots=True)
class RootHashSignature:
    signature_status: str
    signature_ref: str
    payload: dict[str, object] | None


@dataclass(frozen=True, slots=True)
class RootHashSignatureVerification:
    ok: bool
    issue_code: str = ""
    issue_detail: str = ""


def _timeout_sec() -> float:
    raw = os.environ.get(_HTTP_TIMEOUT_ENV, "").strip()
    if not raw:
        return 5.0
    try:
        val = float(raw)
    except ValueError:
        return 5.0
    if val <= 0:
        return 5.0
    return min(val, 60.0)


def _hmac_sign(root_hash: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), root_hash.encode("ascii"), hashlib.sha256).hexdigest()


def _crypto_mode() -> str:
    return os.environ.get(_MODE_ENV, "").strip().lower() or "mvp"


class RootHashSignatureAdapter:
    """
    Root hash signature adapter chain:
    1) external qualified-like HTTP signer (if TAKT_FORENSIC_SIGN_URL is set),
    2) HMAC MVP signer (if TAKT_FORENSIC_HMAC_SECRET is set, mvp mode only),
    3) unsigned MVP fallback (mvp mode only).

    In gost_strict mode external signer is mandatory and no HMAC/unsigned fallback is allowed.
    """

    def build_signature(self, root_hash_sha256: str) -> RootHashSignature:
        strict_mode = _crypto_mode() == "gost_strict"
        sign_url = os.environ.get(_SIGN_URL_ENV, "").strip()
        if sign_url:
            try:
                response = httpx.post(
                    sign_url,
                    json={"root_hash_sha256": root_hash_sha256},
                    timeout=_timeout_sec(),
                )
                response.raise_for_status()
                body = response.json()
                payload: dict[str, object] = {
                    "algorithm": str(body.get("algorithm", "GOST-detached")),
                    "root_hash_sha256": root_hash_sha256,
                    "signature": str(body.get("signature", "")),
                    "key_id": str(body.get("key_id", "")),
                    "provider": "external_http",
                    "signature_status": "external_qualified_detached",
                }
                if strict_mode:
                    alg = str(payload.get("algorithm", "")).upper()
                    if "GOST" not in alg:
                        raise RuntimeError("strict crypto mode requires GOST algorithm from signer")
                    if not str(payload.get("signature", "")).strip():
                        raise RuntimeError("strict crypto mode requires non-empty signature")
                    payload["signature_status"] = "external_gost2012_detached"
                    return RootHashSignature(
                        signature_status="external_gost2012_detached",
                        signature_ref="root-hash-signature.json",
                        payload=payload,
                    )
                return RootHashSignature(
                    signature_status="external_qualified_detached",
                    signature_ref="root-hash-signature.json",
                    payload=payload,
                )
            except Exception as exc:
                if strict_mode:
                    raise RuntimeError(
                        "strict crypto mode requires successful external signer response"
                    ) from exc
                payload = {
                    "algorithm": "external_http_error",
                    "root_hash_sha256": root_hash_sha256,
                    "signature": "",
                    "key_id": "",
                    "provider": "external_http",
                    "signature_status": "external_signing_failed_fallback_hmac_or_unsigned",
                    "error": str(exc),
                }
                secret = os.environ.get(_HMAC_ENV, "")
                if secret:
                    payload["algorithm"] = "HMAC-SHA256"
                    payload["signature_hex"] = _hmac_sign(root_hash_sha256, secret)
                    payload["key_id"] = _HMAC_ENV
                    payload["warning"] = (
                        "External signer failed; HMAC fallback used. "
                        "This is still MVP integrity signature, not qualified GOST signature."
                    )
                    return RootHashSignature(
                        signature_status="hmac_sha256_mvp",
                        signature_ref="root-hash-signature.json",
                        payload=payload,
                    )
                return RootHashSignature(signature_status="unsigned_mvp", signature_ref="", payload=payload)

        if strict_mode:
            raise RuntimeError(f"{_SIGN_URL_ENV} is required when {_MODE_ENV}=gost_strict")

        secret = os.environ.get(_HMAC_ENV, "")
        if secret:
            return RootHashSignature(
                signature_status="hmac_sha256_mvp",
                signature_ref="root-hash-signature.json",
                payload={
                    "algorithm": "HMAC-SHA256",
                    "root_hash_sha256": root_hash_sha256,
                    "signature_hex": _hmac_sign(root_hash_sha256, secret),
                    "key_id": _HMAC_ENV,
                    "signature_status": "hmac_sha256_mvp",
                    "warning": "MVP integrity signature; not a qualified electronic signature and not certified GOST crypto.",
                },
            )
        return RootHashSignature(signature_status="unsigned_mvp", signature_ref="", payload=None)

    def verify_signature(
        self,
        *,
        signature_status: str,
        root_hash_sha256: str,
        signature_payload: dict[str, object] | None,
    ) -> RootHashSignatureVerification:
        if signature_status == "unsigned_mvp":
            return RootHashSignatureVerification(ok=True)
        if signature_status == "hmac_sha256_mvp":
            secret = os.environ.get(_HMAC_ENV, "")
            if not secret:
                return RootHashSignatureVerification(
                    ok=False,
                    issue_code="signature_secret_missing",
                    issue_detail=f"{_HMAC_ENV} is required to verify HMAC signature",
                )
            got = str((signature_payload or {}).get("signature_hex", ""))
            expected = _hmac_sign(root_hash_sha256, secret)
            if not hmac.compare_digest(got, expected):
                return RootHashSignatureVerification(
                    ok=False,
                    issue_code="signature_mismatch",
                    issue_detail="root hash HMAC signature mismatch",
                )
            return RootHashSignatureVerification(ok=True)
        if signature_status in {"external_qualified_detached", "external_gost2012_detached"}:
            verify_url = os.environ.get(_VERIFY_URL_ENV, "").strip()
            if not verify_url:
                return RootHashSignatureVerification(
                    ok=False,
                    issue_code="signature_verifier_unconfigured",
                    issue_detail=f"{_VERIFY_URL_ENV} is required to verify external signature",
                )
            try:
                response = httpx.post(
                    verify_url,
                    json={
                        "root_hash_sha256": root_hash_sha256,
                        "signature": signature_payload or {},
                    },
                    timeout=_timeout_sec(),
                )
                response.raise_for_status()
                body = response.json()
                if bool(body.get("ok", False)):
                    if signature_status == "external_gost2012_detached":
                        alg = str((signature_payload or {}).get("algorithm", "")).upper()
                        if "GOST" not in alg:
                            return RootHashSignatureVerification(
                                ok=False,
                                issue_code="signature_algorithm_invalid",
                                issue_detail="strict mode signature payload does not declare GOST algorithm",
                            )
                    return RootHashSignatureVerification(ok=True)
                return RootHashSignatureVerification(
                    ok=False,
                    issue_code="signature_mismatch",
                    issue_detail=str(body.get("detail", "external signature verification failed")),
                )
            except Exception as exc:
                return RootHashSignatureVerification(
                    ok=False,
                    issue_code="signature_verification_error",
                    issue_detail=str(exc),
                )
        return RootHashSignatureVerification(
            ok=False,
            issue_code="unknown_signature_status",
            issue_detail=f"unsupported signature_status={signature_status!r}",
        )
