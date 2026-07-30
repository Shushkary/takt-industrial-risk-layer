"""
Состояние движка стенда TAKT — реализует принципы антихрупкости.

Здесь живёт вся изменяемая логика, благодаря которой стенд не просто
«выдерживает» действия оператора и сбои, а становится от них лучше:

  • Петля обучения по вердикту (skin in the game).
        Оператор закрывает кейс вердиктом TP / FP / benign. FP автоматически
        понижает вес инвариантов, породивших ложное срабатывание, TP —
        усиливает. Веса пересчитывают эффективный риск ВСЕХ кейсов, где эти
        инварианты встречаются. Ошибка оператора → топливо для калибровки.

  • Барбелл: риск vs импакт vs доверие.
        Эффективный риск = базовый риск × средний вес инвариантов.
        Доверие растёт с числом подтверждений инварианта (эпистемическая
        надёжность), импакт остаётся физической величиной АСУ ТП.

  • Queue lock (skin in the game + отсутствие race condition).
        Кейс берётся оператором в работу эксклюзивно.

  • Неизменяемый аудит-лог (hash-chain).
        Любое действие оператора фиксируется append-only с цепочкой хэшей —
        разбор после инцидента и защита от подмены истории.

  • Инъекция хаоса (hormesis).
        Управляемый стресс: всплеск, обрыв источника, дубли, события «из
        будущего», битый payload, задержка. Стенд деградирует, а не падает.
"""
from __future__ import annotations

import hashlib
import json
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Literal

from synthetic_data import build_cases

Verdict = Literal["tp", "fp", "benign"]
ChaosMode = Literal["off", "burst", "drop_source", "dup", "future", "malformed", "latency"]

_WEIGHT_MIN = 0.2
_WEIGHT_MAX = 1.5
_FP_DECAY = 0.6      # FP: инвариант ослабляется
_TP_REINFORCE = 1.15  # TP: инвариант усиливается


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class EngineState:
    """Потокобезопасное изменяемое состояние стенда."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cases: dict[str, dict] = {}
        # Вес каждого инварианта (петля обучения). По умолчанию 1.0.
        self._weights: dict[str, float] = defaultdict(lambda: 1.0)
        # Сколько раз инвариант подтверждён/опровергнут оператором.
        self._confirms: dict[str, int] = defaultdict(int)
        self._rejects: dict[str, int] = defaultdict(int)
        # Локи: case_id -> {operator, ts}.
        self._locks: dict[str, dict] = {}
        # Вердикты: case_id -> {...}.
        self._verdicts: dict[str, dict] = {}
        # Аудит-лог (append-only, hash-chain).
        self._audit: list[dict] = []
        # Состояние инъекции хаоса.
        self._chaos: dict[str, Any] = {"mode": "off", "since": None, "hits": 0}
        self._load()

    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        with self._lock:
            self._cases.clear()
            for c in build_cases():
                c = dict(c)
                c.pop("_chain", None)
                self._cases[c["id"]] = c

    # --- Петля обучения: эффективный риск и доверие ------------------- #
    def _invariant_factor(self, invariants: list[str]) -> float:
        if not invariants:
            return 1.0
        return sum(self._weights[i] for i in invariants) / len(invariants)

    def _effective_case(self, case: dict) -> dict:
        """Кейс с риском/доверием, пересчитанными по текущим весам."""
        out = dict(case)
        invs = case.get("invariants", [])
        factor = self._invariant_factor(invs)
        base_risk = case.get("risk_score", 0.0)
        out["base_risk_score"] = base_risk
        out["risk_score"] = round(min(1.0, base_risk * factor), 3)
        # Доверие растёт с числом подтверждений инвариантов кейса.
        confirms = sum(self._confirms[i] for i in invs)
        base_conf = case.get("confidence", 0.5)
        out["confidence"] = round(min(0.98, base_conf + 0.03 * confirms), 3)
        out["invariant_factor"] = round(factor, 3)
        # Прикладываем вердикт и лок, если есть.
        if case["id"] in self._verdicts:
            out["verdict"] = self._verdicts[case["id"]]
        if case["id"] in self._locks:
            out["lock"] = self._locks[case["id"]]
        return out

    # --- Аудит -------------------------------------------------------- #
    def _append_audit(self, action: str, case_id: str, operator: str, detail: dict) -> dict:
        prev_hash = self._audit[-1]["hash"] if self._audit else "0" * 64
        entry = {
            "seq": len(self._audit) + 1,
            "ts": _now(),
            "action": action,
            "case_id": case_id,
            "operator": operator,
            "detail": detail,
            "prev_hash": prev_hash,
        }
        payload = json.dumps(
            {k: entry[k] for k in ("seq", "ts", "action", "case_id", "operator", "detail", "prev_hash")},
            sort_keys=True, ensure_ascii=False,
        )
        entry["hash"] = hashlib.sha256((prev_hash + payload).encode()).hexdigest()
        self._audit.append(entry)
        return entry

    # ------------------------------------------------------------------ #
    # Публичное API состояния                                            #
    # ------------------------------------------------------------------ #
    def list_cases(self) -> list[dict]:
        with self._lock:
            cases = [self._effective_case(c) for c in self._cases.values()]
        return sorted(cases, key=lambda c: c.get("risk_score", 0), reverse=True)

    def get_case(self, case_id: str) -> dict | None:
        with self._lock:
            c = self._cases.get(case_id)
            return self._effective_case(c) if c else None

    def set_status(self, case_id: str, status: str) -> dict | None:
        with self._lock:
            c = self._cases.get(case_id)
            if not c:
                return None
            c["status"] = status
            c["updated_at"] = _now()
            self._append_audit("status", case_id, "operator.shift-A", {"status": status})
            return self._effective_case(c)

    def set_severity(self, case_id: str, severity: str, operator: str) -> dict | None:
        with self._lock:
            c = self._cases.get(case_id)
            if not c:
                return None
            c["severity"] = severity
            c["updated_at"] = _now()
            self._append_audit("severity", case_id, operator, {"severity": severity})
            return self._effective_case(c)

    def escalate(self, case_id: str, operator: str) -> dict | None:
        with self._lock:
            c = self._cases.get(case_id)
            if not c:
                return None
            c["status"] = "investigating"
            c["escalated"] = True
            c["updated_at"] = _now()
            self._append_audit("escalate", case_id, operator, {"to": "L2"})
            return self._effective_case(c)

    # --- Лок очереди -------------------------------------------------- #
    def lock(self, case_id: str, operator: str) -> dict | None:
        with self._lock:
            c = self._cases.get(case_id)
            if not c:
                return None
            existing = self._locks.get(case_id)
            if existing and existing["operator"] != operator:
                return {"conflict": True, **existing}
            self._locks[case_id] = {"operator": operator, "ts": _now()}
            c["status"] = "investigating" if c["status"] == "new" else c["status"]
            self._append_audit("lock", case_id, operator, {})
            return {"conflict": False, **self._locks[case_id]}

    def unlock(self, case_id: str, operator: str) -> bool:
        with self._lock:
            if case_id in self._locks:
                del self._locks[case_id]
                self._append_audit("unlock", case_id, operator, {})
            return True

    # --- Вердикт + петля обучения ------------------------------------ #
    def record_verdict(self, case_id: str, verdict: Verdict, reason: str,
                       operator: str, risk_feedback: str | None = None) -> dict | None:
        with self._lock:
            c = self._cases.get(case_id)
            if not c:
                return None
            invs: list[str] = c.get("invariants", [])
            adjusted: list[dict] = []

            for inv in invs:
                before = self._weights[inv]
                if verdict == "fp":
                    self._weights[inv] = max(_WEIGHT_MIN, before * _FP_DECAY)
                    self._rejects[inv] += 1
                elif verdict == "tp":
                    self._weights[inv] = min(_WEIGHT_MAX, before * _TP_REINFORCE)
                    self._confirms[inv] += 1
                # benign — нейтрально по весу, но фиксирует наблюдение.
                after = self._weights[inv]
                if after != before:
                    adjusted.append({"invariant": inv, "before": round(before, 3), "after": round(after, 3)})

            self._verdicts[case_id] = {
                "verdict": verdict,
                "reason": reason,
                "risk_feedback": risk_feedback,
                "operator": operator,
                "ts": _now(),
            }
            c["status"] = "resolved"
            c["updated_at"] = _now()
            self._append_audit("verdict", case_id, operator, {
                "verdict": verdict, "reason": reason, "risk_feedback": risk_feedback,
            })

            # Сколько ДРУГИХ кейсов затронуто пересчётом (эффект обучения).
            affected = [
                cid for cid, other in self._cases.items()
                if cid != case_id and set(other.get("invariants", [])) & set(invs)
            ]
            return {
                "case": self._effective_case(c),
                "adjusted_invariants": adjusted,
                "affected_cases": affected,
            }

    # --- Модель ------------------------------------------------------- #
    def model_snapshot(self) -> dict:
        with self._lock:
            weights = {k: round(v, 3) for k, v in self._weights.items()}
            verdict_counts = defaultdict(int)
            for v in self._verdicts.values():
                verdict_counts[v["verdict"]] += 1
            return {
                "weights": weights,
                "confirms": dict(self._confirms),
                "rejects": dict(self._rejects),
                "verdicts_total": len(self._verdicts),
                "verdict_counts": dict(verdict_counts),
                # Показатель обученности: суммарное отклонение весов от 1.0.
                "calibration_delta": round(sum(abs(v - 1.0) for v in self._weights.values()), 3),
            }

    def audit_log(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return self._audit[-limit:][::-1]

    # --- Chaos -------------------------------------------------------- #
    def set_chaos(self, mode: ChaosMode) -> dict:
        with self._lock:
            self._chaos = {
                "mode": mode,
                "since": _now() if mode != "off" else None,
                "hits": 0,
            }
            self._append_audit("chaos", "-", "operator.shift-A", {"mode": mode})
            return dict(self._chaos)

    def get_chaos(self) -> dict:
        with self._lock:
            return dict(self._chaos)

    def bump_chaos(self) -> None:
        with self._lock:
            self._chaos["hits"] = self._chaos.get("hits", 0) + 1

    def reset(self) -> None:
        """Полный сброс к исходному состоянию (для демо-прогонов)."""
        with self._lock:
            self._weights = defaultdict(lambda: 1.0)
            self._confirms = defaultdict(int)
            self._rejects = defaultdict(int)
            self._locks.clear()
            self._verdicts.clear()
            self._audit.clear()
            self._chaos = {"mode": "off", "since": None, "hits": 0}
            self._load()


# Единый экземпляр состояния на процесс.
STATE = EngineState()
