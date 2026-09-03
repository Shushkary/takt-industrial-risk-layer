"""Служба сборки инцидентов, работающая отдельно от приёма.

Сборка на приёме доводит поток до инцидента сразу, но прогон идёт внутри запроса и на его
время держит замок. На эталонном корпусе это 60 мс и незаметно; на хранилище в 8000 дел
полный обход стоит 1,8 с, и платит их приём — по разу на каждое срабатывание инварианта.

Здесь прогон вынесен: приём отмечает работу в очереди (`DeferAssemblyToWorker`), а эта
служба её забирает и выполняет в своём процессе. Точка входа —
`python -m takt.tools.assembly_worker`.

**Что при этом меняется, а что нет.** Условие запуска остаётся прежним — появилось
срабатывание инварианта, а не «прошло N секунд»; интервал опроса задаёт только задержку
между срабатыванием и инцидентом. Итог сборки от этого не зависит: встречаемость сущностей
пересчитывается на каждом прогоне, а редакции, которых прогон не воспроизвёл, снимаются —
поэтому и сборка внутри приёма, и сборка воркером сходятся к одному инциденту на одних и тех
же данных (замер: `tests/test_assembly_worker.py`, тот же корпус INC-002, те же 23 события).

Меняется другое: **промежуточные редакции**. Сигналы, накопленные за цикл, схлопываются в
один прогон — 19 срабатываний INC-002 дают 19 прогонов на приёме и один у воркера, если все
они пришли между двумя циклами. Итоговый инцидент тот же, но аналитик видит меньше
промежуточных карточек, а инцидент появляется в очереди позже — не в момент приёма, а на
ближайшем цикле.

Сигналы возвращаются в очередь, если прогон не удался: приём их уже не повторит, и съеденный
сигнал означал бы поток без инцидента до следующего срабатывания.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from takt.application.use_cases.assembly_on_ingest import AssemblyQueuePort
from takt.application.use_cases.auto_assemble_incidents import (
    AutoAssembleIncidentsUseCase,
    AutoAssemblyReport,
)


@dataclass(slots=True)
class AssemblyWorkerService:
    """Один цикл работы воркера: забрать сигналы и, если они есть, собрать инциденты."""

    queue: AssemblyQueuePort
    assemble: AutoAssembleIncidentsUseCase
    actor: str = "assembly-worker"
    on_error: Callable[[BaseException], None] | None = None
    runs: int = field(default=0, init=False)
    last_report: AutoAssemblyReport | None = field(default=None, init=False)

    def run_once(self) -> AutoAssemblyReport | None:
        """Выполняет прогон, если в очереди есть работа. Пусто — возвращает `None`.

        Пустой цикл не должен стоить ничего заметного: прогон — это полный обход хранилища
        дел, и запускать его «на всякий случай» раз в несколько секунд дороже, чем весь
        приём.
        """
        taken = self.queue.take_pending()
        if taken <= 0:
            return None
        self.runs += 1
        try:
            self.last_report = self.assemble.execute(actor=self.actor)
        except Exception as exc:
            # Работа возвращается в очередь: следующий цикл попробует снова.
            self.queue.note_hits(taken)
            if self.on_error is not None:
                self.on_error(exc)
            return None
        return self.last_report
