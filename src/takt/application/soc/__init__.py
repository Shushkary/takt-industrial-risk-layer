"""L2 Application — сценарии использования ядра «SOC core» (итерация 1).

CQRS-разделение: write use cases (изменяют состояние, пишут в hash-chain журнал)
и read models (читают проекции, не агрегаты). Слой не зависит от FastAPI/инфры.
"""
