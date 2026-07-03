# ТАКТ — АРМ оператора

Фронтенд АРМ расположен только в `frontend/takt-arm` текущего репозитория. Он работает в двух явно разделённых режимах:

- **API-режим**: включается через `VITE_TAKT_API_BASE_URL`; рабочие экраны читают backend API, локальные сценарные переключатели отключены.
- **Локальный демонстрационный режим**: включается только при отсутствии `VITE_TAKT_API_BASE_URL`; в шапке показывается плашка `Локальный демонстрационный режим`, локальные отчёты помечаются как `NON-EVIDENCE`.

АРМ не выполняет активное управление оборудованием, не отправляет команды на ПЛК, не блокирует учётные записи и не закрывает кейсы автоматически. Итоговое решение остаётся за оператором.

## API-интеграция

Клиент API находится в `src/app/taktApi.ts`. Runtime API configuration remains limited to `VITE_TAKT_API_BASE_URL` and `VITE_TAKT_API_KEY`.

```bash
VITE_TAKT_API_BASE_URL=http://127.0.0.1:8000
VITE_TAKT_API_KEY=optional-key
```

Подключённые рабочие API-потоки:

- `/health`, `/ready`
- `/cases`, `/cases/stats`, `/cases/{id}`
- `/cases/{id}/decision`
- `/cases/{id}/operator-actions/viewed`, `/additional-review`, `/history`
- `/cases/{id}/manual-permits`
- `/cases/{id}/formal-verdict/history`
- `/cases/{id}/forensic-bundle/manifest`, `/forensic-bundle.zip`, `/forensic-bundle/verify`
- `/cases/{id}/compliance/evidence-checklist`
- `/compliance/mode`, `/compliance/data-quality-report`, `/compliance/forensic-readiness`, `/compliance/remediations`
- `/cases/{id}/compliance/remediations`, `/recheck-readiness`, `/recheck-readiness/history`
- `/invariants`, `/catalog/event-sources`, `/topology/demo-graph`
- `/audit-ledger/operations/verify`, `/cases/{id}/audit-ledger/verify`, `/audit-engagements`
- `/events/batch` для demo-to-real ingest входной телеметрии

Ответы API валидируются через `zod`; ошибки валидации нормализуются как русские сообщения `Некорректный ответ API: ...`.

## Локальный demo boundary

`src/demo` содержит локальные сценарии теплоэнергетики Москвы, эмулятор телеметрии и fixture для загрузки событий через `/events/batch`. Эти данные используются только для явного локального demo-mode или как входной telemetry fixture для backend ingest.

В API-режиме:

- очередь инцидентов читает `/cases` с query-фильтрами, `X-Total-Count` и `Link`;
- обзор сегмента читает `/cases/stats`, `/health`, `/compliance/data-quality-report`;
- карточка кейса отправляет решения, просмотр, дополнительную проверку, ручной наряд и remediation attempts через API;
- библиотека инвариантов читает `/invariants` и `/catalog/event-sources`;
- карта сегмента строится из `/topology/demo-graph`, а локальные risk sliders отключены;
- settings/audit читает compliance, readiness, ledger verify и audit engagements endpoints.

Локальные UI-отчёты не являются доказательными артефактами. В compliance-режиме локальные отчёты очереди, инвариантов и settings/audit блокируются или остаются явно `NON-EVIDENCE`.

## Команды

```bash
cd frontend/takt-arm
npm install
npm run dev
npm run lint
npm run build
npm run test:frontend
npm run sbom:frontend
npm run build-storybook
```

`npm run test:frontend` выполняет:

- `check:workspace-boundary`
- `check:api-client`
- source-level frontend contract tests
- 44 Vitest/MSW/Testing Library unit tests
- production build без sourcemap
- frontend CycloneDX SBOM
- Playwright e2e scenarios
- frontend release artifact checks

## Release artifacts

- Production bundle: `dist/`
- Frontend SBOM: `dist/frontend-sbom.cyclonedx.json`
- frontend CycloneDX SBOM: `dist/frontend-sbom.cyclonedx.json`
- Static delivery CSP: `nginx/csp.conf`
- Node runtime pin: `.nvmrc` and `package.json` engines

Production build не использует внешние CDN; шрифты поставляются через локальные npm-пакеты `@fontsource-variable/inter` и `@fontsource/jetbrains-mono`.

## Workspace boundary

Фронтенд не должен иметь ссылок на внешние локальные рабочие деревья или абсолютные пути разработчика. Проверка:

```bash
npm run check:workspace-boundary
```

Скрипт падает при появлении запрещённых путей, внешних workspace markers или runtime API-настроек вне `VITE_TAKT_API_BASE_URL` / `VITE_TAKT_API_KEY`.
