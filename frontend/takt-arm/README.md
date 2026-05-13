# ТАКТ — АРМ оператора (фронтенд MVP)

Каркас UI по документу `D:\TAKT\docs\ТАКТ_Фронтенд_Промпт_и_Чеклист.docx` (версия 1.0): токены, шесть экранов-заглушек, локальные шрифты без CDN.

## Технологии

- React 19 + TypeScript + Vite 6
- Tailwind CSS 3 (утилиты + CSS variables для палитры)
- React Router (боковая навигация и маршруты)
- Zustand (локальное состояние режима сегмента / фазы смены — для прототипа шапки)
- Шрифты: `@fontsource-variable/inter`, `@fontsource/jetbrains-mono` (пакуются в бандл)

## Команды

```bash
cd frontend/takt-arm
npm install
npm run dev
npm run build
npm run lint
npm run storybook
npm run build-storybook
```

## Следующие шаги по чек-листу из .docx

1. Дизайн-система: StatusPill, DataTable, Callout, NodeIcon; Storybook.
2. Экраны: causal mesh, виртуализация очереди, XAI из API, библиотека инвариантов из `/invariants`, топология, аудит.
3. Мок-сценарий «Jump-Server Bypass» end-to-end.
4. Vitest + Playwright, CSP/nginx, SBOM фронта (CycloneDX) в CI.

Артефакты поставки: каталог `dist/` после `npm run build` (без sourcemap в production — см. `vite.config.ts`).
