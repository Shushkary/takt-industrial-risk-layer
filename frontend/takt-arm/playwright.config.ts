import { defineConfig, devices } from '@playwright/test'

// В средах, где браузеры Playwright предустановлены отдельно (образ CI, offline-сборка),
// путь к Chromium задаётся переменной окружения. Пусто — используется браузер,
// установленный обычным `npx playwright install`.
const chromiumExecutable = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE

export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  expect: {
    timeout: 5_000,
  },
  use: {
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        ...(chromiumExecutable ? { launchOptions: { executablePath: chromiumExecutable } } : {}),
      },
    },
  ],
})
