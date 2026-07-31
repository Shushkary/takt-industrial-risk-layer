import { expect, test } from '@playwright/test'
import { createReadStream, existsSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import { extname, join, normalize } from 'node:path'

/**
 * Сквозная проверка рабочего стола расследования на собранной витрине (ТЗ п. 14):
 * единое окно четырёх классов источников, граф связей, карточка сущности,
 * журнал находок и пакет реагирования.
 */

const distRoot = join(process.cwd(), 'dist')
let server: Server
let baseUrl = ''

const mimeTypes: Record<string, string> = {
  '.css': 'text/css',
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
}

test.beforeAll(async () => {
  server = createServer((request, response) => {
    const requestedPath = request.url?.split('?')[0] ?? '/'
    const relativePath = requestedPath === '/' ? 'index.html' : requestedPath.replace(/^\/+/, '')
    const filePath = normalize(join(distRoot, relativePath))
    const resolvedPath = filePath.startsWith(distRoot) && existsSync(filePath) ? filePath : join(distRoot, 'index.html')

    response.setHeader('Content-Type', mimeTypes[extname(resolvedPath)] ?? 'application/octet-stream')
    createReadStream(resolvedPath).pipe(response)
  })

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (address && typeof address === 'object') {
        baseUrl = `http://127.0.0.1:${address.port}`
      }
      resolve()
    })
  })
})

test.afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()))
  })
})

test('единое окно сводит четыре класса источников и строит граф связей', async ({ page }) => {
  const consoleErrors: string[] = []
  page.on('pageerror', (error) => consoleErrors.push(String(error)))

  await page.goto(baseUrl)

  await expect(page.getByRole('heading', { name: 'Рабочий стол расследования' })).toBeVisible()
  await expect(page.getByText('классов источников в кейсе:')).toBeVisible()
  await expect(page.getByText('4', { exact: true }).first()).toBeVisible()

  const graph = page.getByRole('img', { name: 'Граф связей расследования' })
  await expect(graph).toBeVisible()
  // Раскладка обязана развести узлы: слипшийся граф некликабелен.
  await expect(graph.getByRole('button').first()).toBeVisible()

  expect(consoleErrors).toEqual([])
})

test('клик по узлу графа открывает карточку сущности с историчностью', async ({ page }) => {
  await page.goto(baseUrl)

  await page.getByRole('button', { name: 'Узел: ews-01' }).click()

  await expect(page.getByText('нетипичная активность')).toBeVisible()
  await expect(page.getByRole('img', { name: 'Активность сущности по часам' })).toBeVisible()
})

test('находка фиксируется в карточке инцидента, пакет реагирования формируется вручную', async ({ page }) => {
  await page.goto(baseUrl)

  await page.getByRole('button', { name: /Находки/ }).click()
  await page.getByLabel('Новая находка').fill('Цепочка подтверждена по четырём источникам')
  await page.getByRole('button', { name: /Зафиксировать/ }).click()
  await expect(page.getByText('Цепочка подтверждена по четырём источникам')).toBeVisible()

  await page.getByRole('button', { name: /Пакет/ }).click()
  await expect(page.getByText(/Пакет только формируется/)).toBeVisible()
  await page.getByRole('button', { name: 'Подтвердить инцидент' }).click()
  await expect(page.getByRole('button', { name: 'Инцидент подтверждён' })).toBeDisabled()
})

test('хронология проигрывается и двигает курсор по событиям', async ({ page }) => {
  await page.goto(baseUrl)

  const scrub = page.getByLabel('Позиция на таймлайне расследования')
  await expect(scrub).toBeVisible()
  const before = await scrub.inputValue()

  await page.getByRole('button', { name: 'Воспроизвести хронологию' }).click()
  await page.waitForTimeout(1200)
  await page.getByRole('button', { name: 'Остановить воспроизведение' }).click()

  // Проигрывание стартует с начала, поэтому позиция обязана отличаться от конечной.
  expect(await scrub.inputValue()).not.toBe(before)
})
