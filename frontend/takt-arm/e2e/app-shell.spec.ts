import { expect, test } from '@playwright/test'
import { createReadStream, existsSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import { extname, join, normalize } from 'node:path'

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

test('operator shell renders in explicit local demo mode without active control actions', async ({ page }) => {
  await page.goto(baseUrl)

  await expect(page.getByText('Нормативный режим выключен')).toBeVisible()
  await expect(page.locator('#demo-scenario')).toBeEnabled()
  await expect(page.getByText(/active control/i)).toHaveCount(0)
})

test('queue row can be selected with keyboard and opened as a case for operator decision', async ({ page }) => {
  await page.goto(`${baseUrl}/incidents`)

  const rows = page.getByTestId('data-table-row')
  await expect(rows.first()).toBeVisible()
  await rows.first().focus()
  await rows.first().press('Enter')
  await page.getByTestId('incident-open-case').click()

  await expect(page).toHaveURL(/\/cases\//)
  await page.locator('#expected-reason').fill('Проверено по журналу смены и заявке сопровождения.')
  await page.getByTestId('case-decision-submit').click()

  await expect(page.getByText(/локальное демо-решение оператора без доказательной силы/i)).toBeVisible()
})

test('manual permit and formal verdict are recorded through the case workflow', async ({ page }) => {
  await page.goto(`${baseUrl}/cases/demo`)

  await page.locator('#permit-work-order').fill('WO-E2E-0001')
  await page.locator('#permit-executor').fill('дежурный инженер')
  await page.locator('#permit-approver').fill('начальник смены')
  await page.locator('#permit-note').fill('Наряд проверен оператором перед классификацией.')
  await page.getByTestId('case-manual-permit-submit').click()
  await expect(page.getByText('WO-E2E-0001', { exact: true }).first()).toBeVisible()
  await expect(page.getByText(/локальный демо-наряд без доказательной силы.*WO-E2E-0001/i)).toBeVisible()

  await page.locator('#formal-reason').fill('Оператор сверил событие с нарядом и журналом телеметрии.')
  await page.locator('#formal-note').fill('E2E verdict note')
  await page.getByTestId('case-formal-verdict-submit').click()
  await expect(page.getByText(/локальный демо-вердикт без доказательной силы/i)).toBeVisible()
})

test('local forensic export remains non-evidence and does not enable server ZIP verification', async ({ page }) => {
  await page.goto(`${baseUrl}/cases/demo`)

  const download = page.waitForEvent('download')
  await page.getByTestId('case-forensic-download').click()
  await download

  await expect(page.getByText(/non-evidence local operator note/i).first()).toBeVisible()
  await expect(page.getByTestId('case-forensic-verify')).toBeDisabled()
})
