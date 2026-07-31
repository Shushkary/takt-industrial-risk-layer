import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

const server = setupServer()

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  server.resetHandlers()
  vi.unstubAllEnvs()
})
afterAll(() => server.close())

beforeEach(() => {
  vi.resetModules()
  vi.stubEnv('VITE_TAKT_API_BASE_URL', 'http://takt.test')
})

describe('AppShell API mode boundary', () => {
  it('disables local demo controls when the backend API is configured', async () => {
    server.use(
      http.get('http://takt.test/compliance/mode', () =>
        HttpResponse.json({
          mode: 'compliance',
          compliance_enabled: true,
          human_final_decision_required: true,
          no_active_control: true,
        }),
      ),
      http.get('http://takt.test/ready', () => HttpResponse.json({ status: 'ready' })),
    )

    const { AppShell } = await import('./AppShell')

    render(
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<AppShell />}>
            <Route index element={<div>Рабочая область</div>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    )

    expect(await screen.findByText('Нормативный режим включён')).toBeInTheDocument()
    expect(await screen.findByText('API готов')).toBeInTheDocument()
    expect(screen.getByText('Демо-режим отключён в API-режиме.')).toBeInTheDocument()
    expect(document.querySelector<HTMLSelectElement>('#demo-scenario')).toBeDisabled()
  })
})
