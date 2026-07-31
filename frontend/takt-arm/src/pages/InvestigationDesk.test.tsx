import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { InvestigationDesk } from './InvestigationDesk'
import { demoWorkspace } from '../investigation/demoInvestigation'

/**
 * Проверяется контур ТЗ п. 14: единое окно с четырьмя классами источников,
 * граф связей, карточка сущности, журнал находок и пакет реагирования.
 * Тесты идут в демонстрационном режиме (VITE_TAKT_API_BASE_URL не задан).
 */

function renderDesk() {
  return render(
    <MemoryRouter>
      <InvestigationDesk />
    </MemoryRouter>,
  )
}

describe('рабочий стол расследования', () => {
  it('сводит события всех четырёх классов источников в одно окно', () => {
    renderDesk()
    expect(screen.getByRole('heading', { name: 'Рабочий стол расследования' })).toBeInTheDocument()
    expect(screen.getByLabelText('Слияние источников в один кейс')).toBeInTheDocument()

    const sources = new Set(demoWorkspace.events.map((event) => event.source))
    expect(sources).toEqual(new Set(['edr', 'siem', 'ndr', 'ot']))
    expect(screen.getByText(/классов источников в кейсе:/)).toBeInTheDocument()
  })

  it('строит граф связей, в котором рёбра соединяют существующие узлы', () => {
    renderDesk()
    expect(screen.getByRole('img', { name: 'Граф связей расследования' })).toBeInTheDocument()

    const nodeIds = new Set(demoWorkspace.graph.nodes.map((node) => node.id))
    expect(nodeIds.size).toBeGreaterThan(0)
    for (const edge of demoWorkspace.graph.edges) {
      expect(nodeIds.has(edge.source)).toBe(true)
      expect(nodeIds.has(edge.target)).toBe(true)
    }
  })

  it('открывает карточку сущности с историчностью по клику на узел графа', async () => {
    const user = userEvent.setup()
    renderDesk()

    await user.click(screen.getByRole('button', { name: 'Узел: ews-01' }))

    expect(await screen.findByText('нетипичная активность')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: 'Активность сущности по часам' })).toBeInTheDocument()
    expect(screen.getByText(/Окружение \(/)).toBeInTheDocument()
  })

  it('даёт зафиксировать находку в карточке инцидента', async () => {
    const user = userEvent.setup()
    renderDesk()

    await user.click(screen.getByRole('button', { name: /Находки/ }))
    await user.type(screen.getByLabelText('Новая находка'), 'Подтверждено воздействие на контур')
    await user.click(screen.getByRole('button', { name: /Зафиксировать/ }))

    expect(await screen.findByText('Подтверждено воздействие на контур')).toBeInTheDocument()
  })

  it('формирует пакет реагирования и не выполняет критичные действия сам', async () => {
    const user = userEvent.setup()
    renderDesk()

    await user.click(screen.getByRole('button', { name: /Пакет/ }))
    expect(screen.getByText(/Пакет только формируется/)).toBeInTheDocument()

    const confirm = screen.getByRole('button', { name: 'Подтвердить инцидент' })
    expect(confirm).toBeEnabled()
    await user.click(confirm)
    expect(await screen.findByRole('button', { name: 'Инцидент подтверждён' })).toBeDisabled()
  })

  it('управляет хронологией: таймлайн имеет воспроизведение и позицию', () => {
    renderDesk()
    expect(screen.getByRole('button', { name: 'Воспроизвести хронологию' })).toBeInTheDocument()
    expect(screen.getByLabelText('Позиция на таймлайне расследования')).toBeInTheDocument()
  })

  it('помечает демонстрационный режим, чтобы данные не принимали за живые', () => {
    renderDesk()
    const header = screen.getByRole('banner')
    expect(within(header).getByText('демонстрационный набор')).toBeInTheDocument()
  })
})
