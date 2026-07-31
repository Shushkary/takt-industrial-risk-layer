import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { CaseDetail } from './CaseDetail'

function renderCaseDetail() {
  render(
    <MemoryRouter initialEntries={['/cases/demo']}>
      <Routes>
        <Route path="/cases/:id" element={<CaseDetail />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('CaseDetail operator decision', () => {
  it('requires a reason before recording an operator decision', async () => {
    const user = userEvent.setup()
    renderCaseDetail()

    const decisionButton = await screen.findByTestId('case-decision-submit')
    expect(decisionButton).toBeDisabled()

    const reasonInput = document.querySelector<HTMLTextAreaElement>('#expected-reason')
    expect(reasonInput).not.toBeNull()
    await user.type(reasonInput!, 'Проверено по журналу смены и заявке сопровождения.')
    expect(decisionButton).toBeEnabled()

    await user.click(decisionButton)
    expect(await screen.findByText(/локальное демо-решение оператора без доказательной силы/i)).toBeInTheDocument()
  })
})
