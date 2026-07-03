import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DataTable, type DataTableColumn } from './DataTable'

type Row = {
  id: string
  title: string
}

const columns: DataTableColumn<Row>[] = [{ id: 'title', header: 'Название', cell: (row) => row.title }]
const rows: Row[] = [
  { id: 'case-1', title: 'Первый кейс' },
  { id: 'case-2', title: 'Второй кейс' },
]

describe('DataTable selectable rows', () => {
  it('selects rows by click and keyboard', async () => {
    const user = userEvent.setup()
    const onRowSelect = vi.fn()

    render(<DataTable columns={columns} rows={rows} onRowSelect={onRowSelect} />)

    const selectableRows = screen.getAllByTestId('data-table-row')
    await user.click(selectableRows[0])
    expect(onRowSelect).toHaveBeenLastCalledWith(rows[0])

    selectableRows[1].focus()
    await user.keyboard('{Enter}')
    expect(onRowSelect).toHaveBeenLastCalledWith(rows[1])

    await user.keyboard(' ')
    expect(onRowSelect).toHaveBeenLastCalledWith(rows[1])
  })
})
