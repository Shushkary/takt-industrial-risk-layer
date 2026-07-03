import type { Meta, StoryObj } from '@storybook/react'
import { DataTable, type DataTableColumn } from './DataTable'

type Row = { id: string; time: string; node: string; risk: string }

const rows: Row[] = [
  { id: '1', time: '13.05.2026 02:14:08', node: 'плк-сборка-03', risk: '0,812' },
  { id: '2', time: '13.05.2026 02:09:51', node: 'арм-инженера-02', risk: '0,441' },
]

const columns: DataTableColumn<Row>[] = [
  { id: 'time', header: 'Время', cell: (row) => row.time },
  { id: 'node', header: 'Узел', cell: (row) => row.node },
  {
    id: 'risk',
    header: 'Индекс риска',
    align: 'right',
    cell: (row) => <span className="font-mono tabular-nums">{row.risk}</span>,
  },
]

function DataTableDemo() {
  return <DataTable columns={columns} rows={rows} />
}

const meta = {
  title: 'Интерфейс/Таблица данных',
  component: DataTableDemo,
} satisfies Meta<typeof DataTableDemo>

export default meta
type Story = StoryObj<typeof meta>

export const Инциденты: Story = {
  render: () => <DataTableDemo />,
}
