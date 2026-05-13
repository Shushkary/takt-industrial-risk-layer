import type { Meta, StoryObj } from '@storybook/react'
import { DataTable, type DataTableColumn } from './DataTable'

type Row = { id: string; time: string; node: string; risk: string }

const rows: Row[] = [
  { id: '1', time: '13.05.2026 02:14:08', node: 'plc-assembly-03', risk: '0,812' },
  { id: '2', time: '13.05.2026 02:09:51', node: 'eng-workstation-02', risk: '0,441' },
]

const columns: DataTableColumn<Row>[] = [
  { id: 'time', header: 'Время', cell: (r) => r.time },
  { id: 'node', header: 'Узел', cell: (r) => r.node },
  {
    id: 'risk',
    header: 'Risk Index',
    align: 'right',
    cell: (r) => <span className="font-mono tabular-nums">{r.risk}</span>,
  },
]

function DataTableDemo() {
  return <DataTable columns={columns} rows={rows} />
}

const meta = {
  title: 'UI/DataTable',
  component: DataTableDemo,
} satisfies Meta<typeof DataTableDemo>

export default meta
type Story = StoryObj<typeof meta>

export const Incidents: Story = {
  render: () => <DataTableDemo />,
}
