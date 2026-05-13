import { DataTable, type DataTableColumn } from '../components/ui/DataTable'

type Row = { id: string; time: string; node: string; invariant: string; risk: string; status: string }

const columns: DataTableColumn<Row>[] = [
  { id: 'time', header: 'Время', cell: (r) => r.time },
  { id: 'node', header: 'Узел', cell: (r) => r.node },
  { id: 'invariant', header: 'Инвариант', cell: (r) => r.invariant },
  {
    id: 'risk',
    header: 'Risk Index',
    align: 'right',
    cell: (r) => <span className="font-mono tabular-nums">{r.risk}</span>,
  },
  { id: 'status', header: 'Статус', cell: (r) => r.status },
]

const rows: Row[] = [
  {
    id: '1',
    time: '13.05.2026 02:14:08',
    node: 'plc-assembly-03',
    invariant: 'jump_server_bypass',
    risk: '0,812',
    status: 'TRIAGE',
  },
]

export function IncidentQueue() {
  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-[20px] font-semibold text-[var(--fg-1)]">Очередь инцидентов</h1>
      <p className="max-w-[72ch] text-[13px] text-[var(--fg-2)]">
        Таблица на базе `DataTable` (мок). Виртуализация до 50 000 строк — следующий этап.
      </p>
      <DataTable columns={columns} rows={rows} />
    </div>
  )
}
