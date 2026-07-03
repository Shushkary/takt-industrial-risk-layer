import type { KeyboardEvent, ReactNode } from 'react'

export type DataTableColumn<T> = {
  id: keyof T | string
  header: string
  align?: 'left' | 'right'
  cell: (row: T) => ReactNode
}

export function DataTable<T extends { id: string }>({
  columns,
  rows,
  onRowSelect,
  selectedRowId,
}: {
  columns: DataTableColumn<T>[]
  rows: T[]
  onRowSelect?: (row: T) => void
  selectedRowId?: string
}) {
  function handleRowKeyDown(event: KeyboardEvent<HTMLTableRowElement>, row: T) {
    if (!onRowSelect || (event.key !== 'Enter' && event.key !== ' ')) {
      return
    }
    event.preventDefault()
    onRowSelect(row)
  }

  return (
    <div className="overflow-auto rounded-takt border border-[var(--line)]">
      <table className="min-w-full border-collapse text-left text-[13px]">
        <thead className="sticky top-0 z-10 border-b border-[var(--line)] bg-[var(--bg-2)] text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]">
          <tr>
            {columns.map((c) => (
              <th
                key={String(c.id)}
                className={`px-3 py-2 ${c.align === 'right' ? 'text-right' : 'text-left'}`}
                scope="col"
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="text-[var(--fg-1)]">
          {rows.map((row) => (
            <tr
              key={row.id}
              aria-label={onRowSelect ? `Выбрать строку ${row.id}` : undefined}
              aria-selected={selectedRowId === row.id ? true : undefined}
              className="border-b border-[var(--line)] bg-[var(--bg-1)] last:border-b-0 hover:bg-[var(--bg-2)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--teal-1)]"
              data-row-id={row.id}
              data-testid={onRowSelect ? 'data-table-row' : undefined}
              onClick={onRowSelect ? () => onRowSelect(row) : undefined}
              onKeyDown={(event) => handleRowKeyDown(event, row)}
              role={onRowSelect ? 'button' : undefined}
              tabIndex={onRowSelect ? 0 : undefined}
            >
              {columns.map((c) => (
                <td key={String(c.id)} className={`px-3 py-2 ${c.align === 'right' ? 'text-right font-mono tabular-nums' : ''}`}>
                  {c.cell(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
