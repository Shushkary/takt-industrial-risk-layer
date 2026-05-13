type NodeKind = 'server' | 'plc' | 'gateway' | 'workstation' | 'external'

const titles: Record<NodeKind, string> = {
  server: 'Сервер',
  plc: 'ПЛК',
  gateway: 'Шлюз',
  workstation: 'Инженерная станция',
  external: 'Внешний узел',
}

/** Геометрические примитивы узлов графа (без цветных иллюстраций). */
export function NodeIcon({ kind, active }: { kind: NodeKind; active?: boolean }) {
  const ring = active ? 'ring-2 ring-[var(--amber-1)]' : ''
  const base = `inline-flex h-8 w-8 items-center justify-center rounded-takt border border-[var(--line)] bg-[var(--bg-2)] ${ring}`

  switch (kind) {
    case 'server':
      return (
        <span className={base} title={titles[kind]} aria-label={titles[kind]}>
          <span className="h-3.5 w-3.5 bg-[var(--fg-2)]" />
        </span>
      )
    case 'plc':
      return (
        <span className={`${base} rounded-full`} title={titles[kind]} aria-label={titles[kind]}>
          <span className="h-2.5 w-2.5 rounded-full border-2 border-[var(--teal-1)]" />
        </span>
      )
    case 'gateway':
      return (
        <span className={base} title={titles[kind]} aria-label={titles[kind]}>
          <span className="h-3 w-3 rotate-45 border border-[var(--fg-2)]" />
        </span>
      )
    case 'workstation':
      return (
        <span className={base} title={titles[kind]} aria-label={titles[kind]}>
          <span className="h-0 w-0 border-x-[6px] border-x-transparent border-b-[10px] border-b-[var(--fg-2)]" />
        </span>
      )
    case 'external':
      return (
        <span className={`${base} rounded-full`} title={titles[kind]} aria-label={titles[kind]}>
          <span className="h-3 w-5 rounded-full border border-dashed border-[var(--fg-3)]" />
        </span>
      )
    default:
      return null
  }
}
