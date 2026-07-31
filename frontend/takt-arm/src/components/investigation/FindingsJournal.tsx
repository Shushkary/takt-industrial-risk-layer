import { useState } from 'react'
import { NotebookPen } from 'lucide-react'
import type { InvestigationFinding } from '../../investigation/types'

/**
 * Журнал находок (ТЗ п. 5.6, п. 4.5): вывод аналитика фиксируется прямо в карточке
 * инцидента вместе с выбранными событиями — вместо записей «в блокноте».
 */

type Props = {
  findings: InvestigationFinding[]
  selectedEventIds: string[]
  onAdd: (text: string, eventIds: string[]) => Promise<void>
  /** Демонстрационный режим: находка живёт только в текущей сессии браузера. */
  localOnly: boolean
}

export function FindingsJournal({ findings, selectedEventIds, onAdd, localOnly }: Props) {
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async () => {
    const value = text.trim()
    if (!value) {
      return
    }
    setBusy(true)
    setError(null)
    try {
      await onAdd(value, selectedEventIds)
      setText('')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Не удалось сохранить находку')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <ul className="flex flex-col gap-1.5">
        {findings.map((finding) => (
          <li
            key={finding.finding_id}
            className="investigation-fade rounded-takt border border-[var(--line)] bg-[var(--bg-2)] px-2.5 py-2 text-[12px]"
          >
            <div className="text-[var(--fg-1)]">{finding.text}</div>
            <div className="mt-1 font-mono text-[10px] text-[var(--fg-3)]">{finding.author || 'analyst'}</div>
          </li>
        ))}
        {findings.length === 0 ? (
          <li className="rounded-takt border border-dashed border-[var(--line)] px-2.5 py-3 text-[12px] text-[var(--fg-3)]">
            Находок пока нет. Выберите события на таймлайне и зафиксируйте вывод — он останется в карточке инцидента.
          </li>
        ) : null}
      </ul>

      <div className="flex flex-col gap-1.5">
        <label className="text-[11px] uppercase tracking-[0.06em] text-[var(--fg-3)]" htmlFor="finding-text">
          Новая находка
        </label>
        <textarea
          id="finding-text"
          value={text}
          onChange={(event) => setText(event.target.value)}
          rows={3}
          disabled={busy}
          placeholder="Что установлено и на основании каких событий"
          className="takt-focus-ring w-full resize-y rounded-takt border border-[var(--line)] bg-[var(--bg-2)] px-2 py-1.5 text-[12px] text-[var(--fg-1)] placeholder:text-[var(--fg-3)] disabled:opacity-50"
        />
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] text-[var(--fg-3)]">
            Привязано событий: <span className="font-mono text-[var(--fg-2)]">{selectedEventIds.length}</span>
          </span>
          <button
            type="button"
            onClick={submit}
            disabled={busy || text.trim().length === 0}
            className="takt-focus-ring flex items-center gap-1.5 rounded-takt border border-[var(--teal-2)] bg-[var(--teal-3)] px-2.5 py-1.5 text-[12px] text-[var(--fg-1)] transition-colors duration-takt hover:bg-[var(--teal-2)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            <NotebookPen size={13} />
            {busy ? 'Сохранение…' : 'Зафиксировать'}
          </button>
        </div>
        {localOnly ? (
          <div className="text-[11px] text-[var(--fg-3)]">
            Демонстрационный режим: находка сохраняется только в текущей сессии браузера.
          </div>
        ) : null}
        {error ? <div className="text-[11px] text-[var(--risk-high)]">{error}</div> : null}
      </div>
    </div>
  )
}
