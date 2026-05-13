export function InvariantLibrary() {
  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-[20px] font-semibold text-[var(--fg-1)]">Библиотека инвариантов</h1>
      <p className="max-w-[72ch] text-[13px] text-[var(--fg-2)]">
        Заглушка экрана 4: 26 инвариантов в 6 блоках + read-only просмотр `config/risk_weights.yaml` с подсветкой
        синтаксиса — следующий этап (данные из `/invariants` и статический YAML).
      </p>
    </div>
  )
}
