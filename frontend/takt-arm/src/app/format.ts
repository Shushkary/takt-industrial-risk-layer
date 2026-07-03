const riskFormatter = new Intl.NumberFormat('ru-RU', {
  maximumFractionDigits: 3,
  minimumFractionDigits: 3,
})

const percentFormatter = new Intl.NumberFormat('ru-RU', {
  maximumFractionDigits: 0,
  minimumFractionDigits: 0,
})

export function formatRisk(value: number): string {
  return riskFormatter.format(value)
}

export function formatPercent(value: number): string {
  return `${percentFormatter.format(value)} %`
}
