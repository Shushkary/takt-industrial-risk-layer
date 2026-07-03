import { describe, expect, it } from 'vitest'
import { formatPercent, formatRisk } from './format'

describe('Russian numeric formatting', () => {
  it('formats risk values with Russian decimal separator and fixed precision', () => {
    expect(formatRisk(0.7)).toBe('0,700')
    expect(formatRisk(4.57)).toBe('4,570')
  })

  it('formats integer percentages with a localized number formatter', () => {
    expect(formatPercent(73.4)).toBe('73 %')
  })
})
