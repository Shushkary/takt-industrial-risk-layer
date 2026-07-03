import type { Meta, StoryObj } from '@storybook/react'
import { RiskBadge } from './RiskBadge'

const meta: Meta = {
  title: 'Дизайн-система/Цвета риска',
  parameters: {
    docs: {
      description: {
        component: 'Примеры индекса риска из чек-листа: 0,0 / 0,4 / 0,7 / 0,9 / 0,95',
      },
    },
  },
}

export default meta

type Story = StoryObj<typeof meta>

export const Шкала: Story = {
  render: () => (
    <div className="flex flex-col gap-6">
      <RiskBadge value={0.0} />
      <RiskBadge value={0.4} />
      <RiskBadge value={0.7} />
      <RiskBadge value={0.9} />
      <RiskBadge value={0.95} />
    </div>
  ),
}
