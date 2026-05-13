import type { Meta, StoryObj } from '@storybook/react'
import { MetricTile } from './MetricTile'

const meta = {
  title: 'UI/MetricTile',
  component: MetricTile,
} satisfies Meta<typeof MetricTile>

export default meta
type Story = StoryObj<typeof meta>

export const Default: Story = {
  args: { label: 'Событий / мин', value: '9 842', hint: 'Пик за последние 15 минут' },
}
