import type { Meta, StoryObj } from '@storybook/react'
import { RiskBadge } from './RiskBadge'

const meta = {
  title: 'UI/RiskBadge',
  component: RiskBadge,
} satisfies Meta<typeof RiskBadge>

export default meta
type Story = StoryObj<typeof meta>

export const Low: Story = { args: { value: 0.12 } }
export const Mid: Story = { args: { value: 0.55 } }
export const High: Story = { args: { value: 0.78 } }
export const Critical: Story = { args: { value: 0.93 } }
