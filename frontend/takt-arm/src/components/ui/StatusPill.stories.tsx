import type { Meta, StoryObj } from '@storybook/react'
import { StatusPill } from './StatusPill'

const meta = {
  title: 'UI/StatusPill',
  component: StatusPill,
} satisfies Meta<typeof StatusPill>

export default meta
type Story = StoryObj<typeof meta>

export const Neutral: Story = { args: { children: 'NORMAL', tone: 'neutral' } }
export const Teal: Story = { args: { children: 'AIR-GAP', tone: 'teal' } }
export const Amber: Story = { args: { children: 'DEGRADED', tone: 'amber' } }
export const Risk: Story = { args: { children: 'STORM', tone: 'risk' } }
