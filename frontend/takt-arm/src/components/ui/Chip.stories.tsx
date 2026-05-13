import type { Meta, StoryObj } from '@storybook/react'
import { Chip } from './Chip'

const meta = {
  title: 'UI/Chip',
  component: Chip,
} satisfies Meta<typeof Chip>

export default meta
type Story = StoryObj<typeof meta>

export const Inactive: Story = {
  args: { children: 'TRIAGE', active: false },
}

export const Active: Story = {
  args: { children: 'CONFIRMED', active: true },
}
