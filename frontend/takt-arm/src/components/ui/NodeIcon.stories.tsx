import type { Meta, StoryObj } from '@storybook/react'
import { NodeIcon } from './NodeIcon'

const meta = {
  title: 'UI/NodeIcon',
  component: NodeIcon,
} satisfies Meta<typeof NodeIcon>

export default meta
type Story = StoryObj<typeof meta>

export const Server: Story = { args: { kind: 'server' } }
export const Plc: Story = { args: { kind: 'plc', active: true } }
export const Gateway: Story = { args: { kind: 'gateway' } }
export const Workstation: Story = { args: { kind: 'workstation' } }
export const External: Story = { args: { kind: 'external' } }
