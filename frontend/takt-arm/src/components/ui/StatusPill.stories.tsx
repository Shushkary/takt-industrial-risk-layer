import type { Meta, StoryObj } from '@storybook/react'
import { StatusPill } from './StatusPill'

const meta = {
  title: 'Интерфейс/Метка статуса',
  component: StatusPill,
} satisfies Meta<typeof StatusPill>

export default meta
type Story = StoryObj<typeof meta>

export const Нейтрально: Story = { args: { children: 'Штатный', tone: 'neutral' } }
export const Подтверждено: Story = { args: { children: 'Изоляция', tone: 'teal' } }
export const Внимание: Story = { args: { children: 'Деградация', tone: 'amber' } }
export const Риск: Story = { args: { children: 'Пик нагрузки', tone: 'risk' } }
