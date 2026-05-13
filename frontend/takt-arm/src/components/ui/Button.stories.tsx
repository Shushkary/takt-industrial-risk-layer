import type { Meta, StoryObj } from '@storybook/react'
import { Button } from './Button'

const meta = {
  title: 'UI/Button',
  component: Button,
  argTypes: {
    variant: { control: 'select', options: ['primary', 'ghost', 'danger'] },
  },
} satisfies Meta<typeof Button>

export default meta
type Story = StoryObj<typeof meta>

export const Primary: Story = {
  args: { children: 'Подтвердить', variant: 'primary' },
}

export const Ghost: Story = {
  args: { children: 'Отмена', variant: 'ghost' },
}

export const Danger: Story = {
  args: { children: 'Экспорт PDF', variant: 'danger' },
}

export const Disabled: Story = {
  args: { children: 'Недоступно', variant: 'primary', disabled: true },
}
