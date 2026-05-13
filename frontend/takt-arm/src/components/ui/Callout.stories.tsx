import type { Meta, StoryObj } from '@storybook/react'
import { Callout } from './Callout'

const meta = {
  title: 'UI/Callout',
  component: Callout,
} satisfies Meta<typeof Callout>

export default meta
type Story = StoryObj<typeof meta>

export const Info: Story = {
  args: { title: 'Информация', tone: 'info', children: 'Контур изолирован; внешние вызовы из UI запрещены политикой.' },
}

export const Warning: Story = {
  args: { title: 'Внимание', tone: 'warning', children: 'Часть источников недоступна — режим DEGRADED, пересчёт риска активен.' },
}

export const Danger: Story = {
  args: { title: 'Критично', tone: 'danger', children: 'Порог Кзи превышен; требуется классификация оператором.' },
}
