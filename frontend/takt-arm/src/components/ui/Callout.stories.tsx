import type { Meta, StoryObj } from '@storybook/react'
import { Callout } from './Callout'

const meta = {
  title: 'Интерфейс/Сообщение',
  component: Callout,
} satisfies Meta<typeof Callout>

export default meta
type Story = StoryObj<typeof meta>

export const Информация: Story = {
  args: { title: 'Информация', tone: 'info', children: 'Контур изолирован; внешние вызовы из интерфейса запрещены политикой.' },
}

export const Внимание: Story = {
  args: { title: 'Внимание', tone: 'warning', children: 'Часть источников недоступна; режим деградации, пересчёт риска активен.' },
}

export const Критично: Story = {
  args: { title: 'Критично', tone: 'danger', children: 'Порог КЗИ превышен; требуется классификация оператором.' },
}
