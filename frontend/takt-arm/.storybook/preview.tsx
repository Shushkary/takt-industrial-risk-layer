import type { Preview } from '@storybook/react'
import type { ReactElement } from 'react'
import '../src/index.css'

const preview: Preview = {
  parameters: {
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
    backgrounds: {
      default: 'takt',
      values: [{ name: 'takt', value: '#0b0f14' }],
    },
    layout: 'padded',
  },
  decorators: [
    (Story): ReactElement => (
      <div className="min-h-[160px] bg-[var(--bg-0)] p-4 text-[var(--fg-1)]">
        <Story />
      </div>
    ),
  ],
}

export default preview
