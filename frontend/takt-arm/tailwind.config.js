/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      borderRadius: {
        takt: '4px',
      },
      transitionDuration: {
        takt: '150ms',
        'takt-slow': '240ms',
      },
      transitionTimingFunction: {
        takt: 'cubic-bezier(0.2, 0, 0, 1)',
      },
      fontFamily: {
        sans: ['"Inter Variable"', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
}
