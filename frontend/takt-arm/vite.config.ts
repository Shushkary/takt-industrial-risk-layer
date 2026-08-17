import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  // Базовый путь публикации. По умолчанию корень домена; при выкладке на
  // подпуть задаётся переменной окружения, например:
  //   VITE_BASE=/takt_pt/ npm run build
  // Значение попадает в import.meta.env.BASE_URL, откуда его берёт basename
  // роутера в src/main.tsx — маршруты в коде остаются относительными.
  base: process.env.VITE_BASE ?? '/',
  root: './',
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['./src/test/setup.ts'],
  },
})
