import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const appBase = process.env.VITE_TAKT_APP_BASE || '/';

// https://vitejs.dev/config/
export default defineConfig({
  base: appBase.endsWith('/') ? appBase : `${appBase}/`,
  plugins: [react()],
  server: {
    port: 3000,
    host: true,
    allowedHosts: true, // Для preview URL
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
});
