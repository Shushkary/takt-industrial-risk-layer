import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './App.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {/* Базовый путь публикации берётся из vite.config.ts (base). Маршруты в
        коде остаются относительными, поэтому перенос приложения на подпуть
        (например, /takt_pt/) меняет только конфигурацию сборки. */}
    <BrowserRouter basename={import.meta.env.BASE_URL}>
      <App />
    </BrowserRouter>
  </StrictMode>,
)
