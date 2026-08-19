# Multi-stage build для TAKT АРМ frontend

# Stage 1: Builder
FROM node:20-alpine AS builder

WORKDIR /app

# Копирование package.json и package-lock.json
COPY package*.json ./

# Установка зависимостей
RUN npm ci

# Копирование исходного кода
COPY . .

# База API задаётся на этапе сборки (Vite «запекает» env в бандл).
# Локально по умолчанию — прямые запросы на http://localhost:8090 (CORS открыт на стенде).
# Для единого origin через nginx-прокси передайте пустую строку или относительный путь.
ARG VITE_TAKT_API_BASE_URL=http://localhost:8090
ENV VITE_TAKT_API_BASE_URL=${VITE_TAKT_API_BASE_URL}
ARG VITE_TAKT_APP_BASE=/
ENV VITE_TAKT_APP_BASE=${VITE_TAKT_APP_BASE}

# Сборка production build
RUN npm run build

# Stage 2: Production
FROM nginx:alpine

# Копирование собранного приложения
COPY --from=builder /app/dist /usr/share/nginx/html

# Копирование конфигурации nginx
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose порт 80
EXPOSE 80

# Запуск nginx
CMD ["nginx", "-g", "daemon off;"]
