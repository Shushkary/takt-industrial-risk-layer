#!/usr/bin/env bash
# Выкладка витрины АРМ аналитика SOC на ВМ SpaceWeb в каталог ralta.ru/PT.
#
# Запускается с машины оператора, у которой есть SSH-ключ к ВМ
# (см. docs/ops/vm_spaceweb_access.md). Скрипт не хранит секретов:
# адрес, пользователь и ключ берутся из переменных окружения.
#
#   PT_SSH_KEY=~/.ssh/id_rsa_spaceweb ./deploy/pt-demo/deploy.sh
#
# Переменные:
#   PT_HOST      — хост ВМ (по умолчанию 89.111.142.231)
#   PT_USER      — пользователь SSH (по умолчанию torionadmin)
#   PT_SSH_KEY   — путь к приватному ключу (обязательно)
#   PT_TARGET    — каталог статики на ВМ (по умолчанию /var/www/ralta/PT)
#   PT_API_URL   — базовый URL backend для витрины; если пусто, витрина
#                  работает на встроенном демонстрационном наборе

set -euo pipefail

HOST="${PT_HOST:-89.111.142.231}"
USER_NAME="${PT_USER:-torionadmin}"
TARGET="${PT_TARGET:-/var/www/ralta/PT}"
API_URL="${PT_API_URL:-}"
KEY="${PT_SSH_KEY:-}"

if [ -z "$KEY" ]; then
  echo "error: задайте PT_SSH_KEY — путь к приватному ключу SSH" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP_DIR="$REPO_ROOT/frontend/takt-arm"

echo "==> сборка витрины для подкаталога /PT"
cd "$APP_DIR"
npm ci --no-audit --no-fund
VITE_BASE_PATH=/PT/ VITE_TAKT_API_BASE_URL="$API_URL" npm run build

if [ ! -f "$APP_DIR/dist/index.html" ]; then
  echo "error: сборка не создала dist/index.html" >&2
  exit 1
fi

echo "==> выкладка на ${USER_NAME}@${HOST}:${TARGET}"
ssh -i "$KEY" -o StrictHostKeyChecking=accept-new "${USER_NAME}@${HOST}" \
  "sudo mkdir -p '${TARGET}' && sudo chown -R ${USER_NAME}:${USER_NAME} '$(dirname "${TARGET}")'"

# --delete убирает ассеты прошлых сборок: имена файлов содержат хеш и накапливались бы.
rsync -az --delete -e "ssh -i ${KEY} -o StrictHostKeyChecking=accept-new" \
  "$APP_DIR/dist/" "${USER_NAME}@${HOST}:${TARGET}/"

echo "==> проверка конфигурации nginx и перезагрузка"
ssh -i "$KEY" "${USER_NAME}@${HOST}" "sudo nginx -t && sudo systemctl reload nginx"

echo "==> smoke-проверка"
ssh -i "$KEY" "${USER_NAME}@${HOST}" \
  "curl -sS -o /dev/null -w 'index=%{http_code}\n' http://127.0.0.1/PT/"

echo "готово: https://ralta.ru/PT/"
