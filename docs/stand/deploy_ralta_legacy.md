# Промпт для агента с доступом к ВМ — развёртывание стенда TAKT на ralta.ru/TAKT_PT

> **Исторический документ.** Порядок выкладки на текущее состояние —
> [`deploy_ralta_current.md`](deploy_ralta_current.md).


> Скопируйте текст ниже целиком и передайте агенту, у которого есть SSH-доступ к ВМ SpaceWeb
> (ключ `~/.ssh/id_rsa_spaceweb`, пользователь `torionadmin`, IP `89.111.142.231`).
> Я (агент сборки) не имею этого ключа и 2FA-телефона, поэтому развернуть на ВМ не могу —
> весь код готов, собран и протестирован локально, осталось только выложить его на ВМ.

---

## ЗАДАЧА

Развернуть демо-стенд **TAKT Industrial Risk Layer** (синтетические данные + фронтенд АРМ
SOC-оператора) на ВМ SpaceWeb и опубликовать по адресу **https://ralta.ru/TAKT_PT**.

Стенд показывает ключевую метрику проекта — **время обработки данных оператором** — в двух
режимах: полностью ручном и в режиме ТАКТ (экран `/compare`).

## ДОСТУП К ВМ

```bash
ssh -i ~/.ssh/id_rsa_spaceweb torionadmin@89.111.142.231
# root отключён, только ключ; sudo доступен.
# Если "REMOTE HOST IDENTIFICATION HAS CHANGED": ssh-keygen -R 89.111.142.231
# Если "Connection refused" (не timeout) — sshd не запущен → reboot из панели
#   https://mcp.sweb.ru/main/auth/ (логин grflmailru, 2FA по SMS) → «Перезагрузить».
```

## ИСТОЧНИК КОДА

Репозиторий: `https://github.com/Shushkary/takt-industrial-risk-layer`
Ветка со стендом и фронтендом: **`feature/frontend-arm`** (PR #4).
Каталог стенда: `stand/`, фронтенд: `frontend/`, compose: `docker-compose.stand.yml`.

## ШАГИ РАЗВЁРТЫВАНИЯ

1. **Подключиться и подготовить окружение**
   ```bash
   ssh -i ~/.ssh/id_rsa_spaceweb torionadmin@89.111.142.231
   sudo apt-get update
   # Docker + compose plugin, если не установлены:
   command -v docker || curl -fsSL https://get.docker.com | sudo sh
   sudo usermod -aG docker torionadmin   # затем перелогиниться
   docker compose version || sudo apt-get install -y docker-compose-plugin
   ```

2. **Забрать код**
   ```bash
   sudo mkdir -p /opt/takt && sudo chown torionadmin:torionadmin /opt/takt
   cd /opt/takt
   git clone --branch feature/frontend-arm --depth 1 \
     https://github.com/Shushkary/takt-industrial-risk-layer.git app || \
     (cd app && git fetch origin feature/frontend-arm && git checkout feature/frontend-arm && git pull)
   cd app
   ```

3. **Собрать фронтенд под нужный публичный адрес API.**
   Фронтенд обращается к API стенда. Так как публикуем под путём `/TAKT_PT`, самый надёжный
   вариант — единый origin: фронтенд ходит на относительный `/TAKT_PT/api/...`, а внешний
   nginx (см. шаг 5) проксирует и статику, и API.
   Соберите фронтенд с базой API, указывающей на публичный API-путь:
   ```bash
   VITE_TAKT_API_BASE_URL="https://ralta.ru/TAKT_PT" \
     docker compose -f docker-compose.stand.yml build
   ```
   > Если проще опубликовать API на отдельном поддомене/порту — задайте в
   > `VITE_TAKT_API_BASE_URL` его публичный адрес (напр. `https://api.ralta.ru`) и
   > откройте на нём CORS (в `stand/server.py` CORS уже открыт на `*`).

4. **Запустить связку** (frontend → :3000, синтетический API → :8090)
   ```bash
   docker compose -f docker-compose.stand.yml up -d --build
   docker compose -f docker-compose.stand.yml ps
   curl -s http://127.0.0.1:8090/health           # {"status":"ok",...}
   curl -s http://127.0.0.1:3000/ | head -c 200    # HTML фронтенда
   ```

5. **Опубликовать по https://ralta.ru/TAKT_PT** через системный nginx.
   Добавьте в конфиг сайта `ralta.ru` (обычно `/etc/nginx/sites-available/ralta.ru`):
   ```nginx
   # Статика/SPA фронтенда АРМ под префиксом /TAKT_PT
   location /TAKT_PT/ {
       proxy_pass http://127.0.0.1:3000/;
       proxy_set_header Host $host;
       proxy_set_header X-Forwarded-Proto $scheme;
   }
   # API стенда (SSE!) — тот же префикс, ветка /api
   location /TAKT_PT/api/ {
       proxy_pass http://127.0.0.1:8090/api/;
       proxy_http_version 1.1;
       proxy_set_header Connection '';
       proxy_buffering off;          # обязательно для SSE (/api/v1/stream/cases)
       proxy_read_timeout 86400s;
       proxy_set_header Host $host;
   }
   ```
   ```bash
   sudo nginx -t && sudo systemctl reload nginx
   ```
   > Внимание к SPA-роутингу: фронтенд собран как SPA (react-router). Внутренние переходы
   > работают, но при прямом заходе на `https://ralta.ru/TAKT_PT/compare` nginx должен
   > отдавать `index.html`. Внутренний nginx фронтенда (`frontend/nginx.conf`) уже делает
   > `try_files ... /index.html`, поэтому проксирование на `:3000` это покрывает.

6. **Проверить публично**
   - Открыть `https://ralta.ru/TAKT_PT/` — очередь инцидентов АРМ.
   - Открыть `https://ralta.ru/TAKT_PT/compare` — экран сравнения; убедиться, что верхние
     карточки метрики заполнены (≈ 29 мин 45 с vs 2 мин 55 с, ×10.2), слева грузится сырой
     поток событий, справа — коррелированный кейс, оба секундомера стартуют.
   - В DevTools → Network проверить, что запросы к `/api/v1/...` возвращают 200 и
     `stream/cases` держит соединение (SSE).

## КРИТЕРИЙ ГОТОВНОСТИ
`https://ralta.ru/TAKT_PT/compare` открывается публично, метрика и оба режима работают,
данные подтягиваются с API стенда. Если что-то из шага 3/5 (адрес API, CORS, префикс) не
сходится — поправить `VITE_TAKT_API_BASE_URL` при сборке фронтенда и перезапустить compose.

## ОТКАТ
```bash
cd /opt/takt/app && docker compose -f docker-compose.stand.yml down
# и убрать блок location /TAKT_PT/ из конфига nginx, sudo systemctl reload nginx
```
