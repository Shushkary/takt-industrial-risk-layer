# Витрина АРМ аналитика SOC на ralta.ru/PT

Публикация фронтенда `frontend/takt-arm` в подкаталоге домена: <https://ralta.ru/PT/>.

## Состав

| Файл | Назначение |
|---|---|
| `deploy.sh` | сборка под `/PT` и выкладка на ВМ по SSH + перезагрузка nginx |
| `nginx-pt.conf` | snippet для server-блока `ralta.ru`: SPA-fallback, заголовки безопасности, кэш |

## Выкладка

Скрипт запускается **с машины оператора**, у которой есть приватный ключ к ВМ
(`docs/ops/vm_spaceweb_access.md`). Секретов в репозитории нет, всё через переменные:

```bash
PT_SSH_KEY=~/.ssh/id_rsa_spaceweb ./deploy/pt-demo/deploy.sh
```

С подключением к живому backend:

```bash
PT_SSH_KEY=~/.ssh/id_rsa_spaceweb PT_API_URL=https://ralta.ru/PT-api ./deploy/pt-demo/deploy.sh
```

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `PT_HOST` | `89.111.142.231` | хост ВМ |
| `PT_USER` | `torionadmin` | пользователь SSH |
| `PT_SSH_KEY` | — (обязательна) | путь к приватному ключу |
| `PT_TARGET` | `/var/www/ralta/PT` | каталог статики на ВМ |
| `PT_API_URL` | пусто | базовый URL API; пусто — витрина на встроенном демонстрационном наборе |

## Разовая настройка nginx на ВМ

```bash
sudo mkdir -p /var/www/ralta/PT
sudo cp nginx-pt.conf /etc/nginx/snippets/takt-pt.conf
# в server-блок ralta.ru добавить:  include /etc/nginx/snippets/takt-pt.conf;
sudo nginx -t && sudo systemctl reload nginx
```

## Два режима витрины

Сборка читает `VITE_TAKT_API_BASE_URL` на этапе `npm run build`:

* **переменная пуста** — витрина работает на встроенном демонстрационном наборе
  (`src/investigation/demoInvestigation.ts`), повторяющем цепочку стенда: заражение АРМ
  инженера, обращение к C2, выход в технологический контур. Режим помечен в интерфейсе
  плашкой «демонстрационный набор», чтобы данные не приняли за живые;
* **переменная задана** — экран работает на живом API: очередь инцидентов, рабочий стол
  кейса, карточки сущностей, находки, решение аналитика.

При подключении живого API его нужно опубликовать по HTTPS с того же домена либо
разрешить CORS-источник витрины (`TAKT_CORS_ORIGINS`), иначе браузер заблокирует запросы.
API поднимается по `deploy/stand/docker-compose.stand.yml`; открывать его наружу без
`TAKT_API_KEY` и `TAKT_AUTH_REQUIRED=1` нельзя.

## Проверка после выкладки

```bash
curl -sSI https://ralta.ru/PT/ | head -1                 # 200
curl -sS https://ralta.ru/PT/ | grep -o '/PT/assets[^"]*' # пути ассетов с префиксом /PT
```

В браузере: <https://ralta.ru/PT/> — открывается «Рабочий стол расследования»,
граф связей собирается анимацией, таймлайн проигрывает хронологию.

## Откат

Выкладка — это статика в каталоге. Откат = повторный запуск `deploy.sh` из нужного
коммита. Резервная копия предыдущей версии перед перезаписью:

```bash
ssh -i ~/.ssh/id_rsa_spaceweb torionadmin@89.111.142.231 \
  'sudo cp -a /var/www/ralta/PT /var/www/ralta/PT.bak-$(date +%F-%H%M)'
```
