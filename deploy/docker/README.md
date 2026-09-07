# Выкладка бэкенда на боевую ВМ

Порядок для контейнера `takt-api`, который обслуживает АРМ по адресу
`https://ralta.ru/takt_pt_arm/`. Числа портов и путей — фактические, проверены на стенде.

## Что делает эту выкладку необычной

**С ВМ нет выхода в интернет.** Недоступны ни Docker Hub, ни pypi, ни GitHub. Из этого следует
три ограничения, каждое из которых уже один раз ломало выкладку:

1. **Код приезжает git-бандлом, а не `git pull`.** Клон на ВМ — `~/takt-build`, ветка
   `deploy-main`.
2. **Полная сборка образа невозможна**: зависимости не установить. Обновляется только `src/`,
   `config/` и метаданные пакета — поверх уже собранного образа
   ([`Dockerfile.overlay`](Dockerfile.overlay)).
3. **Базовый образ обязан быть на месте.** Если тега, указанного в `ARG BASE`, на ВМ нет,
   docker идёт за ним в Docker Hub и падает по таймауту DNS — сообщение при этом говорит про
   `failed to resolve reference`, а не про отсутствующий локальный образ.

## Прогон

```bash
# 1. На машине разработчика: бандл от ревизии, из которой собран работающий образ.
git bundle create takt-<новая ревизия>.bundle <ревизия на ВМ>..main
scp -i ~/.ssh/id_rsa_spaceweb takt-<новая ревизия>.bundle torionadmin@89.111.142.231:~/

# 2. На ВМ: перемотать клон.
cd ~/takt-build
git fetch ~/takt-<новая ревизия>.bundle main:refs/remotes/bundle/<новая ревизия>
git merge --ff-only refs/remotes/bundle/<новая ревизия>

# 3. Собрать образ. `DOCKER_BUILDKIT=0` — buildkit пытается разрешать даже локальный базовый
#    образ через registry, которого отсюда нет.
REV=$(git rev-parse HEAD)
sudo env DOCKER_BUILDKIT=0 docker build \
  -f deploy/docker/Dockerfile.overlay \
  --build-arg TAKT_BUILD_REVISION=$REV \
  -t takt-risk-layer:$(git rev-parse --short HEAD) .

# 4. Пересоздать контейнер. Набор переменных полный: без TAKT_AUTH_REQUIRED=0 приложение не
#    поднимается вовсе — оно требует ключ, когда аутентификация включена.
sudo docker rm -f takt-api
sudo docker run -d --name takt-api --restart unless-stopped \
  -p 127.0.0.1:18093:8090 \
  -v takt_sqlite:/app/data \
  -e TAKT_STORAGE=sqlite \
  -e TAKT_SQLITE_PATH=data/takt_cases.db \
  -e TAKT_METRICS=1 \
  -e TAKT_RATE_LIMIT_PER_MIN=300 \
  -e TAKT_AUTH_REQUIRED=0 \
  -e TAKT_BUILD_REVISION=$REV \
  takt-risk-layer:$(git rev-parse --short HEAD)

# 5. Переставить плавающий тег базы и сохранить образ файлом (см. ниже, зачем).
sudo docker tag takt-risk-layer:$(git rev-parse --short HEAD) takt-risk-layer:base
sudo mkdir -p /opt/takt/backups/images
sudo sh -c "docker save takt-risk-layer:$(git rev-parse --short HEAD) | gzip -6 \
  > /opt/takt/backups/images/takt-risk-layer-$(git rev-parse --short HEAD).tar.gz"
```

## Проверка

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://ralta.ru/takt_pt_arm/health
curl -s https://ralta.ru/takt_pt_arm/health | grep -o '"build_revision":"[^"]*"'
```

`build_revision` обязан совпадать с `git rev-parse HEAD`.

## Перед остановкой контейнера — сверить версию схемы БД

```bash
grep CURRENT_DB_SCHEMA_VERSION src/takt/infrastructure/stores/sqlite_store.py
curl -s http://127.0.0.1:18093/health | grep -o '"sqlite_schema_version":[0-9]*'
```

Если в новом коде версия выше, откат станет невозможен без восстановления базы: приложение
поднимает схему при старте, а прежний образ отказывается работать с более новой схемой —
`SQLite schema_version 9 is newer than supported 8`. Так уже был получасовой простой.
Совпадают — откат безопасен.

## Откат

```bash
sudo docker rm -f takt-api
# и тот же `docker run` с прежним тегом образа
```

## Восстановление, если образов на ВМ не осталось

Образы с ВМ уже пропадали: `d816f4e`, `3bc35a5`, `3bc35a5-rev` и `latest` были удалены вручную
(автоматической чистки на машине нет, а диск занят на 78 %). Собрать их заново нельзя — pypi
недоступен. Поэтому после каждой выкладки образ сохраняется файлом:

```bash
sudo sh -c "gunzip -c /opt/takt/backups/images/takt-risk-layer-<ревизия>.tar.gz | docker load"
sudo docker tag takt-risk-layer:<ревизия> takt-risk-layer:base
```

Если пропадут и образы, и файлы — бэкенд восстанавливается только полной сборкой на машине с
интернетом и переносом образа файлом.

## Чего не делать

- Не трогать другие сайты и контейнеры на этой ВМ: `torion.su`, `torion-shop`, `zdorov-life`,
  `takt-pt-v4-*` на портах 18092 и 13000.
- Не удалять том `takt_sqlite`: в нём дела, события и журнал безопасности.
- Не запускать `docker image prune -a`: он снесёт базовый образ, а собрать его на ВМ нечем.
