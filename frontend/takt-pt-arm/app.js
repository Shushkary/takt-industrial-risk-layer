// Рабочее место аналитика: очередь кейсов и окно расследования одного инцидента.
//
// Работает поверх REST этого репозитория: GET /cases, GET /cases/{id}/workspace,
// GET /entities/{type}/{id}/card, POST /cases/{id}/findings. Отдельного демо-контура нет —
// раньше интерфейс обращался к /api/v1/*, которого в продукте не существует, и на стенде
// каждый запрос отдавал 404.
//
// Базовый адрес API берётся из того же origin, что и страница: раздача статики и прокси
// к backend настроены в nginx.takt-pt-arm.conf. Для локального прогона адрес можно задать
// через window.TAKT_API_BASE до загрузки этого файла.

const API_BASE = String(window.TAKT_API_BASE || `${location.pathname.replace(/\/[^/]*$/, '')}/api`).replace(/\/+$/, '');
const POLL_MS = 15000;

// Пояснения к блокам и значениям. Ключ совпадает с data-help в разметке.
// Каждая запись отвечает на три вопроса: что это, откуда берётся, что с этим делать.
const HELP = {
  // --- Вкладка «Симуляция» ---------------------------------------------
  simulation: {
    title: 'Вкладка «Симуляция»',
    body: [
      'Хронология цепочки атаки по этому кейсу: шаги в порядке времени, фаза каждого шага и то, каким механизмом ТАКТ его выделил.',
      'В хронологию попадают только события с разметкой фазы. Разметка приходит от источника или от датасета, ТАКТ её не вычисляет: события без фазы остаются в кейсе, но шагом цепочки не считаются, и их число показано отдельно.',
      'Что делать: пройти цепочку по шагам и проверить, каждый ли шаг объясняется тем основанием, которое назвал продукт.',
    ],
  },
  seconds_per_action: {
    title: 'Секунд на одно действие',
    body: [
      'Коэффициент, которым число действий переводится во время. Это объявленное допущение, а не измеренная величина: в методике измерения такого коэффициента нет и никто его не замерял.',
      'Значение по умолчанию выбрано для наглядности и меняется здесь же. Любая цифра времени в интерфейсе пересчитывается от него.',
      'Что делать: подставлять значение, полученное наблюдением за своим процессом. До этого относиться к времени как к иллюстрации, а не как к результату замера.',
    ],
  },
  counter_time: {
    title: 'Счётчики времени',
    body: [
      'Слева время разбора в ТАКТ, справа — расчётное время ручного разбора. Обе величины модельные: число действий умножено на коэффициент.',
      'Отдельного сокращения времени здесь нет намеренно. Модельное время пропорционально действиям, поэтому его сокращение совпало бы с сокращением действий и выглядело бы вторым независимым доказательством, которым не является.',
      'Что делать: сравнивать порядок величин. Настоящее время разбора даёт только парный прогон с наблюдателем — docs/pt_techlab/baseline_methodology.md.',
    ],
  },
  counters: {
    title: 'Трудоёмкость разбора',
    body: [
      'Два счётчика: сколько действий потребовал бы ручной разбор того же инцидента и сколько их записано в ТАКТ.',
      'Числа растут по мере проигрывания, итог совпадает с ответом /simulation.',
      'Что делать: смотреть на разницу как на порядок величины, а не как на точный замер — откуда берётся каждое число, показывает «Методика расчёта».',
    ],
  },
  counter_manual: {
    title: 'Счётчик «Аналитик вручную»',
    body: [
      'Расчёт по модели: открыть консоль каждого источника, найти каждую отличительную сущность в каждой системе, перенести идентификаторы между системами, занести относящиеся события в заметку, свести итог.',
      'Это оценка с явными коэффициентами, а не наблюдение за живым аналитиком.',
      'Что делать: если процесс в вашей организации устроен иначе — коэффициенты меняются, и расчёт нужно повторить.',
    ],
  },
  counter_takt: {
    title: 'Счётчик «Аналитик в ТАКТ»',
    body: [
      'Замер по append-only журналу кейса: считаются записи с меткой актора, то есть действия человека. Автоматические операции конвейера не считаются.',
      'В журнал попадают действия, меняющие состояние кейса. Навигация — открыть кейс, открыть карточку сущности — состояние не меняет и не записывается.',
      'Что делать: считать это число нижней границей, а сокращение — верхней.',
    ],
  },
  reduction: {
    title: 'Сокращение действий',
    body: [
      'Разница между расчётом ручного процесса и замером в ТАКТ, в процентах от ручного.',
      'Целевой ориентир ТЗ — не менее 30%.',
      'Что делать: подтверждать парным прогоном с наблюдателем; до него это оценка.',
    ],
  },
  effort_method: {
    title: 'Методика расчёта счётчиков',
    body: [
      'Сторона ТАКТ — замер. Источник: append-only журнал кейса с цепочкой хэшей. Ручным считается действие с меткой actor= : её несут только записи человека.',
      'Сторона ручного процесса — расчёт. Модель: (число источников) + (сущности × источники) + (сущности × (источники − 1)) + (события) + 1. Коэффициенты явные и заменяются наблюдением.',
      'Сокращение = (ручные − ТАКТ) / ручные × 100%.',
      'Время — модельная оценка. Коэффициент «секунд на действие» в методике не задан и никем не измерялся, поэтому по умолчанию время не показывается вовсе; при заданном коэффициенте оно помечается как модельное.',
      'Границы: журнал не отражает навигационные клики, поэтому число действий в ТАКТ занижено; в модели преобладает шаг «фиксация событий в заметке». Расчёт не заменяет парный прогон с наблюдателем — docs/pt_techlab/baseline_methodology.md.',
    ],
  },
  player: {
    title: 'Плеер цепочки',
    body: [
      'Пошаговое или автоматическое проигрывание событий в порядке времени. Цвет шага — фаза цепочки атаки.',
      'При проигрывании подсвечивается путь на графе и растут счётчики трудоёмкости.',
      'Что делать: остановиться на шаге и открыть его — в окне шага видно, что произошло и почему ТАКТ это выделил.',
    ],
  },
  attack_graph: {
    title: 'Граф атаки',
    body: [
      'Сущности цепочки и переходы между ними: учётная запись, узел, адрес, объект конвейера. Цвет узла — фаза, в которой он впервые появился.',
      'Граф строится только по событиям цепочки этого кейса, связи вне кейса в нём не видны.',
      'Что делать: смотреть на переходы между узлами и смену учётной записи — по ним читается перемещение внутри сети.',
    ],
  },
  sim_summary: {
    title: 'Итог разбора',
    body: [
      'Класс риска, сработавшие инварианты и применимые варианты реагирования по отличительным сущностям инцидента.',
      'Варианты реагирования — рекомендации. ТАКТ их не выполняет и команд не отправляет, исполняет внешняя система после подтверждения аналитика.',
    ],
  },
  step: {
    title: 'Шаг цепочки',
    body: [
      'Одно событие инцидента: что зафиксировал источник, к какой фазе атаки оно относится и какая техника ATT&CK ему сопоставлена.',
      'Отдельно показано, чем ТАКТ выделил это событие: пивотом по отличительной сущности, расширением до уровня узла или срабатыванием инварианта.',
      'Что делать: проверить основание. Событие, добранное расширением, требует отсева аналитиком — оно попало в кейс по узлу, а не по признаку атаки.',
    ],
  },
  mitre: {
    title: 'Техника MITRE ATT&CK',
    body: [
      'Идентификатор техники из матрицы ATT&CK, сопоставленный событию разметкой источника.',
      'ТАКТ технику не определяет: значение приходит с данными.',
      'Что делать: использовать как общий язык при передаче инцидента и при сверке покрытия детектирования.',
    ],
  },
  queue: {
    title: 'Очередь инцидентов',
    body: [
      'Кейсы из хранилища ТАКТ, от большего балла риска к меньшему. Кейс — группа событий, отнесённых к одному разбору.',
      'Часть кейсов создаёт конвейер приёма по совпадению признаков, часть собирает аналитик пивотом по отличительным сущностям.',
      'Что делать: открыть кейс с наибольшим баллом, проверить состав событий и решить, инцидент это или штатная активность.',
    ],
  },
  summary: {
    title: 'Сводка инцидента',
    body: [
      'Идентификатор, статус, заголовок и оценка риска кейса.',
      'Заголовок задаётся при сборке и не является выводом системы.',
      'Что делать: сверить заголовок с фактическим составом событий. Расхождение — повод переименовать кейс, а не доверять заголовку.',
    ],
  },
  sources: {
    title: 'Состав по источникам',
    body: [
      'Сколько событий кейса пришло от каждого класса источников: edr — агент на узле, siem — правило корреляции, network_events — сетевой поток Netflow, ot — телеметрия и конвейер сборки.',
      'Что делать: инцидент, видимый из нескольких источников, надёжнее того же инцидента из одного. Если источник отсутствует — сначала проверить, подключён ли он, и только потом считать это признаком.',
    ],
  },
  invariants: {
    title: 'Сработавшие инварианты',
    body: [
      'Правила ТАКТ, сработавшие на событиях кейса. Инвариант — признак отклонения, а не вердикт.',
      'Часть инвариантов поднимается по вердикту вышестоящего средства обнаружения, часть вычисляется самим ТАКТ.',
      'Что делать: для каждого инварианта найти в цепочке событие, на котором он сработал, и проверить, объясняется ли оно штатной работой.',
    ],
  },
  chain: {
    title: 'Цепочка событий',
    body: [
      'Все события кейса по времени, от раннего к позднему, время в UTC. Основной рабочий список: по нему восстанавливается ход инцидента.',
      'Что делать: идти сверху вниз и на каждом шаге отвечать, чем событие вызвано. Клик по узлу, учётной записи или адресу открывает карточку сущности.',
    ],
  },
  graph: {
    title: 'Связи сущностей',
    body: [
      'Связи между узлами, учётными записями, процессами и адресами кейса: запуск процесса, порождение дочернего процесса, сетевое обращение.',
      'Строится только по событиям кейса, поэтому связи вне кейса здесь не видны.',
      'Что делать: искать переходы между узлами и смену учётной записи — по ним видно перемещение внутри сети.',
    ],
  },
  entity: {
    title: 'Карточка сущности',
    body: [
      'История и окружение выбранной сущности по всем принятым событиям, а не только по событиям кейса.',
      'Что делать: проверить, впервые ли сущность ведёт себя так. Если такая активность для неё обычна, событие в кейсе скорее фон.',
    ],
  },
  findings: {
    title: 'Находки',
    body: [
      'Сущности, которые аналитик отметил как относящиеся к инциденту. Запись попадает в журнал кейса.',
      'Находка — решение человека, система её не проставляет.',
      'Что делать: фиксировать сущность сразу после подтверждения её участия, чтобы не собирать идентификаторы заново при передаче смены.',
    ],
  },
  response: {
    title: 'Варианты реагирования',
    body: [
      'Действия, применимые к составу этого кейса: изоляция узла, сброс учётной записи, блокировка адреса, заморозка конвейера.',
      'ТАКТ их не выполняет и команд не отправляет. Это перечень для решения аналитика, исполняет его внешняя система после подтверждения.',
      'Что делать: выбрать применимые пункты и передать ответственному вместе с составом кейса.',
    ],
  },
  risk_class: {
    title: 'Класс риска',
    body: [
      'LOW, MEDIUM, HIGH или CRITICAL — балл риска, разложенный по порогам из конфигурации.',
      'Считается по признакам события или кейса и не учитывает ценность актива для организации.',
      'Что делать: использовать как порядок разбора, а не как приоритет реагирования. Приоритет определяет аналитик с учётом того, что стоит за активом.',
    ],
  },
  risk_score: {
    title: 'Балл риска',
    body: [
      'Число от 0 до 1: взвешенная сумма пяти векторов — ритмика, связи, контекст, пользователь, качество данных.',
      'Для собранного инцидента считается по объединению его срабатываний, но не ниже самого тяжёлого из вошедших кейсов.',
      'Что делать: сравнивать баллы между кейсами одного потока. Само по себе значение в ущерб не переводится.',
    ],
  },
  status: {
    title: 'Статус кейса',
    body: [
      'NEW — принят конвейером, никто не смотрел. TRIAGE — в разборе. CONFIRMED — подтверждён аналитиком. FALSE_POSITIVE — ложное срабатывание. EXPECTED_BEHAVIOR — объяснён штатной работой. MERGED — влит в другой кейс.',
      'Статус меняет человек; сборка инцидента ставит TRIAGE и вердикта не выносит.',
      'Что делать: не оставлять кейс в TRIAGE после завершения разбора — по статусу видно, что уже закрыто.',
    ],
  },
  time_utc: {
    title: 'Время события, UTC',
    body: [
      'Момент, когда событие произошло у источника.',
      'UTC выбран, чтобы события четырёх источников с разными зонами выстраивались в один ряд.',
      'Что делать: при сверке с журналами заказчика переводить в местную зону, а не наоборот.',
    ],
  },
  source: {
    title: 'Источник события',
    body: [
      'edr — агент на узле, siem — правило корреляции, network_events — сетевой поток Netflow, ot — телеметрия и конвейер сборки.',
      'Что делать: помнить разную природу свидетельств. EDR показывает, что произошло на узле; Netflow — что ушло по сети; SIEM — что уже решило вышестоящее средство.',
    ],
  },
  operation: {
    title: 'Операция',
    body: [
      'Что зафиксировал источник: тип события EDR, имя правила SIEM, вердикт по потоку, операция конвейера. Значение приходит от источника и не переписывается.',
      'Что делать: операции вида *_SUSPECT и *_ANOMALY означают вывод вышестоящего средства; их нужно перепроверять, а не принимать как факт.',
    ],
  },
  entity_host: {
    title: 'Узел',
    body: [
      'Рабочая станция, сервер или объект конвейера, на котором зафиксировано событие.',
      'Что делать: собрать по узлу все события кейса и проверить, есть ли среди них вход извне.',
    ],
  },
  entity_user: {
    title: 'Учётная запись',
    body: [
      'Пользователь или служебная запись, от имени которой выполнено действие.',
      'Что делать: сверить с тем, кто фактически работал. Служебная запись с интерактивными действиями — отдельный повод для проверки.',
    ],
  },
  entity_address: {
    title: 'Адрес',
    body: [
      'Источник и назначение сетевого обращения.',
      'Что делать: проверить внешние адреса по внутренним спискам. Повторяющиеся обращения к одному внешнему адресу — признак управляющего канала.',
    ],
  },
  artifact: {
    title: 'Артефакт',
    body: [
      'Объект, привязанный к событию: хэш файла, путь, домен, индикатор SIEM, имя службы или репозитория.',
      'Что делать: по артефактам проверяется, встречался ли инцидент на других узлах.',
    ],
  },
  dq_score: {
    title: 'Качество данных',
    body: [
      'Доля признаков, вычисленных по событию без пропусков: 1.00 — данные полные.',
      'Что делать: значение ниже 1.00 означает, что часть проверок не выполнялась. Это причина запросить исходные журналы, а не понижать значимость инцидента.',
    ],
  },
  event_count: {
    title: 'Событий в кейсе',
    body: [
      'Сколько событий отнесено к кейсу.',
      'Большое число само по себе не означает опасность: расширение разбора до уровня узла намеренно добирает и штатную активность этих узлов.',
      'Что делать: смотреть не количество, а состав по источникам и цепочку.',
    ],
  },
  xai: {
    title: 'Как собран кейс',
    body: [
      'Чем набран кейс: по каким отличительным сущностям собрано ядро и до каких узлов разбор расширен.',
      'Расширение до уровня узла добирает события без отличительных признаков, вместе с ними приходит штатная активность тех же узлов.',
      'Что делать: считать ядро надёжной частью, а добранное расширением — материалом для отсева.',
    ],
  },
};

const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) =>
  String(value ?? '').replace(/[&<>'"]/g, (symbol) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[symbol]));

let cases = [];
let selectedCaseId = null;
let selectedEntity = null;
let pollTimer = null;
let lastFocused = null;

// --- Работа с API ----------------------------------------------------------

async function api(path, options) {
  const request = { cache: 'no-store', ...options };
  if (options && options.body) {
    request.headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  }
  const response = await fetch(`${API_BASE}${path}`, request);
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      message = (await response.json()).detail || message;
    } catch (error) {
      // тело без JSON — оставляем код ответа
    }
    throw new Error(message);
  }
  return response.status === 204 ? null : response.json();
}

// --- Формат ----------------------------------------------------------------

function utc(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value ?? '—');
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
}

function score(value) {
  return Number.isFinite(Number(value)) ? Number(value).toFixed(3) : '—';
}

function firstArtifact(event) {
  const item = (event.artifacts || [])[0];
  return item ? `${item.type}: ${item.value}` : '';
}

function addressOf(entities) {
  if (!entities) return '';
  const parts = [entities.src_address, entities.dst_address].filter(Boolean);
  return parts.join(' → ');
}

// --- Очередь ---------------------------------------------------------------

function renderQueue() {
  const list = $('#queueList');
  list.replaceChildren();
  $('#queueEmpty').hidden = cases.length > 0;
  // При равном балле выше идёт кейс с большим числом событий: собранный инцидент
  // не должен теряться среди одиночных срабатываний с тем же баллом.
  const ordered = [...cases].sort(
    (a, b) => Number(b.risk_score) - Number(a.risk_score) || Number(b.event_count || 0) - Number(a.event_count || 0)
  );
  for (const item of ordered) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `queue-item${item.case_id === selectedCaseId ? ' active' : ''}`;
    button.innerHTML = `
      <span class="queue-top">
        <span class="case-id">${escapeHtml(item.case_id)}</span>
        <span class="risk ${escapeHtml(String(item.risk_class || '').toLowerCase())}">${escapeHtml(item.risk_class || '—')}</span>
      </span>
      <span class="queue-title">${escapeHtml(item.title || '—')}</span>
      <span class="queue-meta">${escapeHtml(item.status || '')} · ${escapeHtml(String(item.event_count ?? 0))} соб. · ${escapeHtml(score(item.risk_score))}</span>`;
    button.addEventListener('click', () => openCase(item.case_id));
    list.appendChild(button);
  }
}

// --- Окно инцидента --------------------------------------------------------

async function openCase(caseId) {
  selectedCaseId = caseId;
  renderQueue();
  $('#workEmpty').hidden = true;
  $('#workBody').hidden = false;
  try {
    const workspace = await api(`/cases/${encodeURIComponent(caseId)}/workspace`);
    renderCase(workspace);
  } catch (error) {
    $('#workBody').hidden = true;
    $('#workEmpty').hidden = false;
    $('#workEmpty').textContent = `Кейс не открылся: ${error.message}`;
  }
}

function renderCase(workspace) {
  const item = workspace.case || {};
  $('#caseId').textContent = item.case_id || '—';
  $('#caseStatus').textContent = item.status || '—';
  $('#caseTitle').textContent = item.title || '—';
  $('#riskClass').textContent = item.risk_class || '—';
  $('#riskClass').className = `metric-value risk ${String(item.risk_class || '').toLowerCase()}`;
  $('#riskScore').textContent = score(item.risk_score);
  $('#eventCount').textContent = String((workspace.events || []).length);
  $('#dqScore').textContent = `${score(item.dq_score)}${item.dq_partial ? ' (неполные)' : ''}`;
  $('#caseXai').textContent = item.xai_summary || '';

  renderSources(workspace.events || []);
  renderInvariants(item.invariant_hits || []);
  renderChain(workspace.events || []);
  renderGraph(workspace.graph || { nodes: [], edges: [] });
  renderResponse(workspace.events || [], workspace.artifacts || []);
  renderFindings(item.findings || []);
}

function renderSources(events) {
  const counts = new Map();
  for (const event of events) counts.set(event.source, (counts.get(event.source) || 0) + 1);
  const box = $('#sourceList');
  box.replaceChildren();
  if (!counts.size) {
    box.innerHTML = '<span class="muted small">нет событий</span>';
    return;
  }
  for (const [source, count] of [...counts.entries()].sort()) {
    const chip = document.createElement('span');
    chip.className = 'chip';
    chip.textContent = `${source} · ${count}`;
    box.appendChild(chip);
  }
}

function renderInvariants(hits) {
  const box = $('#invariantList');
  box.replaceChildren();
  if (!hits.length) {
    box.innerHTML = '<span class="muted small">срабатываний нет</span>';
    return;
  }
  for (const hit of hits) {
    const chip = document.createElement('span');
    chip.className = 'chip warn';
    chip.textContent = hit;
    box.appendChild(chip);
  }
}

function entityButton(type, value) {
  if (!value) return '';
  return `<button type="button" class="entity-link" data-entity-type="${escapeHtml(type)}" data-entity-id="${escapeHtml(value)}">${escapeHtml(value)}</button>`;
}

function renderChain(events) {
  const body = $('#chainBody');
  body.replaceChildren();
  const ordered = [...events].sort((a, b) => String(a.observed_at).localeCompare(String(b.observed_at)));
  for (const event of ordered) {
    const entities = event.entities || {};
    const row = document.createElement('tr');
    row.innerHTML = `
      <td class="mono">${escapeHtml(utc(event.observed_at))}</td>
      <td><span class="chip sm">${escapeHtml(event.source)}</span></td>
      <td class="mono">${escapeHtml(event.operation)}</td>
      <td>${entityButton('host', entities.host_id)}</td>
      <td>${entityButton('user', entities.user_id)}</td>
      <td class="mono small">${escapeHtml(addressOf(entities))}</td>
      <td class="small">${escapeHtml(firstArtifact(event))}</td>`;
    body.appendChild(row);
  }
  body.querySelectorAll('.entity-link').forEach((button) => {
    button.addEventListener('click', () => openEntity(button.dataset.entityType, button.dataset.entityId));
  });
}

function renderGraph(graph) {
  const box = $('#graphList');
  box.replaceChildren();
  const edges = graph.edges || [];
  if (!edges.length) {
    box.innerHTML = '<span class="muted small">связей нет</span>';
    return;
  }
  const kinds = { initiated: 'запустил', spawned: 'породил', runs: 'выполняет', network: 'обратился к' };
  const seen = new Set();
  for (const edge of edges) {
    const key = `${edge.source}|${edge.type}|${edge.target}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const row = document.createElement('div');
    row.className = 'graph-row';
    row.innerHTML = `<span class="mono">${escapeHtml(edge.source)}</span>
      <span class="edge">${escapeHtml(kinds[edge.type] || edge.type)}</span>
      <span class="mono">${escapeHtml(edge.target)}</span>`;
    box.appendChild(row);
  }
}

// Варианты реагирования строятся по отличительным сущностям инцидента (артефакты кейса
// с источником pivot-seed), а не по всем сущностям событий. События, добранные расширением
// до уровня узла, содержат и штатную активность: предлагать по ним действия — значит
// предлагать сброс учётных записей людей, которые в это время просто работали.
function renderResponse(events, artifacts) {
  const hosts = new Set();
  const users = new Set();
  const addresses = new Set();
  let pipeline = false;
  const seeds = (artifacts || []).filter((item) => item.source === 'pivot-seed');
  const objects = new Set();
  for (const seed of seeds) {
    // Объекты конвейера приходят в поле узла с префиксом вида `pipeline:` или
    // `artifact:`. Изолировать их нельзя — это не узлы сети.
    if (seed.type === 'host') (seed.value.includes(':') ? objects : hosts).add(seed.value);
    if (seed.type === 'user') users.add(seed.value);
    if (seed.type === 'address') addresses.add(seed.value);
  }
  for (const event of events) {
    if (event.source === 'ot') pipeline = true;
  }
  if (!seeds.length) {
    // Кейс собран не пивотом: отличительных сущностей нет, перечислять нечего.
    const list = $('#responseList');
    list.replaceChildren();
    list.innerHTML = '<li class="muted small">отличительные сущности не заданы; выберите объекты действия в цепочке событий</li>';
    return;
  }
  const options = [];
  if (hosts.size) options.push(`Изоляция узлов: ${[...hosts].join(', ')}`);
  if (users.size) options.push(`Сброс учётных записей: ${[...users].join(', ')}`);
  if (addresses.size) options.push(`Блокировка адресов: ${[...addresses].join(', ')}`);
  if (pipeline || objects.size) {
    const listed = objects.size ? `: ${[...objects].join(', ')}` : '';
    options.push(`Заморозка конвейера сборки до проверки объектов${listed}`);
  }

  const list = $('#responseList');
  list.replaceChildren();
  if (!options.length) {
    list.innerHTML = '<li class="muted small">объектов для действий в кейсе нет</li>';
    return;
  }
  for (const option of options) {
    const row = document.createElement('li');
    row.textContent = option;
    list.appendChild(row);
  }
}

// --- Сущность и находки ----------------------------------------------------

async function openEntity(type, id) {
  selectedEntity = { type, id };
  $('#entityEmpty').hidden = true;
  $('#entityBody').hidden = false;
  $('#entityType').textContent = type;
  $('#entityId').textContent = id;
  const facts = $('#entityFacts');
  facts.replaceChildren();
  try {
    const card = await api(`/entities/${encodeURIComponent(type)}/${encodeURIComponent(id)}/card`);
    const typicality = card.typicality || {};
    const known = { first_seen: 'встречается впервые', rare: 'редкая сущность', typical: 'обычная активность' };
    const rows = [
      ['Событий всего', card.event_count ?? (card.environment || []).length],
      ['Историчность', known[typicality.status] || typicality.status || '—'],
      ['Первое появление', card.first_seen ? utc(card.first_seen) : '—'],
      ['Последнее появление', card.last_seen ? utc(card.last_seen) : '—'],
      ['Источники', (card.sources || []).join(', ') || '—'],
      ['Связанные кейсы', (card.related_cases || []).join(', ') || '—'],
    ];
    for (const [label, value] of rows) {
      const dt = document.createElement('dt');
      dt.textContent = label;
      const dd = document.createElement('dd');
      dd.textContent = String(value);
      facts.append(dt, dd);
    }
  } catch (error) {
    const dt = document.createElement('dt');
    dt.textContent = 'Историчность';
    const dd = document.createElement('dd');
    dd.textContent = `недоступна: ${error.message}`;
    facts.append(dt, dd);
  }
}

function renderFindings(findings) {
  const list = $('#findingList');
  list.replaceChildren();
  if (!findings.length) {
    list.innerHTML = '<li class="muted small">находок нет</li>';
    return;
  }
  for (const finding of findings) {
    const row = document.createElement('li');
    row.textContent = finding.text || `${finding.entity_type || ''}: ${finding.entity_id || ''}`;
    list.appendChild(row);
  }
}

async function addFinding() {
  if (!selectedEntity || !selectedCaseId) return;
  const button = $('#addFinding');
  button.disabled = true;
  try {
    await api(`/cases/${encodeURIComponent(selectedCaseId)}/findings`, {
      method: 'POST',
      body: JSON.stringify({ text: `${selectedEntity.type}: ${selectedEntity.id}` }),
    });
    toast('Находка записана в журнал кейса');
    await openCase(selectedCaseId);
  } catch (error) {
    toast(`Находка не сохранена: ${error.message}`);
  } finally {
    button.disabled = false;
  }
}

// --- Модальные пояснения ---------------------------------------------------

function openHelp(key) {
  const entry = HELP[key];
  if (!entry) return;
  lastFocused = document.activeElement;
  $('#modalTitle').textContent = entry.title;
  const body = $('#modalBody');
  body.replaceChildren();
  for (const paragraph of entry.body) {
    const item = document.createElement('p');
    item.textContent = paragraph;
    body.appendChild(item);
  }
  $('#modal').hidden = false;
  $('#modalClose').focus();
}

function closeHelp() {
  $('#modal').hidden = true;
  if (lastFocused && typeof lastFocused.focus === 'function') lastFocused.focus();
}

function toast(message) {
  const box = $('#toast');
  box.textContent = message;
  box.hidden = false;
  setTimeout(() => {
    box.hidden = true;
  }, 4000);
}

// --- Обновление и запуск ---------------------------------------------------

function setConnection(state, detail = '') {
  const box = $('#connection');
  box.className = `conn ${state}`;
  box.textContent = state === 'ok' ? 'связь есть' : state === 'off' ? `нет связи${detail ? `: ${detail}` : ''}` : 'подключение';
}

async function refresh() {
  try {
    const data = await api('/cases');
    cases = Array.isArray(data) ? data : data.items || [];
    renderQueue();
    setConnection('ok');
    $('#lastSync').textContent = `обновлено ${utc(new Date().toISOString())} UTC`;
    if (!selectedCaseId && cases.length) {
      const top = [...cases].sort(
        (a, b) => Number(b.risk_score) - Number(a.risk_score) || Number(b.event_count || 0) - Number(a.event_count || 0)
      )[0];
      openCase(top.case_id);
    }
  } catch (error) {
    setConnection('off', error.message);
  }
}

document.addEventListener('click', (event) => {
  const helpButton = event.target.closest('[data-help]');
  if (helpButton) {
    openHelp(helpButton.dataset.help);
    return;
  }
  if (event.target === $('#modal')) closeHelp();
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !$('#modal').hidden) closeHelp();
});

$('#modalClose').addEventListener('click', closeHelp);
$('#addFinding').addEventListener('click', addFinding);

// ---------------------------------------------------------------------------
// Вкладка «Симуляция»: хронология цепочки, счётчики трудоёмкости, граф атаки
// ---------------------------------------------------------------------------

// Цвета фаз. Порядок соответствует доменному перечню KillChainPhase — по нему строится
// легенда и раскраска графа.
const PHASE_COLORS = {
  recon: '#64748b',
  initial_access: '#38bdf8',
  execution: '#22d3ee',
  c2: '#a78bfa',
  privilege_escalation: '#fbbf24',
  lateral_movement: '#fb923c',
  persistence: '#f472b6',
  exfiltration: '#f87171',
  impact: '#ef4444',
};

const PLAY_INTERVAL_MS = 1200;

let simulation = null;
let simCursor = 0;
let simTimer = null;

// Значение счётчика на шаге: ровное распределение с остатком на последнем шаге.
// Так итог после проигрывания совпадает с числом из /simulation, а не «примерно».
function cumulative(total, steps, index) {
  if (steps <= 0) return 0;
  if (index >= steps) return total;
  return Math.round((total * index) / steps);
}

// Коэффициент модельной оценки времени. Задаётся оператором: измеренного значения нет,
// поэтому значение по умолчанию — объявленное допущение, а не величина из методики.
function secondsPerAction() {
  const raw = Number($('#secondsPerAction').value);
  return Number.isFinite(raw) && raw > 0 ? raw : null;
}

function formatDuration(seconds) {
  if (!Number.isFinite(seconds)) return '—';
  const total = Math.round(seconds);
  const minutes = Math.floor(total / 60);
  return minutes ? `${minutes} мин ${String(total % 60).padStart(2, '0')} с` : `${total} с`;
}

function phaseColor(phase) {
  return PHASE_COLORS[phase] || '#64748b';
}

async function openSimulation() {
  if (!selectedCaseId) return;
  $('#simEmpty').hidden = true;
  $('#simBody').hidden = false;
  try {
    const perAction = secondsPerAction();
    const query = perAction ? `?seconds_per_action=${perAction}` : '';
    simulation = await api(`/cases/${encodeURIComponent(selectedCaseId)}/simulation${query}`);
  } catch (error) {
    $('#simBody').hidden = true;
    $('#simEmpty').hidden = false;
    $('#simEmpty').textContent = `Симуляция недоступна: ${error.message}`;
    return;
  }
  simCursor = 0;
  renderLegend();
  renderSteps();
  renderAttackGraph();
  renderSummary();
  updateCounters();
  updatePosition();
}

function renderLegend() {
  const box = $('#phaseLegend');
  box.replaceChildren();
  for (const phase of simulation.phases || []) {
    const item = document.createElement('span');
    item.className = 'legend-item';
    item.innerHTML = `<i style="background:${phaseColor(phase.phase)}"></i>${escapeHtml(phase.title_ru)} · ${phase.events}`;
    box.appendChild(item);
  }
}

function renderSteps() {
  const list = $('#stepList');
  list.replaceChildren();
  for (const step of simulation.steps || []) {
    const row = document.createElement('li');
    row.className = 'step';
    row.dataset.order = String(step.order);
    row.style.borderLeftColor = phaseColor(step.attack_phase);
    row.innerHTML = `
      <button type="button" class="step-open">
        <span class="step-time mono">${escapeHtml(utc(step.observed_at))}</span>
        <span class="step-phase" style="color:${phaseColor(step.attack_phase)}">${escapeHtml(step.attack_phase_title_ru)}</span>
        <span class="step-op mono">${escapeHtml(step.operation)}</span>
        <span class="chip sm">${escapeHtml(step.source)}</span>
        <span class="muted small">${escapeHtml(step.mitre_technique || '')}</span>
      </button>`;
    row.querySelector('.step-open').addEventListener('click', () => openStep(step.order));
    list.appendChild(row);
  }
  paintProgress();
}

// Узлы и переходы цепочки: сущности в порядке первого появления.
function chainGraph() {
  const nodes = new Map();
  const edges = [];
  const add = (id, type, phase, order) => {
    if (!id) return null;
    if (!nodes.has(id)) nodes.set(id, { id, type, phase, order });
    return id;
  };
  for (const step of simulation.steps || []) {
    const parts = step.entities || {};
    const user = add(parts.user_id, 'user', step.attack_phase, step.order);
    const host = add(parts.host_id, 'host', step.attack_phase, step.order);
    const dst = add(parts.dst_address, 'address', step.attack_phase, step.order);
    if (user && host) edges.push({ from: user, to: host, label: 'действует на', order: step.order });
    if (host && dst) edges.push({ from: host, to: dst, label: 'обращается к', order: step.order });
  }
  return { nodes: [...nodes.values()], edges };
}

// Имя намеренно отличается от `renderGraph` панели «Связи сущностей». Обе функции лежат в
// одной области видимости, и объявление ниже перекрывало объявление выше: открытие кейса
// вызывало отрисовку графа атаки, читало `simulation.steps` у ещё не загруженной симуляции и
// падало — вкладка «Расследование» не открывалась вообще.
function renderAttackGraph() {
  const svg = $('#attackGraph');
  svg.replaceChildren();
  const { nodes, edges } = chainGraph();
  if (!nodes.length) return;

  const perRow = 5;
  const position = new Map();
  nodes.forEach((node, index) => {
    const row = Math.floor(index / perRow);
    const col = index % perRow;
    position.set(node.id, { x: 110 + col * 185, y: 60 + row * 90 });
  });

  const ns = 'http://www.w3.org/2000/svg';
  const seen = new Set();
  for (const edge of edges) {
    const key = `${edge.from}|${edge.to}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const from = position.get(edge.from);
    const to = position.get(edge.to);
    if (!from || !to) continue;
    const line = document.createElementNS(ns, 'line');
    line.setAttribute('x1', from.x);
    line.setAttribute('y1', from.y);
    line.setAttribute('x2', to.x);
    line.setAttribute('y2', to.y);
    line.setAttribute('class', 'edge-line');
    line.dataset.order = String(edge.order);
    svg.appendChild(line);
    const label = document.createElementNS(ns, 'text');
    label.setAttribute('x', (from.x + to.x) / 2);
    label.setAttribute('y', (from.y + to.y) / 2 - 6);
    label.setAttribute('class', 'edge-label');
    label.textContent = edge.label;
    svg.appendChild(label);
  }

  for (const node of nodes) {
    const point = position.get(node.id);
    const group = document.createElementNS(ns, 'g');
    group.setAttribute('class', 'graph-node');
    group.dataset.order = String(node.order);
    const circle = document.createElementNS(ns, 'circle');
    circle.setAttribute('cx', point.x);
    circle.setAttribute('cy', point.y);
    circle.setAttribute('r', 14);
    circle.setAttribute('fill', phaseColor(node.phase));
    group.appendChild(circle);
    const text = document.createElementNS(ns, 'text');
    text.setAttribute('x', point.x);
    text.setAttribute('y', point.y + 30);
    text.setAttribute('class', 'node-label');
    text.textContent = node.id.length > 22 ? `${node.id.slice(0, 21)}…` : node.id;
    group.appendChild(text);
    group.addEventListener('click', () => openStep(node.order));
    svg.appendChild(group);
  }
  paintProgress();
}

function paintProgress() {
  for (const row of document.querySelectorAll('#stepList .step')) {
    const order = Number(row.dataset.order);
    row.classList.toggle('played', order <= simCursor);
    row.classList.toggle('current', order === simCursor);
  }
  for (const element of document.querySelectorAll('#attackGraph .edge-line, #attackGraph .graph-node')) {
    element.classList.toggle('played', Number(element.dataset.order) <= simCursor);
  }
}

function updateCounters() {
  const effort = simulation.effort || {};
  const steps = (simulation.steps || []).length;
  const manual = cumulative(effort.current_actions || 0, steps, simCursor);
  const takt = cumulative(effort.takt_actions || 0, steps, simCursor);
  $('#manualActions').textContent = String(manual);
  $('#taktActions').textContent = String(takt);
  const reduction = effort.reduction_actions_percent;
  $('#reductionValue').textContent =
    reduction === null || reduction === undefined ? '—' : `${reduction.toFixed(1)}%`;

  const perAction = effort.seconds_per_action;
  if (perAction) {
    const manualTime = manual * perAction;
    const taktTime = takt * perAction;
    $('#manualSeconds').textContent = `${formatDuration(manualTime)} (модель)`;
    $('#taktSeconds').textContent = `${formatDuration(taktTime)} (модель)`;
    $('#timeValue').textContent = `${formatDuration(taktTime)} / ${formatDuration(manualTime)}`;
    // Модельное время пропорционально действиям, поэтому отдельного вывода о сокращении
    // времени здесь нет: он совпал бы с сокращением действий и выглядел бы вторым
    // независимым доказательством, которым не является.
    $('#timeDelta').textContent = `ТАКТ / вручную · модельная оценка при ${perAction} с на действие`;
  } else {
    $('#manualSeconds').textContent = 'время не рассчитано';
    $('#taktSeconds').textContent = 'время не рассчитано';
    $('#timeValue').textContent = '—';
    $('#timeDelta').textContent = 'коэффициент не задан';
  }
}

function updatePosition() {
  const steps = (simulation && simulation.steps ? simulation.steps : []).length;
  $('#playerPosition').textContent = `${simCursor} / ${steps}`;
}

function renderSummary() {
  const facts = $('#simSummary');
  facts.replaceChildren();
  const rows = [
    ['Класс риска', `${simulation.risk_class} · ${Number(simulation.risk_score).toFixed(3)}`],
    ['Статус', simulation.status],
    ['Событий в кейсе', `${simulation.events_total}, из них шагов цепочки ${simulation.chain_length}`],
    ['Без разметки фазы', String(simulation.events_without_phase)],
    ['Сработавшие инварианты', (simulation.invariants || []).join(', ') || 'нет'],
  ];
  for (const option of simulation.response_options || []) {
    rows.push([option.title, option.objects || '—']);
  }
  for (const [label, value] of rows) {
    const dt = document.createElement('dt');
    dt.textContent = label;
    const dd = document.createElement('dd');
    dd.textContent = value;
    facts.append(dt, dd);
  }
}

function openStep(order) {
  const step = (simulation.steps || []).find((item) => item.order === order);
  if (!step) return;
  setCursor(order);

  const detection = step.detection_explanation || {};
  const entities = Object.entries(step.entities || {})
    .filter(([, value]) => value)
    .map(([name, value]) => `${name}: ${value}`);
  const artifacts = (step.artifacts || []).map((item) => `${item.type}: ${item.value}`);

  lastFocused = document.activeElement;
  $('#modalTitle').textContent = `Шаг ${step.order}. ${step.attack_phase_title_ru}`;
  const body = $('#modalBody');
  body.replaceChildren();
  const paragraphs = [
    `Что произошло: источник ${step.source} зафиксировал ${step.operation} в ${utc(step.observed_at)} UTC.`,
    `Фаза цепочки: ${step.attack_phase_title_ru}. Техника ATT&CK: ${step.mitre_technique || 'не сопоставлена'}. Разметка приходит от источника, ТАКТ её не вычисляет.`,
    `Чем выделено: ${detection.selected_by_title_ru || 'не зафиксировано'}. ${detection.reason || ''}`,
    detection.invariants && detection.invariants.length
      ? `Сработавшие инварианты на этом событии: ${detection.invariants.join(', ')}.`
      : 'Инварианты на этом событии не срабатывали: оно попало в кейс по связи сущностей, а не по признаку правила.',
    entities.length ? `Сущности: ${entities.join(', ')}.` : 'Сущности не заполнены.',
    artifacts.length ? `Артефакты: ${artifacts.join(', ')}.` : 'Артефактов нет.',
  ];
  for (const text of paragraphs) {
    const item = document.createElement('p');
    item.textContent = text;
    body.appendChild(item);
  }
  $('#modal').hidden = false;
  $('#modalClose').focus();
}

function setCursor(next) {
  const steps = (simulation && simulation.steps ? simulation.steps : []).length;
  simCursor = Math.max(0, Math.min(steps, next));
  paintProgress();
  updateCounters();
  updatePosition();
}

function stopPlayback() {
  clearInterval(simTimer);
  simTimer = null;
  $('#playPause').textContent = 'Воспроизвести';
}

function togglePlayback() {
  if (!simulation) return;
  if (simTimer) {
    stopPlayback();
    return;
  }
  $('#playPause').textContent = 'Пауза';
  simTimer = setInterval(() => {
    if (simCursor >= simulation.steps.length) {
      stopPlayback();
      return;
    }
    setCursor(simCursor + 1);
  }, PLAY_INTERVAL_MS);
}

function showTab(name) {
  const isSimulation = name === 'simulation';
  $('#tabSimulation').classList.toggle('active', isSimulation);
  $('#tabSimulation').setAttribute('aria-pressed', String(isSimulation));
  $('#tabInvestigation').classList.toggle('active', !isSimulation);
  $('#tabInvestigation').setAttribute('aria-pressed', String(!isSimulation));
  document.querySelector('.layout').hidden = isSimulation;
  $('#simulationView').hidden = !isSimulation;
  if (isSimulation) openSimulation();
  else stopPlayback();
}

$('#tabSimulation').addEventListener('click', () => showTab('simulation'));
$('#tabInvestigation').addEventListener('click', () => showTab('investigation'));
$('#playPause').addEventListener('click', togglePlayback);
$('#stepForward').addEventListener('click', () => {
  stopPlayback();
  setCursor(simCursor + 1);
});
$('#stepBack').addEventListener('click', () => {
  stopPlayback();
  setCursor(simCursor - 1);
});
$('#secondsPerAction').addEventListener('change', () => {
  if (!$('#simulationView').hidden) openSimulation();
});
$('#resetPlayer').addEventListener('click', () => {
  stopPlayback();
  setCursor(0);
});

refresh();
pollTimer = setInterval(refresh, POLL_MS);
