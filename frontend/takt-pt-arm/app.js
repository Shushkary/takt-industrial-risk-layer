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

refresh();
pollTimer = setInterval(refresh, POLL_MS);
