// На текущем HTTP/2-контуре параллельная загрузка CSS и JS периодически
// удерживает второй поток. Стили подключаются после получения app.js.
if (!document.querySelector('style[data-takt-styles]')) {
  const stylesheet = document.createElement('link');
  stylesheet.rel = 'stylesheet';
  stylesheet.href = './styles.css?v=20260803-07';
  document.head.appendChild(stylesheet);
}

const API_BASE = location.protocol === 'file:' ? 'https://ralta.ru/takt_pt' : '/takt_pt_arm';
const OPERATOR_ID = 'operator.arm-04';
const POLL_MS = 10000;
const STALE_MS = 7000;

// Демонстрационный сценарий INC-002 — компрометация конвейера сборки через
// фишинг. Используется, когда API недоступен: интерфейс остаётся показательным
// и на стенде без бэкенда. Данные синтетические, совпадают с фикстурой
// tests/fixtures/pt_techlab/inc_002.
const FALLBACK_CASES = [
  { id: 'INC-002', severity: 'critical', status: 'investigating', title: 'Компрометация конвейера сборки: фишинг → C2 → подмена артефакта', risk_score: .93, impact_score: .96, confidence: .87, observations: 27, tail_risk: true, invariants: ['INV-NET-01','INV-AUTH-03','INV-CI-07'], xai_summary: 'Собрано 27 событий из 4 источников: фишинг на ws-17 (smirnov) → канал C2 по DoH → kerberoasting и захват svc_build → перемещение на build-srv-01 → неподписанный артефакт в релизном конвейере release-prod.', findings: [{ entity_type: 'host', entity_id: 'ws-17' }, { entity_type: 'account', entity_id: 'svc_build' }, { entity_type: 'address', entity_id: '185.220.101.34' }, { entity_type: 'repo', entity_id: 'release-prod' }] },
  { id: 'BG-ADMIN', severity: 'medium', status: 'new', title: 'Удалённое исполнение WMI вне рабочего окна (admin_ops)', risk_score: .44, impact_score: .21, confidence: .39, observations: 2, tail_risk: false, invariants: ['INV-AUTH-09'], xai_summary: 'Похоже на горизонтальное перемещение, но действие выполнено штатной учётной записью администратора.', findings: [{ entity_type: 'host', entity_id: 'dc-02' }] },
  { id: 'BG-SCAN', severity: 'low', status: 'new', title: 'Сканирование сети с scan-01', risk_score: .31, impact_score: .12, confidence: .52, observations: 9, tail_risk: false, invariants: ['INV-NET-01'], xai_summary: 'Санкционированное сканирование уязвимостей; профиль совпадает с согласованным окном.', findings: [{ entity_type: 'host', entity_id: 'scan-01' }] },
  { id: 'BG-BACKUP', severity: 'low', status: 'resolved', title: 'Ночное резервное копирование (svc_backup)', risk_score: .22, impact_score: .18, confidence: .46, observations: 2, tail_risk: false, invariants: [], xai_summary: 'Большой объём SMB-трафика объясняется плановым бэкапом.', findings: [{ entity_type: 'host', entity_id: 'backup-01' }] }
];

const INC002_EVENTS = [
  { ts:'2026-08-17T06:00:00Z', source_class:'edr', host_id:'ws-17', user_id:'smirnov', process:'OUTLOOK.EXE', severity:'info', operation:'PROCESS_START' },
  { ts:'2026-08-17T06:01:00Z', source_class:'edr', host_id:'ws-17', user_id:'smirnov', process:'mshta.exe', severity:'info', operation:'PROCESS_START' },
  { ts:'2026-08-17T06:01:30Z', source_class:'edr', host_id:'ws-17', user_id:'smirnov', process:'powershell.exe', address:'185.220.101.34', severity:'info', operation:'PROCESS_START' },
  { ts:'2026-08-17T06:02:00Z', source_class:'edr', host_id:'ws-17', user_id:'smirnov', process:'invoice_viewer.exe', severity:'warning', operation:'FILE_WRITE' },
  { ts:'2026-08-17T06:02:30Z', source_class:'edr', host_id:'ws-17', user_id:'smirnov', process:'invoice_viewer.exe', address:'185.220.101.34', severity:'info', operation:'PROCESS_START' },
  { ts:'2026-08-17T06:03:00Z', source_class:'ndr', host_id:'ws-17', address:'185.220.101.34', artifact:'cdn-metrics.example-analytics.com', severity:'critical', operation:'C2_SUSPECT' },
  { ts:'2026-08-17T06:04:00Z', source_class:'siem', host_id:'ws-17', user_id:'smirnov', address:'185.220.101.34', artifact:'cdn-metrics.example-analytics.com', severity:'warning', operation:'SUSPICIOUS_OUTBOUND' },
  { ts:'2026-08-17T06:10:00Z', source_class:'ndr', host_id:'ws-17', address:'185.220.101.34', artifact:'cdn-metrics.example-analytics.com', severity:'critical', operation:'C2_SUSPECT' },
  { ts:'2026-08-17T06:12:00Z', source_class:'edr', host_id:'ws-17', user_id:'smirnov', process:'svchosts.exe', severity:'info', operation:'PROCESS_START' },
  { ts:'2026-08-17T06:13:00Z', source_class:'siem', host_id:'dc-01', user_id:'smirnov', address:'10.10.1.10', artifact:'MSSQLSvc/db01', severity:'critical', operation:'KERBEROS_TGS_RC4' },
  { ts:'2026-08-17T06:13:00Z', source_class:'siem', host_id:'dc-01', user_id:'smirnov', address:'10.10.1.10', artifact:'HTTP/build-srv-01', severity:'critical', operation:'KERBEROS_TGS_RC4' },
  { ts:'2026-08-17T06:13:00Z', source_class:'siem', host_id:'dc-01', user_id:'smirnov', address:'10.10.1.10', artifact:'CIFS/file-srv-01', severity:'critical', operation:'KERBEROS_TGS_RC4' },
  { ts:'2026-08-17T06:14:00Z', source_class:'siem', host_id:'dc-01', user_id:'svc_build', address:'10.10.1.10', artifact:'svc_build', severity:'warning', operation:'LOGON_SERVICE_ACCOUNT_ANOMALY' },
  { ts:'2026-08-17T06:15:00Z', source_class:'ndr', host_id:'ws-17', address:'10.10.3.5', severity:'critical', operation:'LATERAL_SUSPECT' },
  { ts:'2026-08-17T06:16:00Z', source_class:'edr', host_id:'build-srv-01', user_id:'svc_build', process:'wmiprvse.exe', address:'10.10.1.26', severity:'info', operation:'PROCESS_START' },
  { ts:'2026-08-17T06:16:30Z', source_class:'edr', host_id:'build-srv-01', user_id:'svc_build', process:'powershell.exe', severity:'info', operation:'PROCESS_START' },
  { ts:'2026-08-17T06:17:00Z', source_class:'ndr', host_id:'ws-17', address:'185.220.101.34', artifact:'cdn-metrics.example-analytics.com', severity:'critical', operation:'C2_SUSPECT' },
  { ts:'2026-08-17T06:17:00Z', source_class:'siem', host_id:'build-srv-01', user_id:'svc_build', address:'10.10.3.5', severity:'critical', operation:'REMOTE_EXEC_WMI' },
  { ts:'2026-08-17T06:20:00Z', source_class:'ndr', host_id:'build-srv-01', address:'10.10.3.6', artifact:'git-srv-01.corp.local', severity:'info', operation:'ALLOWED' },
  { ts:'2026-08-17T06:21:00Z', source_class:'edr', host_id:'build-srv-01', user_id:'svc_build', process:'git.exe', severity:'info', operation:'PROCESS_START' },
  { ts:'2026-08-17T06:22:00Z', source_class:'edr', host_id:'build-srv-01', user_id:'svc_build', process:'app-setup.msi', severity:'warning', operation:'FILE_WRITE' },
  { ts:'2026-08-17T06:23:00Z', source_class:'ot', host_id:'artifact:app-setup.msi', address:'10.10.3.6', severity:'critical', operation:'ARTIFACT_HASH_MISMATCH' },
  { ts:'2026-08-17T06:23:30Z', source_class:'ot', host_id:'pipeline:release-prod', address:'10.10.3.6', severity:'critical', operation:'UNSIGNED_ARTIFACT_PUSH' },
  { ts:'2026-08-17T06:24:00Z', source_class:'ndr', host_id:'ws-17', address:'185.220.101.34', artifact:'cdn-metrics.example-analytics.com', severity:'critical', operation:'C2_SUSPECT' },
  { ts:'2026-08-17T06:24:00Z', source_class:'siem', host_id:'build-srv-01', user_id:'svc_build', address:'10.10.3.6', artifact:'release-prod', severity:'warning', operation:'CODE_REPO_WRITE_OFFHOURS' },
  { ts:'2026-08-17T06:31:00Z', source_class:'ndr', host_id:'ws-17', address:'185.220.101.34', artifact:'cdn-metrics.example-analytics.com', severity:'critical', operation:'C2_SUSPECT' },
  { ts:'2026-08-17T06:38:00Z', source_class:'ndr', host_id:'ws-17', address:'185.220.101.34', artifact:'cdn-metrics.example-analytics.com', severity:'critical', operation:'C2_SUSPECT' },
];

// События демо-сценария по кейсам: показываются, когда поток из API недоступен.
const FALLBACK_EVENTS = { 'INC-002': INC002_EVENTS };

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
const percent = (value) => `${Math.round(clamp(Number(value) || 0, 0, 1) * 100)}%`;
const number = (value) => new Intl.NumberFormat('ru-RU').format(value);
const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, (symbol) => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' }[symbol]));

let cases = [];
let selectedCaseId = null;
let lastActivity = 0;
let pollTimer = null;
let refreshInFlight = false;
let selectedEntity = null;
let investigationEvents = [];

const SEGMENT_MODES = {
  normal: {
    status: 'ШТАТНЫЙ · МОНИТОРИНГ ПОЛНЫЙ',
    title: 'Штатный режим применён',
    detail: 'Мониторинг и обработка данных ТАКТ выполняются в полном объёме.'
  },
  degraded: {
    status: 'ДЕГРАДАЦИЯ · УСИЛЕННЫЙ КОНТРОЛЬ',
    title: 'Режим деградации применён',
    detail: 'Интерфейс помечен для усиленного контроля; внешние действия не запускались.'
  },
  isolated: {
    status: 'ИЗОЛЯЦИЯ · ОЖИДАНИЕ ПОДТВЕРЖДЕНИЯ',
    title: 'Режим изоляции подготовлен',
    detail: 'Автоматическая изоляция сегмента не выполняется. Подтвердите действие в согласованном контуре.'
  }
};

function setSegmentMode(mode, announce = false) {
  const selected = SEGMENT_MODES[mode] ? mode : 'normal';
  const meta = SEGMENT_MODES[selected];
  document.body.dataset.segmentMode = selected;
  $$('.mode').forEach((button) => {
    const active = button.dataset.mode === selected;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  });
  $('#segmentModeStatus').textContent = meta.status;
  try { localStorage.setItem('takt.segment-mode', selected); } catch { /* private browsing */ }
  if (announce) showToast(meta.title, meta.detail, selected === 'isolated');
}

function tickClock() {
  $('#clock').textContent = new Date().toLocaleTimeString('ru-RU', { hour12: false });
}

function formatAge() {
  if (!lastActivity) return '—';
  const seconds = Math.max(0, Math.round((Date.now() - lastActivity) / 1000));
  return seconds < 2 ? 'только что' : `${seconds} сек. назад`;
}

function formatSla(item) {
  if (item.status === 'resolved') return 'ЗАКР';
  const minutes = Math.max(3, Math.round((1 - clamp(item.risk_score, 0, 1)) * 60));
  return `${String(Math.floor(minutes / 60)).padStart(2, '0')}:${String(minutes % 60).padStart(2, '0')}`;
}

function severityMeta(severity) {
  return ({ critical: ['critical', 'КРИТИЧЕСКИЙ'], high: ['critical', 'ВЫСОКИЙ'], medium: ['warning', 'СРЕДНИЙ'], low: ['cyan', 'НИЗКИЙ'] })[severity] || ['muted', 'НАБЛЮДЕНИЕ'];
}

function mainEntity(item) {
  const finding = (item.findings || []).find((entry) => entry.entity_type === 'host') || (item.findings || [])[0];
  return finding?.entity_id || 'связанный актив';
}

function recommendation(item) {
  const entity = mainEntity(item);
  if (item.status === 'resolved') return `Проверить устойчивость после закрытия · ${entity}`;
  if (item.risk_score >= .8) return `Изолировать ${entity} и проверить цепочку`;
  if (item.tail_risk) return `Проверить OT-контур и ограничения · ${entity}`;
  if (item.risk_score >= .4) return `Подтвердить окно работ · ${entity}`;
  return `Наблюдать отклонение · ${entity}`;
}

function setMetric(selector, value) {
  const safe = clamp(Math.round(value), 0, 100);
  $(`${selector} i`).style.width = `${safe}%`;
  $(`${selector} b`).textContent = `${safe}%`;
}

function renderQueue() {
  const active = cases.filter((item) => item.status !== 'resolved');
  $('#totalCount').textContent = cases.length;
  $('#activeCount').textContent = active.length;
  const average = cases.length ? cases.reduce((sum, item) => sum + Number(item.risk_score || 0), 0) / cases.length : 0;
  $('#queueDelta').innerHTML = `${percent(average)}<small>средний риск</small>`;
  const table = $('.incident-table');
  table.querySelectorAll('button.tr').forEach((row) => row.remove());
  cases.slice(0, 4).forEach((item) => {
    const [severityClass] = severityMeta(item.severity);
    const score = Number(item.risk_score || 0);
    const riskClass = score >= .75 ? 'high' : score >= .4 ? 'medium' : score >= .25 ? 'low' : 'quiet';
    const row = document.createElement('button');
    row.className = `tr${item.id === selectedCaseId ? ' selected' : ''}`;
    row.dataset.id = item.id;
    row.setAttribute('role', 'row');
    row.innerHTML = `<span><i class="severity ${severityClass}"></i><b>${escapeHtml(item.title)}</b><small>${escapeHtml(mainEntity(item))} · ${escapeHtml((item.invariants || []).slice(0, 2).join(' / ') || 'TAKT')}</small></span><span class="risk ${riskClass}">${Number(score).toFixed(2)}</span><span class="sla ${score >= .75 ? 'danger' : ''}">${formatSla(item)}</span><svg><use href="#i-chevron"/></svg>`;
    row.addEventListener('click', () => selectCase(item.id));
    row.addEventListener('dblclick', () => openInvestigation(item.id));
    table.appendChild(row);
  });
  $('#kpiActive').textContent = active.length;
  $('#kpiAverage').textContent = Number(average).toFixed(2);
  $('#kpiCritical').textContent = cases.filter((item) => item.severity === 'critical').length;
  $('#kpiTail').textContent = cases.filter((item) => item.tail_risk).length;
}

function renderThreat(item) {
  $('#profileScore').textContent = percent(item.confidence);
  const values = [item.confidence, item.risk_score, item.impact_score, item.tail_risk ? .9 : .35, clamp((item.invariants || []).length / 6, .25, 1), clamp((item.observations || 0) / 6, .25, 1)];
  const centerX = 160, centerY = 126, radius = 92;
  const points = values.map((value, index) => {
    const angle = (-90 + index * 60) * Math.PI / 180;
    return `${(centerX + Math.cos(angle) * radius * value).toFixed(1)},${(centerY + Math.sin(angle) * radius * value).toFixed(1)}`;
  }).join(' ');
  $('#threatPolygon').setAttribute('points', points);
  const labels = {
    'INV-NET-01': 'Сетевая аномалия', 'INV-AUTH-03': 'Нарушение аутентификации', 'INV-AUTH-04': 'Недоверенная сессия',
    'INV-EDR-07': 'Подозрительный процесс', 'INV-OT-11': 'Команда управления OT', 'INV-OT-12': 'Аномалия телеметрии',
    'INV-CFG-03': 'Изменение конфигурации', 'INV-PKI-02': 'Контроль сертификата', 'INV-CAP-01': 'Ресурсный предел'
  };
  const tactics = $('#tactics');
  tactics.replaceChildren();
  (item.invariants || []).slice(0, 3).forEach((code, index) => {
    const row = document.createElement('div');
    const level = index === 0 && item.risk_score >= .75 ? 'HIGH' : item.risk_score >= .4 ? 'MED' : 'LOW';
    row.innerHTML = `<span>${escapeHtml(code)}</span><b>${escapeHtml(labels[code] || 'Нарушение инварианта')}</b><em>${level}</em>`;
    tactics.appendChild(row);
  });
}

function selectCase(id) {
  const item = cases.find((entry) => entry.id === id);
  if (!item) return;
  selectedCaseId = item.id;
  $$('.incident-table button.tr').forEach((row) => row.classList.toggle('selected', row.dataset.id === id));
  const score = Math.round(clamp(item.risk_score, 0, 1) * 100);
  $('#caseCode').textContent = item.id;
  $('#riskValue').textContent = score;
  $('#riskDial').style.setProperty('--score', score);
  $('#riskDial').style.setProperty('--dial-color', score >= 75 ? '#ff4d62' : score >= 40 ? '#ffb323' : '#20d4f4');
  $('#caseTitle').textContent = item.title;
  $('#caseDescription').textContent = item.xai_summary || 'ТАКТ формирует объяснение по доступному контексту.';
  $('#countdown').textContent = formatSla(item);
  $('.critical-label').textContent = severityMeta(item.severity)[1];
  $('#recommendation').textContent = recommendation(item);
  setMetric('#contextMetric', 45 + (item.observations || 0) * 6 + (item.invariants || []).length * 3);
  setMetric('#confidenceMetric', Number(item.confidence || 0) * 100);
  setMetric('#impactMetric', Number(item.impact_score || 0) * 100);
  $('#currentRisk').textContent = Number(item.risk_score || 0).toFixed(2);
  $('#riskDelta').textContent = `${item.observations || 0} наблюд. · ТАКТ`;
  const button = $('#acceptButton');
  button.classList.toggle('accepted', item.status === 'investigating');
  button.textContent = item.status === 'investigating' ? '✓ В РАБОТЕ' : item.status === 'resolved' ? '✓ ЗАКРЫТ' : 'ПРИНЯТЬ В РАБОТУ';
  button.disabled = item.status === 'resolved';
  renderThreat(item);
}

function renderCases(nextCases) {
  cases = [...nextCases].sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
  if (!selectedCaseId || !cases.some((item) => item.id === selectedCaseId)) selectedCaseId = cases[0]?.id || null;
  renderQueue();
  if (selectedCaseId) selectCase(selectedCaseId);
}

function renderSources(payload) {
  const items = payload?.items || [];
  const groups = { EDR: 0, SIEM: 0, NDR: 0, OT: 0 };
  items.forEach((event) => {
    const source = String(event.source_class || '').toLowerCase();
    if (/edr|audit|endpoint|windows/.test(source)) groups.EDR += 1;
    else if (/netflow|ndr|dns/.test(source)) groups.NDR += 1;
    else if (/iec|modbus|snmp|plc|ot/.test(source)) groups.OT += 1;
    else groups.SIEM += 1;
  });
  Object.entries(groups).forEach(([key, value]) => {
    const card = $(`[data-source="${key}"]`);
    card.querySelector('strong').textContent = number(value);
    card.querySelector('em').textContent = value ? 'ONLINE' : 'ОЖИДАНИЕ';
  });
  $('#eventCount').textContent = number(payload?.total_count ?? items.length);
  $('#sourcesStatus').innerHTML = `<i></i> ${items.length ? '4 КЛАССА ДАННЫХ' : 'ОЖИДАНИЕ ДАННЫХ'}`;
}

function renderSourcesFromCases(caseItems) {
  const groups = { EDR: 0, SIEM: 0, NDR: 0, OT: 0 };
  let observations = 0;
  caseItems.forEach((item) => {
    const weight = Math.max(1, Number(item.observations || 0));
    const codes = (item.invariants || []).join(' ');
    const entities = (item.findings || []).map((entry) => entry.entity_id).join(' ');
    observations += Number(item.observations || 0);
    groups.SIEM += weight;
    if (/EDR|AUTH/.test(codes)) groups.EDR += weight;
    if (/NET/.test(codes)) groups.NDR += weight;
    if (/OT|plc|hmi|iec/i.test(`${codes} ${entities}`)) groups.OT += weight;
  });
  Object.entries(groups).forEach(([key, value]) => {
    const card = $(`[data-source="${key}"]`);
    card.querySelector('strong').textContent = number(value);
    card.querySelector('em').textContent = value ? 'ONLINE' : 'ОЖИДАНИЕ';
  });
  $('#eventCount').textContent = number(observations);
  $('#sourcesStatus').innerHTML = '<i></i> ДАННЫЕ КЕЙСОВ · LIVE';
}

function renderInvestigationContext(item) {
  const [, severityLabel] = severityMeta(item.severity);
  $('#investigationSeverity').textContent = severityLabel;
  $('#investigationTitle').textContent = item.title;
  $('#investigationCode').textContent = item.id;
  $('#investigationRisk').textContent = Number(item.risk_score || 0).toFixed(2);
  $('#investigationImpact').textContent = Number(item.impact_score || 0).toFixed(2);
  $('#investigationConfidence').textContent = Number(item.confidence || 0).toFixed(2);
  $('#investigationXai').textContent = item.xai_summary || 'Объяснение по кейсу отсутствует.';
  const falsifiers = $('#falsifierList');
  falsifiers.replaceChildren();
  const checks = item.falsifiers?.length ? item.falsifiers : ['Подтвердить легитимность активности у владельца актива', 'Проверить наличие согласованного окна работ'];
  checks.forEach((text) => {
    const li = document.createElement('li');
    li.textContent = text;
    falsifiers.appendChild(li);
  });
  renderInvestigationFindings(item);
}

function renderInvestigationFindings(item) {
  const findings = item.findings || [];
  $('#findingCount').textContent = findings.length;
  const list = $('#findingList');
  list.replaceChildren();
  if (!findings.length) {
    const empty = document.createElement('div');
    empty.className = 'finding-empty';
    empty.textContent = 'Находки ещё не зафиксированы';
    list.appendChild(empty);
    return;
  }
  findings.forEach((finding) => {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'finding-item';
    row.innerHTML = `<small>${escapeHtml(finding.entity_type)}</small><b>${escapeHtml(finding.entity_id)}</b>`;
    row.addEventListener('click', () => loadEntity(finding.entity_type, finding.entity_id));
    list.appendChild(row);
  });
}

// ---------------------------------------------------------------------------
// Пост-ML разбор: что осталось после автоматики, гипотеза, уровни сущности,
// вердикт с выводами. Пользователь ТАКТ — опытный аналитик, который получает
// инцидент уже после отработки ML-контура.
// ---------------------------------------------------------------------------

// МОДЕЛЬ, а не интеграция: реального обмена с MaxPatrol O2 нет. Считаем, что
// правилами SIEM закрываются сетевые, аутентификационные и сигнатурные
// срабатывания; остальное автоматика оставляет аналитику.
const SIEM_COVERED_PREFIXES = ['INV-NET', 'INV-AUTH', 'INV-MAL', 'INV-SIG'];
const OT_SOURCE_PATTERN = /iec|modbus|opc|scada|\bot\b|plc/;

// Источник класса `ot` описывает защищаемый контур за пределами корпоративной
// сети. В промышленном сценарии это АСУ ТП, в SOC-сценарии — целостность
// сборки и релиза. Формулировки подстраиваются, чтобы не называть конвейер
// сборки технологическим сегментом.
function protectedZone(events) {
  const assets = events
    .filter((event) => OT_SOURCE_PATTERN.test(String(event.source_class || '').toLowerCase()))
    .map((event) => String(event.host_id || ''));
  if (!assets.length) return null;
  const build = assets.some((asset) => asset.startsWith('artifact:') || asset.startsWith('pipeline:'));
  return build
    ? { name: 'конвейер сборки и релиза', short: 'конвейер сборки', asset: assets[0] }
    : { name: 'технологический сегмент', short: 'технологический сегмент', asset: assets[0] };
}

function o2Handoff(item, events) {
  const invariants = (item.invariants || []).map(String);
  const closed = invariants.filter((inv) => SIEM_COVERED_PREFIXES.some((prefix) => inv.startsWith(prefix)));
  const open = invariants.filter((inv) => !closed.includes(inv));
  const classes = [...new Set(events.map((event) => String(event.source_class || '').toLowerCase()).filter(Boolean))];
  const otClasses = classes.filter((name) => OT_SOURCE_PATTERN.test(name));

  const reasons = [];
  if (open.length) reasons.push(`${open.length} инвариант${open.length === 1 ? '' : 'а'} вне правил SIEM: ${open.join(', ')}`);
  const zoneForHandoff = protectedZone(events);
  if (otClasses.length) reasons.push(`телеметрия защищаемого контура — ${zoneForHandoff ? zoneForHandoff.name : 'вне SIEM'} (${otClasses.join(', ')}) — не входит в модель SIEM`);
  if (classes.length > 1) reasons.push(`связь ${classes.length} классов источников установлена корреляцией, а не одиночным правилом`);
  if (item.tail_risk) reasons.push('хвостовой риск: редкое сочетание признаков вне обучающей выборки');

  return { closed, open, classes, otClasses, reasons, handedOver: reasons.length > 0 };
}

function buildHypothesis(item, events) {
  const chain = deriveAttackChain(events);
  const entry = chain.nodes[0];
  const target = chain.nodes[chain.nodes.length - 1];
  const otEvent = events.find((event) => OT_SOURCE_PATTERN.test(String(event.source_class || '').toLowerCase()));
  const zone = protectedZone(events);

  const statement = entry && target && entry.id !== target.id
    ? `Точка входа — ${entry.label}; активность прошла по цепочке и достигла ${target.label}${zone ? ` в защищаемом контуре (${zone.short})` : ''}.`
    : `Активность сосредоточена на ${mainEntity(item)}; цепочка пока не восстановлена.`;

  const basis = [];
  if (chain.nodes.length > 1) basis.push(`Цепочка из ${chain.nodes.length} сущностей связана корреляцией ТАКТ`);
  if (zone) basis.push(`Достигнут ${zone.name}: ${zone.asset || otEvent?.host_id || 'защищаемый объект'}`);
  if (item.tail_risk) basis.push('Отмечен хвостовой риск — редкое сочетание признаков');
  if ((item.invariants || []).length) basis.push(`Сработали инварианты: ${item.invariants.join(', ')}`);
  if (!basis.length) basis.push('Оснований пока недостаточно — требуется сбор контекста');

  return { statement, basis, chain };
}

const ENTITY_LEVELS = [
  { key: 'address', label: 'Сетевой адрес', hint: 'откуда пришло' },
  { key: 'host', label: 'Узел', hint: 'где произошло' },
  { key: 'user', label: 'Учётная запись', hint: 'кто действовал' },
  { key: 'process', label: 'Процесс', hint: 'чем действовал' },
  { key: 'artifact', label: 'Артефакт', hint: 'что оставило след' },
];

function entityLevels(item, events) {
  const buckets = new Map(ENTITY_LEVELS.map((level) => [level.key, new Set()]));
  const put = (type, value) => { if (value && buckets.has(type)) buckets.get(type).add(String(value)); };
  events.forEach((event) => {
    put('address', event.address);
    put('host', event.host_id);
    put('user', event.user_id);
    put('process', event.process);
    put('artifact', event.artifact);
  });
  (item.findings || []).forEach((finding) => put(finding.entity_type, finding.entity_id));
  return ENTITY_LEVELS.map((level) => ({ ...level, values: [...buckets.get(level.key)] }));
}

function buildVerdict(item, events) {
  const score = Number(item.risk_score || 0);
  const handoff = o2Handoff(item, events);
  const levels = entityLevels(item, events).filter((level) => level.values.length);
  const zoneReached = protectedZone(events);

  let verdict = 'ОТКЛОНЕНИЕ БЕЗ ПРИЗНАКОВ АТАКИ';
  let tone = 'quiet';
  if (score >= 0.75) { verdict = 'ПОДТВЕРЖДЁННЫЙ ИНЦИДЕНТ'; tone = 'critical'; }
  else if (score >= 0.4) { verdict = 'ТРЕБУЕТ ПРОВЕРКИ АНАЛИТИКОМ'; tone = 'warning'; }

  const conclusions = [];
  if (handoff.handedOver) conclusions.push(`Автоматика закрыла ${handoff.closed.length} из ${handoff.closed.length + handoff.open.length} признаков; остальное разобрано в ТАКТ.`);
  if (levels.length > 1) {
    const word = levels.length % 10 === 1 && levels.length % 100 !== 11 ? 'уровень'
      : [2, 3, 4].includes(levels.length % 10) && ![12, 13, 14].includes(levels.length % 100) ? 'уровня' : 'уровней';
    conclusions.push(`Разбор охватил ${levels.length} ${word} сущностей: ${levels.map((level) => level.label.toLowerCase()).join(' → ')}.`);
  }
  if (zoneReached) conclusions.push(`Активность вышла за пределы рабочих станций и затронула ${zoneReached.name} — приоритет по импакту.`);
  conclusions.push(`Совокупная оценка: риск ${score.toFixed(2)}, импакт ${Number(item.impact_score || 0).toFixed(2)}, доверие ${Number(item.confidence || 0).toFixed(2)}.`);

  // Варианты, а не единственное предписание: выбор остаётся за аналитиком.
  // Состав вариантов выводится из того, какие сущности затронуты инцидентом,
  // поэтому одни и те же правила дают разные наборы для разных сценариев.
  const findings = item.findings || [];
  const findingOf = (type) => findings.find((entry) => entry.entity_type === type)?.entity_id;
  const account = findingOf('account') || events.map((event) => event.user_id).find(Boolean);
  const external = findingOf('address')
    || events.map((event) => event.address).find((value) => value && !String(value).startsWith('10.'));
  const pipeline = findingOf('repo') || findingOf('pipeline');
  const options = [];

  if (score >= 0.75) {
    options.push({ code: 'isolate', title: `Изолировать ${mainEntity(item)}`, effect: 'Прерывает цепочку немедленно. Узел теряет связь — согласовать с владельцем актива.' });
    if (account) options.push({ code: 'reset', title: `Сбросить учётную запись ${account}`, effect: 'Обрывает доступ, полученный атакующим. Сервисная запись может остановить зависимые задания.' });
    if (external) options.push({ code: 'block', title: `Заблокировать внешний адрес ${external}`, effect: 'Закрывает управляющий канал на периметре. Не удаляет закрепление на узле.' });
    if (pipeline) options.push({ code: 'freeze', title: `Заморозить конвейер ${pipeline}`, effect: 'Останавливает распространение неподписанного артефакта в релиз. Задержит выпуск сборки.' });
  } else if (score >= 0.4) {
    options.push({ code: 'verify', title: 'Подтвердить легитимность у владельца актива', effect: 'Отделяет плановые работы от инцидента без вмешательства в процесс.' });
    if (account) options.push({ code: 'restrict', title: `Ограничить ${account} и наблюдать`, effect: 'Применяется, если владелец не подтвердил работы.' });
  } else {
    options.push({ code: 'observe', title: 'Наблюдение с фиксацией baseline', effect: 'Отклонение фиксируется без действий; при повторе кейс поднимется автоматически.' });
  }
  options.push({ code: 'handover', title: 'Передать в смену с пакетом доказательств', effect: 'Контекст, находки и цепочка передаются следующему аналитику без потери.' });

  return { verdict, tone, conclusions, options, handoff };
}

function renderO2Handoff(item, events) {
  const handoff = o2Handoff(item, events);
  $('#handoffClosed').textContent = handoff.closed.length;
  $('#handoffOpen').textContent = handoff.open.length;
  $('#handoffClosedList').textContent = handoff.closed.length
    ? handoff.closed.join(' · ')
    : 'нет срабатываний, закрываемых правилами SIEM';
  const list = $('#handoffReasons');
  list.replaceChildren();
  const reasons = handoff.handedOver
    ? handoff.reasons
    : ['Признаков за пределами правил SIEM не обнаружено — кейс закрывается автоматикой.'];
  reasons.forEach((text) => {
    const li = document.createElement('li');
    li.textContent = text;
    list.appendChild(li);
  });
  $('#handoffState').textContent = handoff.handedOver ? 'ТРЕБУЕТ АНАЛИТИКА' : 'ЗАКРЫТО АВТОМАТИКОЙ';
  $('#handoffState').className = `handoff-state ${handoff.handedOver ? 'open' : 'closed'}`;
}

function renderHypothesis(item, events) {
  const hypothesis = buildHypothesis(item, events);
  $('#hypothesisStatement').textContent = hypothesis.statement;
  const basis = $('#hypothesisBasis');
  basis.replaceChildren();
  hypothesis.basis.forEach((text) => {
    const li = document.createElement('li');
    li.textContent = text;
    basis.appendChild(li);
  });
}

function renderEntityLevels(item, events) {
  const levels = entityLevels(item, events);
  const container = $('#entityLevels');
  container.replaceChildren();
  levels.forEach((level, index) => {
    const row = document.createElement('div');
    const filled = level.values.length > 0;
    row.className = `level-row${filled ? '' : ' empty'}`;
    row.innerHTML = `<i>${index + 1}</i><div><small>${escapeHtml(level.label)} · ${escapeHtml(level.hint)}</small><b>${filled ? escapeHtml(level.values.slice(0, 2).join(', ')) : 'нет данных на этом уровне'}</b></div><em>${level.values.length}</em>`;
    if (filled) {
      row.tabIndex = 0;
      row.setAttribute('role', 'button');
      const open = () => loadEntity(level.key, level.values[0]);
      row.addEventListener('click', open);
      row.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(); } });
    }
    container.appendChild(row);
  });
  const reached = levels.filter((level) => level.values.length).length;
  $('#levelReach').textContent = `${reached} из ${levels.length}`;
}

function renderVerdict(item, events) {
  const result = buildVerdict(item, events);
  const badge = $('#verdictBadge');
  badge.textContent = result.verdict;
  badge.className = `verdict-badge ${result.tone}`;
  // Дубль в шапке: вердикт должен быть виден без прокрутки колонки разбора.
  const chip = $('#verdictChip');
  if (chip) {
    chip.textContent = result.verdict;
    chip.className = `verdict-chip ${result.tone}`;
  }
  const conclusions = $('#verdictConclusions');
  conclusions.replaceChildren();
  result.conclusions.forEach((text) => {
    const li = document.createElement('li');
    li.textContent = text;
    conclusions.appendChild(li);
  });
  const options = $('#verdictOptions');
  options.replaceChildren();
  result.options.forEach((option) => {
    const row = document.createElement('article');
    row.className = 'verdict-option';
    row.innerHTML = `<b>${escapeHtml(option.title)}</b><p>${escapeHtml(option.effect)}</p>`;
    options.appendChild(row);
  });
}

// Метрика заказчика — время разбора инцидента: от передачи аналитику до вердикта.
let investigationStartedAt = 0;
let investigationTimer = null;

function renderInvestigationElapsed() {
  if (!investigationStartedAt) return;
  const seconds = Math.max(0, Math.round((Date.now() - investigationStartedAt) / 1000));
  const value = `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
  const target = $('#investigationElapsed');
  if (target) target.textContent = value;
}

function startInvestigationTimer() {
  investigationStartedAt = Date.now();
  renderInvestigationElapsed();
  if (investigationTimer) clearInterval(investigationTimer);
  investigationTimer = setInterval(renderInvestigationElapsed, 1000);
}

function stopInvestigationTimer() {
  if (investigationTimer) clearInterval(investigationTimer);
  investigationTimer = null;
  investigationStartedAt = 0;
}

// Раскладка узлов графа. При длинной цепочке (десятки сущностей) размещение в
// одну линию давало наложение кругов, поэтому узлы переносятся на несколько
// рядов «змейкой»: порядок обхода сохраняется, подписи не сливаются.
const GRAPH_MAX_PER_ROW = 7;

function nodePosition(index, total) {
  if (total <= 1) return { x: 450, y: 250 };
  const perRow = Math.min(total, GRAPH_MAX_PER_ROW);
  const rows = Math.ceil(total / perRow);
  const row = Math.floor(index / perRow);
  const inRow = index % perRow;
  const rowCount = row === rows - 1 ? total - perRow * row : perRow;
  const step = rowCount > 1 ? 690 / (rowCount - 1) : 0;
  const x = rowCount > 1 ? 105 + inRow * step : 450;
  const rowGap = rows > 1 ? Math.min(150, 380 / rows) : 0;
  const top = 250 - ((rows - 1) * rowGap) / 2;
  return { x, y: top + row * rowGap };
}

function shortText(value, max = 24) {
  const textValue = String(value || '');
  return textValue.length > max ? `${textValue.slice(0, max - 1)}…` : textValue;
}

function renderAttackGraph(chain) {
  const svg = $('#attackGraph');
  const nodes = chain?.nodes || [];
  const positions = new Map(nodes.map((node, index) => [node.id, nodePosition(index, nodes.length)]));
  const parts = ['<defs><marker id="graphArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path class="graph-arrow" d="M0 0 10 5 0 10Z"/></marker></defs>'];
  (chain?.edges || []).forEach((edge) => {
    const source = positions.get(edge.source), target = positions.get(edge.target);
    if (!source || !target) return;
    const middleX = (source.x + target.x) / 2, middleY = (source.y + target.y) / 2 - 15;
    parts.push(`<path class="attack-edge-glow" d="M${source.x + 34} ${source.y} C${middleX} ${source.y},${middleX} ${target.y},${target.x - 34} ${target.y}"/>`);
    parts.push(`<path class="attack-edge" marker-end="url(#graphArrow)" d="M${source.x + 34} ${source.y} C${middleX} ${source.y},${middleX} ${target.y},${target.x - 34} ${target.y}"/>`);
    parts.push(`<text class="edge-label" x="${middleX}" y="${middleY}">${escapeHtml(shortText(edge.correlation_reason, 38))}</text>`);
  });
  nodes.forEach((node, index) => {
    const point = positions.get(node.id);
    const type = ['address','user','artifact','host','process'].includes(node.type) ? node.type : 'process';
    parts.push(`<g class="attack-node ${type}" data-entity-type="${escapeHtml(node.type)}" data-entity-id="${escapeHtml(node.label)}" transform="translate(${point.x} ${point.y})"><circle r="33"/><circle r="25" fill="none" opacity=".25"/><text class="node-type" y="-3">${escapeHtml(node.type.toUpperCase())}</text><text y="55">${escapeHtml(shortText(node.label, 22))}</text></g>`);
  });
  svg.innerHTML = parts.join('');
  svg.querySelectorAll('.attack-node').forEach((node) => node.addEventListener('click', () => loadEntity(node.dataset.entityType, node.dataset.entityId)));
  $('#graphPane .pane-loading').classList.add('hidden');
}

function eventPrimaryEntity(event) {
  if (event.artifact) return { type: 'artifact', id: event.artifact };
  if (event.process) return { type: 'process', id: event.process };
  if (event.user_id) return { type: 'user', id: event.user_id };
  if (event.host_id) return { type: 'host', id: event.host_id };
  return { type: 'address', id: event.address };
}

function eventSummary(event) {
  return [event.host_id, event.user_id, event.process, event.address, event.artifact].filter(Boolean).join(' · ');
}

function graphEntityForEvent(event) {
  const source = String(event.source_class || '').toLowerCase();
  if (/netflow|ndr|firewall/.test(source) && event.address) return { type: 'address', id: event.address };
  if (/syslog|auth/.test(source) && event.user_id) return { type: 'user', id: event.user_id };
  if (/endpoint|edr/.test(source) && event.artifact) return { type: 'artifact', id: event.artifact };
  if (/iec|modbus|snmp|ot/.test(source) && event.host_id) return { type: 'host', id: event.host_id };
  return eventPrimaryEntity(event);
}

function deriveAttackChain(events) {
  const nodes = [];
  events.forEach((event) => {
    const entity = graphEntityForEvent(event);
    const id = `${entity.type}:${entity.id}`;
    if (!nodes.some((node) => node.id === id)) nodes.push({ id, type: entity.type, label: entity.id, severity: event.severity });
  });
  const edges = nodes.slice(0, -1).map((node, index) => ({
    id: `derived-edge-${index}`,
    source: node.id,
    target: nodes[index + 1].id,
    correlation_reason: `${String(events[index]?.source_class || 'событие').toUpperCase()} → ${String(events[index + 1]?.source_class || 'событие').toUpperCase()} · временная и контекстная связь`,
  }));
  return { nodes, edges };
}

function renderInvestigationEvents(events) {
  investigationEvents = events;
  $('#eventTotal').textContent = `${events.length} событий`;
  const timeline = $('#timelineList');
  const table = $('#workspaceEvents');
  timeline.replaceChildren();
  table.replaceChildren();
  events.forEach((event) => {
    const entity = eventPrimaryEntity(event);
    const date = new Date(event.ts);
    const time = Number.isNaN(date.valueOf()) ? event.ts : date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const timelineRow = document.createElement('article');
    timelineRow.className = `timeline-event ${event.severity || ''}`;
    timelineRow.innerHTML = `<time>${escapeHtml(time)}</time><div class="timeline-marker"><i></i></div><div class="timeline-card"><header><strong>${escapeHtml(event.source_class.toUpperCase())} · ${escapeHtml(event.host_id || entity.id)}</strong><span>${escapeHtml(event.severity || 'info')}</span></header><p>${escapeHtml(eventSummary(event))}</p></div>`;
    timelineRow.addEventListener('click', () => loadEntity(entity.type, entity.id));
    timeline.appendChild(timelineRow);
    const eventRow = document.createElement('div');
    eventRow.className = 'workspace-event';
    eventRow.innerHTML = `<time>${escapeHtml(time)}</time><span>${escapeHtml(event.source_class)}</span><b>${escapeHtml(eventSummary(event))}</b><em>${escapeHtml(event.severity || 'info')}</em>`;
    eventRow.addEventListener('click', () => loadEntity(entity.type, entity.id));
    table.appendChild(eventRow);
  });
}

function packageEntities(item, events) {
  const entities = new Map();
  const add = (type, id, source, severity = 'context') => {
    if (!id || !['host','artifact','address','process'].includes(type)) return;
    const key = `${type}:${id}`;
    const previous = entities.get(key);
    entities.set(key, { type, id, source: previous ? `${previous.source}, ${source}` : source, severity: previous?.severity === 'critical' ? 'critical' : severity });
  };
  (item.findings || []).forEach((finding) => add(finding.entity_type, finding.entity_id, 'finding'));
  events.forEach((event) => {
    add('host', event.host_id, event.source_class, event.severity);
    add('artifact', event.artifact, event.source_class, event.severity);
    add('address', event.address, event.source_class, event.severity);
    add('process', event.process, event.source_class, event.severity);
  });
  return [...entities.values()];
}

function updatePackageCount() {
  const selected = $$('.package-entity input:checked').length;
  $('#packageCount').textContent = selected;
}

function renderResponsePackage(item, events) {
  const entities = packageEntities(item, events);
  $('#packageCaseCode').textContent = item.id;
  const counts = ['host','artifact','address','process'].map((type) => ({ type, count: entities.filter((entry) => entry.type === type).length }));
  const labels = { host:'УЗЛЫ', artifact:'ФАЙЛЫ', address:'АДРЕСА', process:'ПРОЦЕССЫ' };
  $('#packageSummary').innerHTML = counts.map(({ type, count }) => `<div class="package-stat"><small>${labels[type]}</small><strong>${count}</strong></div>`).join('');
  const list = $('#packageEntities');
  list.replaceChildren();
  entities.forEach((entity, index) => {
    const label = document.createElement('label');
    label.className = 'package-entity';
    const checked = ['host','artifact','address'].includes(entity.type);
    label.innerHTML = `<input type="checkbox" ${checked ? 'checked' : ''} data-entity-type="${escapeHtml(entity.type)}" data-entity-id="${escapeHtml(entity.id)}" data-source="${escapeHtml(entity.source)}"><span>${escapeHtml(labels[entity.type] || entity.type)}</span><b>${escapeHtml(entity.id)}</b><em>${escapeHtml(entity.severity || `объект ${index + 1}`)}</em>`;
    label.querySelector('input').addEventListener('change', updatePackageCount);
    list.appendChild(label);
  });
  $('#responseNote').value = '';
  updatePackageCount();
}

function collectResponsePackage() {
  const item = cases.find((entry) => entry.id === selectedCaseId);
  const entities = $$('.package-entity input:checked').map((input) => ({
    type: input.dataset.entityType,
    id: input.dataset.entityId,
    source: input.dataset.source,
  }));
  return {
    schema: 'takt.response-package.v1',
    created_at: new Date().toISOString(),
    case_id: item?.id,
    case_title: item?.title,
    risk: item?.risk_score,
    impact: item?.impact_score,
    confidence: item?.confidence,
    action: $('#responseAction').value,
    rationale: $('#responseNote').value.trim(),
    entities,
    operator: OPERATOR_ID,
    human_confirmed: true,
    execution: 'not_performed',
    notice: 'Критичные действия автоматически не выполнялись. Пакет подготовлен для проверки аналитиком и передачи в EDR/SOAR.',
  };
}

function saveFile(name, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function downloadResponsePackage() {
  const data = collectResponsePackage();
  if (!data.entities.length) {
    showToast('Пакет пуст', 'Выберите хотя бы одну сущность для реагирования', true);
    return;
  }
  saveFile(`${data.case_id}-response-package.json`, JSON.stringify(data, null, 2), 'application/json;charset=utf-8');
  showToast('Пакет подготовлен', `${data.entities.length} сущностей · исполнение не запускалось`);
}

function downloadIncidentReport() {
  const item = cases.find((entry) => entry.id === selectedCaseId);
  const data = collectResponsePackage();
  const eventLines = investigationEvents.map((event) => `- ${event.ts} [${event.source_class}] ${eventSummary(event)}`).join('\n');
  const entityLines = data.entities.map((entity) => `- ${entity.type}: ${entity.id} (${entity.source})`).join('\n');
  const report = `ОТЧЁТ ПО ИНЦИДЕНТУ ТАКТ\n\nКейс: ${item?.id}\nНазвание: ${item?.title}\nРиск: ${item?.risk_score}  Импакт: ${item?.impact_score}  Доверие: ${item?.confidence}\nСтатус: ${item?.status}\nСформирован: ${new Date().toLocaleString('ru-RU')}\nОператор: ${OPERATOR_ID}\n\nОБЪЯСНЕНИЕ ТАКТ\n${item?.xai_summary || '—'}\n\nХРОНОЛОГИЯ\n${eventLines || '—'}\n\nПАКЕТ РЕАГИРОВАНИЯ\nДействие: ${data.action}\nОбоснование: ${data.rationale || 'не указано'}\n${entityLines || 'сущности не выбраны'}\n\nКОНТРОЛЬ HUMAN-IN-THE-LOOP\nАвтоматическое исполнение критичных действий не выполнялось. Решение и передача пакета остаются за аналитиком.\n`;
  saveFile(`${item?.id}-incident-report.txt`, `\uFEFF${report}`, 'text/plain;charset=utf-8');
  showToast('Отчёт сформирован', 'Описание инцидента и решения выгружено в TXT');
}

function renderBaseline(baseline) {
  const values = baseline?.z_scores || [];
  const min = -3, max = 7;
  const points = values.map((value, index) => {
    const x = values.length <= 1 ? 150 : index * (300 / (values.length - 1));
    const y = 100 - ((clamp(Number(value), min, max) - min) / (max - min)) * 100;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  $('#baselineLine').setAttribute('points', points || '0,50 300,50');
  $('#baselineMean').textContent = Number(baseline?.mean || 0).toFixed(2);
  $('#baselineStd').textContent = Number(baseline?.stddev || 0).toFixed(2);
  const peak = values.length ? Math.max(...values.map((value) => Math.abs(Number(value) || 0))) : 0;
  const typicality = Math.round(clamp(100 - peak / 6.4 * 100, 0, 100));
  $('#entityTypicality').textContent = `${typicality}%`;
  $('#entityVerdict').textContent = peak >= 3 ? `аномалия ${peak.toFixed(1)}σ` : peak >= 2 ? `отклонение ${peak.toFixed(1)}σ` : 'типичное поведение';
}

async function loadEntity(type, id) {
  if (!type || !id) return;
  selectedEntity = { type, id };
  $('#entityEmpty').hidden = true;
  $('#entityContent').hidden = false;
  $('#entityType').textContent = type.toUpperCase();
  $('#entityId').textContent = id;
  $('#entityTypicality').textContent = '—';
  $('#entityVerdict').textContent = 'baseline по запросу';
  $('#entityTypicality').textContent = '—';
  $('#baselineMean').textContent = '—';
  $('#baselineStd').textContent = '—';
  $('#baselineLine').setAttribute('points', '0,50 300,50');
  $('#entityIcon').textContent = ({ host:'▣', user:'●', process:'⚙', address:'◆', artifact:'▤' })[type] || '●';
  $$('.attack-node').forEach((node) => node.classList.toggle('selected', node.dataset.entityType === type && node.dataset.entityId === id));
  const relations = $('#entityRelations');
  relations.replaceChildren();
  const item = cases.find((entry) => entry.id === selectedCaseId);
  (item?.findings || []).filter((finding) => finding.entity_id !== id).slice(0, 8).forEach((finding) => {
    const chip = document.createElement('span');
    chip.textContent = `${finding.entity_type}:${finding.entity_id}`;
    relations.appendChild(chip);
  });
}

async function loadSelectedBaseline() {
  if (!selectedEntity) return;
  const { type, id } = selectedEntity;
  const button = $('#loadBaselineButton');
  button.disabled = true;
  button.textContent = 'ЗАПРОС BASELINE В ТАКТ…';
  $('#entityVerdict').textContent = 'загрузка baseline';
  try {
    const baseline = await fetchJson(`/api/v1/baseline/${encodeURIComponent(type)}/${encodeURIComponent(id)}`);
    if (selectedEntity?.type === type && selectedEntity?.id === id) renderBaseline(baseline);
    button.textContent = '✓ BASELINE ОБНОВЛЁН';
  } catch (error) {
    $('#entityVerdict').textContent = 'baseline недоступен';
    button.textContent = 'ПОВТОРИТЬ ПРОВЕРКУ BASELINE';
    showToast('Историчность недоступна', error.message, true);
  } finally {
    button.disabled = false;
  }
}

async function openInvestigation(caseId = selectedCaseId) {
  const item = cases.find((entry) => entry.id === caseId) || cases[0];
  if (!item) {
    showToast('Очередь ещё загружается', 'Повторите действие через несколько секунд', true);
    return;
  }
  selectedCaseId = item.id;
  stopPolling();
  $('#overviewHero').hidden = true;
  $('#overviewDashboard').hidden = true;
  $('#investigationView').hidden = false;
  $$('.top-tab').forEach((tab) => tab.classList.toggle('active', tab.dataset.view === 'investigation'));
  renderInvestigationContext(item);
  $('#graphPane .pane-loading').classList.remove('hidden');
  $('#attackGraph').replaceChildren();
  $('#timelineList').replaceChildren();
  $('#workspaceEvents').replaceChildren();
  $('#entityEmpty').hidden = false;
  $('#entityContent').hidden = true;
  selectedEntity = null;
  startInvestigationTimer();
  let events = [];
  try {
    events = await fetchJson(`/api/v1/cases/${encodeURIComponent(item.id)}/events`);
    const chain = deriveAttackChain(events);
    renderAttackGraph(chain);
    renderInvestigationEvents(events);
    const firstNode = chain.nodes?.[0];
    if (firstNode) loadEntity(firstNode.type, firstNode.label);
  } catch (error) {
    // Демонстрационный сценарий отрабатывает и без API: граф, таймлайн и
    // события строятся из встроенного набора INC-002.
    events = FALLBACK_EVENTS[item.id] || [];
    if (events.length) {
      const chain = deriveAttackChain(events);
      renderAttackGraph(chain);
      renderInvestigationEvents(events);
      const firstNode = chain.nodes?.[0];
      if (firstNode) loadEntity(firstNode.type, firstNode.label);
      setChannel('offline', 'демонстрационный сценарий');
    } else {
      $('#graphPane .pane-loading').textContent = `Данные расследования недоступны · ${error.message}`;
      showToast('Не удалось открыть расследование', error.message, true);
    }
  }
  // Разбор строится и без потока событий: гипотеза, уровни и вердикт опираются
  // на сам кейс, поэтому панели не остаются пустыми при недоступном источнике.
  renderResponsePackage(item, events);
  renderO2Handoff(item, events);
  renderHypothesis(item, events);
  renderEntityLevels(item, events);
  renderVerdict(item, events);
}

function closeInvestigation() {
  stopInvestigationTimer();
  $('#investigationView').hidden = true;
  $('#overviewHero').hidden = false;
  $('#overviewDashboard').hidden = false;
  $$('.top-tab').forEach((tab) => tab.classList.toggle('active', tab.dataset.view === 'situation'));
  if (!pollTimer) pollTimer = setInterval(refreshData, POLL_MS);
  refreshData();
}

async function addSelectedFinding() {
  if (!selectedEntity || !selectedCaseId) return;
  const button = $('#addFindingButton');
  button.disabled = true;
  button.textContent = 'ФИКСАЦИЯ В ТАКТ…';
  try {
    await fetchJson('/api/v1/findings', { method: 'POST', body: JSON.stringify({ case_id: selectedCaseId, entity_type: selectedEntity.type, entity_id: selectedEntity.id }) });
    const item = cases.find((entry) => entry.id === selectedCaseId);
    if (item && !(item.findings || []).some((finding) => finding.entity_type === selectedEntity.type && finding.entity_id === selectedEntity.id)) {
      item.findings = [...(item.findings || []), { id: `local-${Date.now()}`, entity_type: selectedEntity.type, entity_id: selectedEntity.id }];
    }
    renderInvestigationFindings(item);
    showToast('Находка сохранена', `${selectedEntity.type}:${selectedEntity.id} привязана к кейсу ТАКТ`);
    button.textContent = '✓ ДОБАВЛЕНО В ЖУРНАЛ';
  } catch (error) {
    showToast('Находка не сохранена', error.message, true);
    button.disabled = false;
    button.textContent = '+ ДОБАВИТЬ В ЖУРНАЛ НАХОДОК';
  }
}

function setChannel(state, detail = '') {
  const channel = $('#channelStatus');
  const states = {
    connecting: 'API · ПОДКЛЮЧЕНИЕ', live: 'LIVE · SSE', polling: 'POLL · РЕЗЕРВ', stale: 'STALE · НЕТ ДАННЫХ', offline: 'OFFLINE'
  };
  channel.className = `live ${state}`;
  channel.innerHTML = `<i></i> ${states[state] || state}`;
  $('#systemState').innerHTML = `<i class="ok-dot"></i> ${state === 'live' ? 'Данные программы ТАКТ актуальны' : state === 'polling' ? 'ТАКТ доступен через резервный опрос' : state === 'offline' ? `Нет связи с ТАКТ${detail ? ` · ${escapeHtml(detail)}` : ''}` : 'Подключение к программе ТАКТ'}`;
}

async function fetchJson(path, options) {
  const started = performance.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 6500);
  const request = { cache: 'no-store', signal: controller.signal, ...options };
  if (options?.body) request.headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  try {
    const response = await fetch(`${API_BASE}${path}`, request);
    $('#latency').textContent = `${Math.round(performance.now() - started)} мс`;
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try { message = (await response.json()).detail || message; } catch { /* response without JSON */ }
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    return response.status === 204 ? null : response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function refreshData({ initial = false } = {}) {
  if (refreshInFlight) return;
  refreshInFlight = true;
  try {
    // Последовательно: стенд ТАКТ обслуживает тяжёлую выдачу raw-events и список
    // кейсов одним demo-worker; параллельные запросы могут удерживать второй ответ.
    const caseData = await fetchJson('/api/v1/cases');
    renderCases(caseData);
    // Состав источников рассчитывается из observations/invariants/findings кейсов.
    // Это те же данные ТАКТ, но без тяжёлого raw-events запроса, блокирующего SSE
    // на однопроцессном демонстрационном backend.
    renderSourcesFromCases(caseData);
    lastActivity = Date.now();
    $('#lastSync').textContent = formatAge();
    if (!window.__sseLive) setChannel('polling');
  } catch (error) {
    if (initial && !cases.length) renderCases(FALLBACK_CASES);
    setChannel('offline', error.message);
  } finally {
    refreshInFlight = false;
  }
}

function startPolling() {
  if (pollTimer) return;
  setChannel('polling');
  refreshData();
  pollTimer = setInterval(refreshData, POLL_MS);
}

function stopPolling() {
  clearInterval(pollTimer);
  pollTimer = null;
}

function connectStream() {
  if (!('EventSource' in window) || location.protocol === 'file:') {
    startPolling();
    return;
  }
  setChannel('connecting');
  const stream = new EventSource(`${API_BASE}/api/v1/stream/cases`);
  stream.onopen = () => {
    window.__sseLive = true;
    lastActivity = Date.now();
    stopPolling();
    setChannel('live');
  };
  stream.onmessage = (event) => {
    lastActivity = Date.now();
    try {
      const incoming = JSON.parse(event.data);
      const next = cases.filter((item) => item.id !== incoming.id);
      renderCases([...next, incoming]);
    } catch { /* malformed chaos payload is ignored */ }
  };
  stream.addEventListener('heartbeat', () => {
    window.__sseLive = true;
    lastActivity = Date.now();
    stopPolling();
    setChannel('live');
  });
  stream.onerror = () => {
    window.__sseLive = false;
    startPolling();
  };
}

function showToast(title, message, danger = false) {
  const toast = $('#toast');
  toast.classList.toggle('danger', danger);
  toast.querySelector('b').textContent = title;
  toast.querySelector('span').textContent = message;
  toast.classList.add('show');
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove('show'), 3400);
}

async function acceptSelectedCase() {
  const item = cases.find((entry) => entry.id === selectedCaseId);
  if (!item || item.status === 'investigating' || item.status === 'resolved') return;
  const button = $('#acceptButton');
  button.disabled = true;
  button.textContent = 'ЗАХВАТ КЕЙСА…';
  try {
    await fetchJson(`/api/v1/cases/${encodeURIComponent(item.id)}/lock`, { method: 'POST', body: JSON.stringify({ operator: OPERATOR_ID }) });
    const updated = await fetchJson(`/api/v1/cases/${encodeURIComponent(item.id)}`, { method: 'PATCH', body: JSON.stringify({ status: 'investigating' }) });
    renderCases(cases.map((entry) => entry.id === updated.id ? updated : entry));
    showToast('Кейс принят в работу', `Лок ТАКТ установлен за ${OPERATOR_ID}`);
  } catch (error) {
    button.disabled = false;
    button.textContent = 'ПРИНЯТЬ В РАБОТУ';
    showToast(error.status === 409 ? 'Кейс уже занят' : 'Действие не выполнено', error.message, true);
  }
}

$$('.mode').forEach((button) => button.addEventListener('click', () => setSegmentMode(button.dataset.mode, true)));
$$('.top-tab').forEach((button) => button.addEventListener('click', () => {
  if (button.dataset.view === 'investigation') openInvestigation();
  else if (button.dataset.view === 'situation') closeInvestigation();
  else showToast(button.textContent, 'Раздел будет подключён на следующем этапе MVP');
}));
$$('.rail-btn').forEach((button) => button.addEventListener('click', () => {
  $$('.rail-btn').forEach((item) => item.classList.remove('active'));
  button.classList.add('active');
}));
const primaryRailButtons = $$('.rail nav .rail-btn');
if (primaryRailButtons[0]) primaryRailButtons[0].addEventListener('click', closeInvestigation);
if (primaryRailButtons[1]) primaryRailButtons[1].addEventListener('click', () => openInvestigation());
$$('.period button').forEach((button) => button.addEventListener('click', () => {
  $$('.period button').forEach((item) => item.classList.remove('active'));
  button.classList.add('active');
}));
$$('.canvas-tab').forEach((button) => button.addEventListener('click', () => {
  $$('.canvas-tab').forEach((tab) => tab.classList.toggle('active', tab === button));
  $$('.canvas-pane').forEach((pane) => pane.classList.remove('active'));
  $(`#${button.dataset.canvas}Pane`).classList.add('active');
}));
$('#acceptButton').addEventListener('click', acceptSelectedCase);
$('#backToOverview').addEventListener('click', closeInvestigation);
$('#loadBaselineButton').addEventListener('click', loadSelectedBaseline);
$('#addFindingButton').addEventListener('click', addSelectedFinding);
$('#downloadPackage').addEventListener('click', downloadResponsePackage);
$('#downloadReport').addEventListener('click', downloadIncidentReport);

tickClock();
try { setSegmentMode(localStorage.getItem('takt.segment-mode') || 'normal'); } catch { setSegmentMode('normal'); }
setInterval(() => {
  tickClock();
  $('#lastSync').textContent = formatAge();
  if (window.__sseLive && lastActivity && Date.now() - lastActivity > STALE_MS) setChannel('stale');
}, 1000);
function startDataLayer() {
  // Запросы начинаются после загрузки статики: так они не делят незавершённый
  // keep-alive поток с app.js на внешнем nginx стенда.
  setTimeout(() => {
    // На демонстрационном однопроцессном контуре длинный SSE может занимать
    // worker и задерживать REST. Поэтому этот АРМ честно использует надёжный
    // резервный режим: короткий опрос каждые 10 секунд.
    refreshData({ initial: true });
    if (!pollTimer) pollTimer = setInterval(refreshData, POLL_MS);
  }, 150);
}
startDataLayer();
