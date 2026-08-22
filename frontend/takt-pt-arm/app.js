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
  // --- Вкладка «Цепочка атаки» -----------------------------------------
  simulation: {
    title: 'Реконструкция цепочки атаки',
    body: [
      'Восстановление хода атаки по событиям, которые уже приняты в этот кейс: шаги в порядке времени, фаза каждого шага и то, каким механизмом ТАКТ его выделил. Это разбор произошедшего, а не эмуляция атаки и не синтетический прогон — ни одно событие здесь не придумано продуктом.',
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
    title: 'Разница во времени',
    body: [
      'Насколько разбор в ТАКТ короче ручного: расчётное время ручного разбора минус замеренное время в ТАКТ. Оба слагаемых выписаны под значением, а само время каждой стороны — в её плитке.',
      'Обе величины модельные: число действий умножено на коэффициент «секунд на одно действие», который задаёте вы. Меняете коэффициент — меняется и разница.',
      'Разница показана в минутах, а не вторым процентом. Модельное время пропорционально действиям, поэтому «сокращение времени» в процентах совпало бы с сокращением действий и выглядело бы вторым независимым доказательством, которым не является. Процент в интерфейсе один — по действиям.',
      'Что делать: сравнивать порядок величин. Настоящее время разбора даёт только парный прогон с наблюдателем — docs/pt_techlab/baseline_methodology.md.',
    ],
  },
  counters: {
    title: 'Трудоёмкость разбора',
    body: [
      'Четыре плитки: расчётное число действий при ручном разборе, замеренное число действий в ТАКТ, разница во времени между ними и сокращение действий в процентах. Время каждой стороны подписано под её счётчиком.',
      'Все четыре относятся к кейсу целиком и от позиции плеера не зависят: ручная оценка считается по составу кейса, замер в ТАКТ — по журналу действий, и ни то ни другое не накапливается по шагам цепочки.',
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
      'Разница между расчётом ручного процесса и замером в ТАКТ, в процентах от ручного. Значение относится к кейсу целиком и по мере проигрывания не меняется.',
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
      'Сущности цепочки и переходы между ними, слева направо по фазам атаки. Форма узла — тип сущности: круг — учётная запись, прямоугольник — узел, ромб — адрес, шестиугольник — процесс. Цвет — фаза, в которой сущность появилась впервые; в остальных фазах она остаётся в этом же цвете. Пунктирным кольцом отмечены сущности первого шага — точка входа.',
      'Переключатель «цепочка процессов» добавляет слой запусков: кто кого породил. По умолчанию он выключен, иначе процессы забивают собой остальное.',
      'Адрес источника отдельным узлом не показан намеренно: у всех четырёх классов источников это собственный адрес наблюдающего узла, а не второй участник обмена. Он подписан под самим узлом.',
      'Граф строится только по событиям цепочки этого кейса, связи вне кейса в нём не видны.',
      'Что делать: смотреть на переходы между узлами, смену учётной записи и цепочку запусков — по ним читается перемещение внутри сети.',
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
      'Сколько событий кейса пришло от каждого класса источников: «защита рабочих станций» — агент на узле, «система сбора событий» — правило корреляции, «сетевые события» — поток Netflow, «промышленная телеметрия» — телеметрия и конвейер сборки.',
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
      '«Новое» — принято конвейером, никто не смотрел. «В разборе» — взято аналитиком. «Подтверждено» — инцидент подтверждён. «Ложное срабатывание» — дефект правила. «Штатное действие» — сработало верно, но действие объяснено штатной работой. «Объединено» — влито в другой кейс.',
      'Разница между «ложным срабатыванием» и «штатным действием» важна: первое правят в правиле, второе — добором организационного контекста. Эта же разметка идёт в отчёт по правилам.',
      'Статус меняет человек; сборка инцидента ставит «в разборе» и вердикта не выносит. Что делать: не оставлять кейс в разборе после завершения — по статусу видно, что уже закрыто.',
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
      '«Защита рабочих станций» — агент на узле, «система сбора событий» — правило корреляции, «сетевые события» — поток Netflow, «промышленная телеметрия» — телеметрия и конвейер сборки. Исходный код класса источника остаётся в подсказке при наведении.',
      'Что делать: помнить разную природу свидетельств. Агент показывает, что произошло на узле; сетевой поток — что ушло по сети; система сбора событий — что уже решило вышестоящее средство.',
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
  confidence: {
    title: 'Обоснованность вывода',
    body: [
      'Одна величина вместо четырёх разбросанных признаков достоверности: полнота организационного контекста (вес 0.40), качество данных (0.25), доверие к источникам (0.20) и обоснование корреляции (0.15). Рядом — вердикт триады и разложение по составляющим с причинами, по которым составляющая не равна единице.',
      'Организационный контекст весит больше остальных: без него безупречные по качеству данные всё равно не дают вывода о легитимности. Доверие к источникам считается по слабейшему звену — вывод не крепче худшего из каналов.',
      'Пока перечень «Чего не хватает» непуст, обоснованность не бывает высокой, каким бы ни было качество данных. Что делать: называть эту величину в разговоре с руководителем и регулятором вместо перечисления отдельных метрик.',
    ],
  },
  missing: {
    title: 'Чего не хватает',
    body: [
      'Маршрут добора контекста: какой документ нужен, у кого он утверждается и за какое окно работ. Появляется ровно тогда, когда вердикт неопределённый.',
      'Неполная наблюдаемость сюда не попадает: она снижает обоснованность и объясняется в составляющей, но организационный документ не заменяет и не требует.',
      'Что делать: запросить перечисленное. После приложения документа вердикт пересчитывается, а оба состояния остаются в журнале.',
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

// --- Русские названия обозначений -----------------------------------------
//
// Словарь приходит из продукта (GET /catalog/vocabulary), а не хранится здесь. Свой словарь в
// АРМ разошёлся бы с продуктом при первом же добавлении статуса или источника — и разошёлся бы
// молча. Пока словарь не загружен или API недоступен, показывается исходный код: выдуманный
// перевод хуже кода, потому что его нельзя сверить с ответом API.
//
// Переводятся только обозначения продукта. Операция, протокол, идентификаторы узлов и учётных
// записей приходят из данных источника и остаются как есть: это материал доказательства.
let vocabulary = {};
let invariantTitles = new Map();

async function loadVocabulary() {
  try {
    vocabulary = (await api('/catalog/vocabulary')) || {};
  } catch (error) {
    vocabulary = {};
  }
  try {
    // Названия правил живут в каталоге инвариантов — том же, по которому работает движок.
    const catalog = (await api('/invariants')) || [];
    invariantTitles = new Map(catalog.map((item) => [item.id, item.title_ru]));
  } catch (error) {
    invariantTitles = new Map();
  }
}

function invariantTitle(id) {
  return invariantTitles.get(id) || id;
}

// Поля сущностей нормализованного события. Это состав нашей модели L1, а не значения из
// данных источника, поэтому названия здесь, а не в словаре продукта: словарь отдаёт типы
// сущностей (`entity_type`), а тут перечислены именно поля события.
const ENTITY_FIELD_RU = {
  host_id: 'узел',
  user_id: 'учётная запись',
  process_id: 'процесс',
  parent_process_id: 'родительский процесс',
  src_address: 'адрес источника',
  dst_address: 'адрес назначения',
};

function entityFieldTitle(name) {
  return ENTITY_FIELD_RU[name] || name;
}

function term(table, code) {
  const value = String(code ?? '').trim();
  if (!value) return '—';
  return (vocabulary[table] || {})[value] || value;
}

function firstArtifact(event) {
  const item = (event.artifacts || [])[0];
  return item ? `${term('artifact_type', item.type)}: ${item.value}` : '';
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
        <span class="risk ${escapeHtml(String(item.risk_class || '').toLowerCase())}">${escapeHtml(term('risk_class', item.risk_class))}</span>
      </span>
      <span class="queue-title">${escapeHtml(item.title || '—')}</span>
      <span class="queue-meta">${escapeHtml(term('case_status', item.status))} · ${escapeHtml(String(item.event_count ?? 0))} соб. · ${escapeHtml(score(item.risk_score))}</span>`;
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
  $('#caseStatus').textContent = term('case_status', item.status);
  $('#caseTitle').textContent = item.title || '—';
  $('#riskClass').textContent = term('risk_class', item.risk_class);
  $('#riskClass').className = `metric-value risk ${String(item.risk_class || '').toLowerCase()}`;
  $('#riskScore').textContent = score(item.risk_score);
  $('#eventCount').textContent = String((workspace.events || []).length);
  $('#dqScore').textContent = `${score(item.dq_score)}${item.dq_partial ? ' (неполные)' : ''}`;
  $('#caseXai').textContent = item.xai_summary || '';

  renderConfidence(item.verdict_confidence);
  renderSources(workspace.events || []);
  // Названия инвариантов приходят из каталога продукта (`invariant_details`), а не собираются
  // здесь: каталог правил — источник правды и для API, и для АРМ.
  renderInvariants(item.invariant_details || [], item.invariant_hits || []);
  renderChain(workspace.events || []);
  renderGraph(workspace.graph || { nodes: [], edges: [] });
  renderResponse(workspace.events || [], workspace.artifacts || []);
  renderFindings(item.findings || []);
}

// --- Обоснованность вывода -------------------------------------------------
//
// Одна величина вместо четырёх разбросанных признаков достоверности плюс маршрут добора
// контекста. Расчёт целиком на стороне продукта (`verdict_confidence` в GET /cases/{id});
// здесь только показ — второй, «свой» расчёт в интерфейсе разошёлся бы с доказательным
// контуром и с тем, что уходит руководителю.

const VERDICT_TEXT = {
  LEG: 'легитимное',
  ILLEG: 'нелегитимное',
  UNDET: 'неопределённое',
};

function renderConfidence(confidence) {
  const badge = $('#verdictBadge');
  const grade = $('#confidenceGrade');
  const scoreBox = $('#confidenceScore');
  const components = $('#confidenceComponents');
  components.replaceChildren();

  if (!confidence) {
    badge.textContent = '—';
    badge.className = 'verdict';
    grade.textContent = '—';
    grade.className = 'grade';
    scoreBox.textContent = 'показатель недоступен';
    renderMissing([]);
    return;
  }

  const verdict = String(confidence.verdict || 'UNDET');
  badge.textContent = VERDICT_TEXT[verdict] || verdict;
  badge.className = `verdict ${verdict.toLowerCase()}`;
  grade.textContent = confidence.grade || '—';
  grade.className = `grade ${gradeClass(confidence.grade)}`;
  scoreBox.textContent = `${score(confidence.score)} из 1.00`;

  for (const part of confidence.components || []) {
    const row = document.createElement('div');
    row.className = 'component';
    const share = Math.max(0, Math.min(1, Number(part.value) || 0));
    // Вес показан рядом с долей: без него две составляющие с одинаковым заполнением
    // выглядели бы равнозначными, хотя вклад в итог у них разный.
    row.innerHTML = `
      <span class="component-name">${escapeHtml(part.title_ru || part.key)}</span>
      <span class="component-bar"><span class="component-fill" style="width:${(share * 100).toFixed(0)}%"></span></span>
      <span class="component-value mono small">${score(part.value)} × ${score(part.weight)}</span>`;
    if ((part.reasons || []).length) {
      const why = document.createElement('p');
      why.className = 'component-reasons muted small';
      why.textContent = part.reasons.join('; ');
      row.appendChild(why);
    }
    components.appendChild(row);
  }

  renderMissing(confidence.missing || []);
}

function gradeClass(grade) {
  if (grade === 'высокая') return 'high';
  if (grade === 'средняя') return 'medium';
  return 'low';
}

function renderMissing(items) {
  const block = $('#missingBlock');
  const list = $('#missingList');
  list.replaceChildren();
  block.hidden = !items.length;
  for (const item of items) {
    const line = document.createElement('li');
    const address = [
      item.required_document ? `документ: ${item.required_document}` : '',
      item.sanctioning_party ? `утверждающий: ${item.sanctioning_party}` : '',
      item.admissible_window ? `окно: ${item.admissible_window}` : '',
    ].filter(Boolean);
    line.innerHTML = `<strong>${escapeHtml(item.text)}</strong>`;
    if (address.length) {
      const hint = document.createElement('span');
      hint.className = 'muted small';
      hint.textContent = ` — ${address.join(' · ')}`;
      line.appendChild(hint);
    }
    list.appendChild(line);
  }
}

function openDecisionBrief() {
  if (!selectedCaseId) return;
  // Сводка открывается как отдельный документ: её адресат — руководитель, и он получает
  // ссылку, а не пересказ из интерфейса аналитика.
  window.open(`${API_BASE}/cases/${encodeURIComponent(selectedCaseId)}/decision-brief.pdf`, '_blank', 'noopener');
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
    chip.textContent = `${term('event_source', source)} · ${count}`;
    box.appendChild(chip);
  }
}

function renderInvariants(details, hits) {
  const box = $('#invariantList');
  box.replaceChildren();
  const titles = new Map((details || []).map((item) => [item.id, item.title_ru]));
  const ids = (details || []).length ? details.map((item) => item.id) : hits;
  if (!ids.length) {
    box.innerHTML = '<span class="muted small">срабатываний нет</span>';
    return;
  }
  for (const id of ids) {
    const chip = document.createElement('span');
    chip.className = 'chip warn';
    // Идентификатор правила остаётся в подсказке: аналитику он нужен, чтобы найти правило в
    // config/invariants, но читать он должен название.
    chip.textContent = titles.get(id) || invariantTitle(id);
    chip.title = id;
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
      <td><span class="chip sm" title="${escapeHtml(event.source)}">${escapeHtml(term('event_source', event.source))}</span></td>
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
  $('#entityType').textContent = term('entity_type', type);
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
      ['Источники', (card.sources || []).map((source) => term('event_source', source)).join(', ') || '—'],
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
      body: JSON.stringify({ text: `${term('entity_type', selectedEntity.type)}: ${selectedEntity.id}` }),
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
    if (!$('#simulationView').hidden && simulation) renderCaseSelect();
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
$('#briefButton').addEventListener('click', openDecisionBrief);

// ---------------------------------------------------------------------------
// Вкладка «Цепочка атаки»: реконструкция хода атаки, счётчики трудоёмкости, граф
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

// Счётчики трудоёмкости позицией плеера не двигаются — намеренно.
//
// Раньше итоговые значения раскладывались по шагам пропорционально позиции, и на нулевой
// позиции экран показывал «0 действий вручную, 0 в ТАКТ» рядом с «сокращение 88.6%», а на
// первом шаге — «3 против 0», то есть стопроцентное сокращение. Ни одно из промежуточных
// чисел ничего не измеряло: ручная оценка считается по составу кейса, замер в ТАКТ — по
// журналу действий, и ни то ни другое не накапливается по шагам размеченной цепочки.
//
// Плеер двигает то, что действительно меняется по шагам: позицию, подсветку графа, состав
// пройденных фаз. Трудоёмкость относится к кейсу целиком и показывается сразу.

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

// Русское название фазы приходит вместе с цепочкой: свой словарь фаз в АРМ разошёлся бы
// с доменным перечнем при первом же добавлении.
function phaseTitle(phase) {
  const found = (simulation.phases || []).find((item) => item.phase === phase);
  return found ? found.title_ru : phase;
}

// Тот же текст стоит в разметке как начальное состояние: пустой абзац до загрузки
// скрипта мигал бы. Здесь он нужен, чтобы вернуть подсказку после сообщения об ошибке.
const SIM_EMPTY_HINT = 'Инцидент не выбран: очередь пуста или кейс ещё не открыт на вкладке «Расследование».';

async function openSimulation() {
  if (!selectedCaseId) {
    $('#simCase').hidden = true;
    $('#simBody').hidden = true;
    $('#simEmpty').hidden = false;
    $('#simEmpty').textContent = SIM_EMPTY_HINT;
    return;
  }
  $('#simEmpty').hidden = true;
  $('#simBody').hidden = false;
  // Шапка рисуется до запроса: если цепочка не построится, на экране всё равно должно быть
  // видно, по какому инциденту это сказано, а список инцидентов — остаться доступным.
  renderSimCase();
  try {
    const perAction = secondsPerAction();
    const query = perAction ? `?seconds_per_action=${perAction}` : '';
    simulation = await api(`/cases/${encodeURIComponent(selectedCaseId)}/simulation${query}`);
  } catch (error) {
    $('#simBody').hidden = true;
    $('#simEmpty').hidden = false;
    $('#simEmpty').textContent = `Цепочка не построена: ${error.message}`;
    return;
  }
  simCursor = 0;
  renderSimCase();
  renderLegend();
  renderSteps();
  renderAttackGraph();
  renderSummary();
  updateCounters();
  updatePosition();
}

// Шапка вкладки: без неё на экране не было ни одного признака, какой инцидент разбирается,
// а очередь на время разбора цепочки скрыта. Скриншот такой вкладки не привязан ни к чему.
function renderSimCase() {
  // Пока цепочка не пришла — сведения из очереди: шапка обязана быть верной и в состоянии
  // ошибки, иначе на экране остаётся сообщение без указания, к какому инциденту оно относится.
  const queued = cases.find((item) => item.case_id === selectedCaseId) || {};
  const item = simulation && simulation.case_id === selectedCaseId ? simulation : queued;
  $('#simCase').hidden = false;
  $('#simCaseId').textContent = item.case_id || selectedCaseId || '—';
  $('#simCaseStatus').textContent = term('case_status', item.status);
  $('#simCaseRisk').textContent = `${term('risk_class', item.risk_class)} · ${score(item.risk_score)}`;
  $('#simCaseRisk').className = `chip risk ${String(item.risk_class || '').toLowerCase()}`;
  $('#simCaseTitle').textContent = item.title || '—';
  renderCaseSelect();
}

// Переключение инцидента без ухода на вкладку «Расследование»: порядок тот же, что в очереди.
function renderCaseSelect() {
  const select = $('#simCaseSelect');
  select.replaceChildren();
  const ordered = [...cases].sort(
    (a, b) => Number(b.risk_score) - Number(a.risk_score) || Number(b.event_count || 0) - Number(a.event_count || 0)
  );
  for (const item of ordered) {
    const option = document.createElement('option');
    option.value = item.case_id;
    option.textContent = `${item.case_id} · ${term('risk_class', item.risk_class)} · ${item.title || '—'}`;
    option.selected = item.case_id === selectedCaseId;
    select.appendChild(option);
  }
}

function renderLegend() {
  const box = $('#phaseLegend');
  box.replaceChildren();
  for (const phase of simulation.phases || []) {
    const item = document.createElement('span');
    item.className = 'legend-item';
    item.dataset.phase = phase.phase;
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
        <span class="chip sm" title="${escapeHtml(step.source)}">${escapeHtml(term('event_source', step.source))}</span>
        <span class="muted small">${escapeHtml(step.mitre_technique || '')}</span>
      </button>`;
    row.querySelector('.step-open').addEventListener('click', () => openStep(step.order));
    list.appendChild(row);
  }
  paintProgress();
}

// Типы сущностей графа. Форма кодирует тип: цвет уже занят фазой, и различать учётную
// запись, узел, адрес и процесс по одному тексту подписи нельзя.
const NODE_TYPE_RU = {
  user: 'учётная запись',
  host: 'узел',
  address: 'адрес',
  process: 'процесс',
};

// Узлы и переходы цепочки.
//
// `src_address` отдельным узлом не показывается намеренно: у всех четырёх классов источников
// это собственный адрес наблюдающего узла (`src_ip` той же машины, что и `host_id`), а не
// второй участник обмена. Отдельным кружком он задваивал бы узел и рисовал бы связь, которой
// в данных нет. Показывается подписью на самом узле.
function chainGraph(withProcesses) {
  const nodes = new Map();
  const edges = [];
  const processHost = new Map();
  const hasParent = new Set();
  const add = (id, type, phase, order) => {
    if (!id) return null;
    if (!nodes.has(id)) nodes.set(id, { id, type, phase, order, addresses: new Set() });
    return id;
  };
  const link = (from, to, label, order) => {
    if (from && to && from !== to) edges.push({ from, to, label, order });
  };

  for (const step of simulation.steps || []) {
    const parts = step.entities || {};
    const user = add(parts.user_id, 'user', step.attack_phase, step.order);
    const host = add(parts.host_id, 'host', step.attack_phase, step.order);
    const dst = add(parts.dst_address, 'address', step.attack_phase, step.order);
    if (host && parts.src_address) nodes.get(host).addresses.add(parts.src_address);
    link(user, host, 'действует на', step.order);
    link(host, dst, 'обращается к', step.order);
    if (!withProcesses) continue;
    // Цепочка процессов — то, ради чего граф вообще смотрят после фишинга: родитель породил
    // потомка. Слой включается отдельно, иначе процессы забивают собой всё остальное.
    const parent = add(parts.parent_process_id, 'process', step.attack_phase, step.order);
    const process = add(parts.process_id, 'process', step.attack_phase, step.order);
    for (const item of [parent, process]) {
      if (item && host && !processHost.has(item)) processHost.set(item, host);
    }
    if (parent && process) {
      link(parent, process, 'породил', step.order);
      hasParent.add(process);
    }
  }

  // Процесс без родителя в цепочке привязывается к своему узлу — иначе он висел бы в воздухе.
  for (const node of nodes.values()) {
    if (node.type === 'process' && !hasParent.has(node.id)) {
      link(processHost.get(node.id), node.id, 'выполняет', node.order);
    }
  }
  return { nodes: [...nodes.values()], edges };
}

// Раскладка по фазам слева направо. Сетка «пять в ряд» смысла не несла: соседство на экране
// не означало связи, а с шестнадцатой сущности узлы уходили за пределы viewBox и пропадали
// молча. Колонка — фаза, в которой сущность появилась впервые; высота считается по рядам.
function graphLayout(nodes) {
  const order = (simulation.phases || []).map((item) => item.phase);
  const columns = new Map(order.map((phase) => [phase, []]));
  for (const node of nodes) {
    const key = columns.has(node.phase) ? node.phase : order[0];
    if (!columns.has(key)) columns.set(key, []);
    columns.get(key).push(node);
  }
  const filled = [...columns.entries()].filter(([, items]) => items.length);
  const position = new Map();
  const columnWidth = 210;
  const rowHeight = 96;
  filled.forEach(([, items], column) => {
    items.forEach((node, row) => {
      position.set(node.id, { x: 110 + column * columnWidth, y: 96 + row * rowHeight });
    });
  });
  const rows = Math.max(1, ...filled.map(([, items]) => items.length));
  return {
    position,
    columns: filled.map(([phase], index) => ({ phase, x: 110 + index * columnWidth })),
    width: Math.max(720, 110 + filled.length * columnWidth),
    height: 96 + rows * rowHeight,
  };
}

const NS = 'http://www.w3.org/2000/svg';

function svgNode(name, attributes) {
  const element = document.createElementNS(NS, name);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
  return element;
}

// Форма по типу сущности.
function nodeShape(node, point) {
  const fill = phaseColor(node.phase);
  if (node.type === 'host') {
    return svgNode('rect', { x: point.x - 24, y: point.y - 15, width: 48, height: 30, rx: 6, fill });
  }
  if (node.type === 'address') {
    const r = 19;
    const points = `${point.x},${point.y - r} ${point.x + r},${point.y} ${point.x},${point.y + r} ${point.x - r},${point.y}`;
    return svgNode('polygon', { points, fill });
  }
  if (node.type === 'process') {
    const r = 17;
    const points = [0, 60, 120, 180, 240, 300]
      .map((angle) => {
        const rad = (Math.PI / 180) * angle;
        return `${(point.x + r * Math.cos(rad)).toFixed(1)},${(point.y + r * Math.sin(rad)).toFixed(1)}`;
      })
      .join(' ');
    return svgNode('polygon', { points, fill });
  }
  return svgNode('circle', { cx: point.x, cy: point.y, r: 15, fill });
}

// Стрелка на ребре: «действует на» и «обращается к» направлены, и без наконечника
// направление на экране прочитать нельзя.
function arrowMarker() {
  const marker = svgNode('marker', {
    id: 'edgeArrow',
    viewBox: '0 0 8 8',
    refX: 7,
    refY: 4,
    markerWidth: 6,
    markerHeight: 6,
    orient: 'auto-start-reverse',
  });
  marker.appendChild(svgNode('path', { d: 'M0,0 L8,4 L0,8 z', class: 'edge-arrow' }));
  const defs = svgNode('defs', {});
  defs.appendChild(marker);
  return defs;
}

// Ребро укорачивается на радиус узла, иначе наконечник прячется под фигурой.
function edgeEnds(from, to) {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const length = Math.hypot(dx, dy) || 1;
  const gap = 26;
  return {
    x1: from.x + (dx / length) * gap,
    y1: from.y + (dy / length) * gap,
    x2: to.x - (dx / length) * gap,
    y2: to.y - (dy / length) * gap,
  };
}

// Имя намеренно отличается от `renderGraph` панели «Связи сущностей». Обе функции лежат в
// одной области видимости, и объявление ниже перекрывало объявление выше: открытие кейса
// вызывало отрисовку графа атаки, читало `simulation.steps` у ещё не загруженного разбора и
// падало — вкладка «Расследование» не открывалась вообще.
function renderAttackGraph() {
  const svg = $('#attackGraph');
  svg.replaceChildren();
  renderGraphLegend();
  const { nodes, edges } = chainGraph($('#showProcesses').checked);
  if (!nodes.length) return;

  const { position, columns, width, height } = graphLayout(nodes);
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.style.minWidth = `${width}px`;
  svg.style.height = `${height}px`;
  svg.appendChild(arrowMarker());

  for (const column of columns) {
    const title = svgNode('text', { x: column.x, y: 34, class: 'column-label', fill: phaseColor(column.phase) });
    title.textContent = phaseTitle(column.phase);
    svg.appendChild(title);
  }

  // Подписи на рёбрах не рисуются: они ложились ровно на подписи узлов, а в слое процессов
  // «породил» повторялось десятки раз. Направление читается по стрелке, тип сущности — по
  // форме, глагол связи — в подсказке при наведении и одной строкой в легенде. Так же
  // устроены графы инцидента у зрелых продуктов: подпись у каждого ребра там не рисуют.
  const seen = new Set();
  for (const edge of edges) {
    const key = `${edge.from}|${edge.to}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const from = position.get(edge.from);
    const to = position.get(edge.to);
    if (!from || !to) continue;
    const ends = edgeEnds(from, to);
    const line = svgNode('line', { ...ends, class: 'edge-line', 'marker-end': 'url(#edgeArrow)' });
    line.dataset.order = String(edge.order);
    const hint = svgNode('title', {});
    hint.textContent = edge.label;
    line.appendChild(hint);
    svg.appendChild(line);
  }

  for (const node of nodes) {
    const point = position.get(node.id);
    if (!point) continue;
    const group = svgNode('g', { class: 'graph-node' });
    group.dataset.order = String(node.order);
    // Точка входа — узел и учётная запись первого шага цепочки. Это разметка источника, а не
    // вывод продукта: первый по времени размеченный шаг и есть начало атаки. Адрес и процесс
    // того же шага точкой входа не помечаются — входят не через них.
    if (node.order === 1 && (node.type === 'host' || node.type === 'user')) {
      group.appendChild(svgNode('circle', { cx: point.x, cy: point.y, r: 27, class: 'entry-ring' }));
      const mark = svgNode('text', { x: point.x, y: point.y - 33, class: 'entry-label' });
      mark.textContent = 'точка входа';
      group.appendChild(mark);
    }
    group.appendChild(nodeShape(node, point));
    const text = svgNode('text', { x: point.x, y: point.y + 32, class: 'node-label' });
    text.textContent = node.id.length > 22 ? `${node.id.slice(0, 21)}…` : node.id;
    group.appendChild(text);
    if (node.addresses.size) {
      const sub = svgNode('text', { x: point.x, y: point.y + 45, class: 'node-sub' });
      sub.textContent = [...node.addresses].join(', ');
      group.appendChild(sub);
    }
    const hint = svgNode('title', {});
    hint.textContent = `${NODE_TYPE_RU[node.type] || node.type}: ${node.id}`;
    group.appendChild(hint);
    group.addEventListener('click', () => openStep(node.order));
    svg.appendChild(group);
  }
  paintProgress();
}

// Легенда форм: без неё тип сущности читается только из подписи.
function renderGraphLegend() {
  const box = $('#graphLegend');
  const withProcesses = $('#showProcesses').checked;
  box.replaceChildren();
  for (const [type, title] of Object.entries(NODE_TYPE_RU)) {
    if (type === 'process' && !withProcesses) continue;
    const item = document.createElement('span');
    item.className = `legend-item shape ${type}`;
    item.innerHTML = `<i></i>${escapeHtml(title)}`;
    box.appendChild(item);
  }
  const note = document.createElement('span');
  note.className = 'legend-note';
  note.textContent = withProcesses
    ? 'стрелка ведёт от действующей сущности к затронутой: учётная запись → узел, узел → адрес, родительский процесс → порождённый'
    : 'стрелка ведёт от действующей сущности к затронутой: учётная запись → узел, узел → адрес';
  box.appendChild(note);
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
  // Пройденные фазы — то, что действительно меняется по мере проигрывания, в отличие от
  // счётчиков трудоёмкости.
  const reached = new Set(
    (simulation && simulation.steps ? simulation.steps : [])
      .filter((step) => step.order <= simCursor)
      .map((step) => step.attack_phase)
  );
  for (const item of document.querySelectorAll('#phaseLegend .legend-item')) {
    item.classList.toggle('reached', reached.has(item.dataset.phase));
  }
}

function updateCounters() {
  const effort = simulation.effort || {};
  const manual = effort.current_actions || 0;
  const takt = effort.takt_actions || 0;
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
    // Разница показывается в минутах, а не вторым процентом. Модельное время пропорционально
    // действиям, поэтому «сокращение времени» в процентах совпало бы с сокращением действий и
    // выглядело бы вторым независимым доказательством, которым не является. Абсолютная разница
    // — та же единственная величина, выраженная так, как её читает человек.
    $('#timeValue').textContent = formatDuration(manualTime - taktTime);
    $('#timeDelta').textContent =
      `${formatDuration(manualTime)} − ${formatDuration(taktTime)} · модельная оценка при ${perAction} с на действие`;
  } else {
    $('#manualSeconds').textContent = 'время не рассчитано';
    $('#taktSeconds').textContent = 'время не рассчитано';
    $('#timeValue').textContent = '—';
    $('#timeDelta').textContent = 'коэффициент не задан';
  }
}

function updatePosition() {
  const steps = (simulation && simulation.steps ? simulation.steps : []).length;
  $('#playerPosition').textContent = `шаг ${simCursor} из ${steps}`;
}

function renderSummary() {
  const facts = $('#simSummary');
  facts.replaceChildren();
  const rows = [
    ['Класс риска', `${term('risk_class', simulation.risk_class)} · ${Number(simulation.risk_score).toFixed(3)}`],
    ['Статус', term('case_status', simulation.status)],
    ['Событий в кейсе', `${simulation.events_total}, из них шагов цепочки ${simulation.chain_length}`],
    ['Без разметки фазы', String(simulation.events_without_phase)],
    ['Сработавшие инварианты', (simulation.invariants || []).map(invariantTitle).join(', ') || 'нет'],
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
    .map(([name, value]) => `${entityFieldTitle(name)}: ${value}`);
  const artifacts = (step.artifacts || []).map((item) => `${term('artifact_type', item.type)}: ${item.value}`);

  lastFocused = document.activeElement;
  $('#modalTitle').textContent = `Шаг ${step.order}. ${step.attack_phase_title_ru}`;
  const body = $('#modalBody');
  body.replaceChildren();
  const paragraphs = [
    `Что произошло: источник «${term('event_source', step.source)}» зафиксировал ${step.operation} в ${utc(step.observed_at)} UTC.`,
    `Фаза цепочки: ${step.attack_phase_title_ru}. Техника ATT&CK: ${step.mitre_technique || 'не сопоставлена'}. Разметка приходит от источника, ТАКТ её не вычисляет.`,
    // Механизм и основание соединяются тире, а не точкой: основание записано со строчной
    // буквы, и после точки читалось бы как оборванная фраза. Пустая часть просто исчезает.
    `Чем выделено: ${[detection.selected_by_title_ru || 'основание не записано', detection.reason].filter(Boolean).join(' — ')}.`,
    detection.invariants && detection.invariants.length
      ? `Сработавшие инварианты на этом событии: ${detection.invariants.map(invariantTitle).join(', ')}.`
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
  updatePosition();
  // Счётчики трудоёмкости здесь не пересчитываются: они относятся к кейсу целиком.
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
$('#simCaseSelect').addEventListener('change', async (event) => {
  stopPlayback();
  await openCase(event.target.value);
  openSimulation();
});
$('#toInvestigation').addEventListener('click', () => showTab('investigation'));
// Слой процессов перерисовывает только граф: цепочка и счётчики от него не зависят,
// перезапрашивать разбор незачем.
$('#showProcesses').addEventListener('change', () => {
  if (simulation) renderAttackGraph();
});
$('#resetPlayer').addEventListener('click', () => {
  stopPlayback();
  setCursor(0);
});

// Словарь грузится до первой отрисовки: иначе очередь успела бы показать коды, а затем
// перерисоваться словами — мигание на пустом месте.
loadVocabulary().then(() => {
  refresh();
  pollTimer = setInterval(refresh, POLL_MS);
});
