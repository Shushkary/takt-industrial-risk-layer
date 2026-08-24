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
      'Часть кейсов создаёт конвейер приёма по совпадению признаков, часть собирает аналитик пивотом по отличительным сущностям; сборка пивотом выполняется вне этого окна — утилитой assemble_incident.',
      'Что делать: открыть кейс с наибольшим баллом, проверить состав событий и решить, инцидент это или штатная активность.',
    ],
  },
  queue_filters: {
    title: 'Фильтры очереди',
    body: [
      'Отбор выполняет продукт, а не браузер: параметры уходят в запрос списка кейсов, счётчик показывает, сколько кейсов подошло под фильтр из общего числа.',
      'По умолчанию показываются первые 100 кейсов по убыванию балла риска.',
      'Что делать: начинать смену с фильтра по классу риска и статусу «новое». Поток однотипных одиночных срабатываний с одинаковым баллом — материал для правки правила, а не для разбора поштучно.',
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
      'Что делать: идти сверху вниз и на каждом шаге отвечать, чем событие вызвано. Клик по узлу или учётной записи открывает карточку сущности. Для адресов карточки нет: история хранится по узлам, учётным записям и процессам.',
    ],
  },
  evidence: {
    title: 'Основание попадания события в кейс',
    body: [
      '«Ядро» — событие совпало с отличительной сущностью инцидента: учётной записью, адресом или артефактом, по которым кейс собирался. «Расширение» — событие добрано по узлу за окно инцидента и собственного признака атаки не имеет.',
      'Значение приходит из ответа продукта (correlation_evidence), интерфейс его не вычисляет. Полная причина — в подсказке при наведении.',
      'Что делать: разбирать сверху вниз ядро, а расширение отсеивать. Вместе с расширением в кейс попадает штатная активность тех же узлов — это цена полноты, а не ошибка сборки.',
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
  reconstruction: {
    title: 'Реконструкция цепочки',
    body: [
      'Точка входа и шаги «назад во времени»: запуск процесса (от кого запущен, что запущено) и сетевое перемещение (откуда обратился, куда). Строится по событиям кейса в порядке времени.',
      'Кто именно вызвал шаг, приходит из данных источника; ТАКТ не решает, является ли переход атакой. Событие вида «антивирус завершил проверку» тоже попадёт сюда как сетевое перемещение, если у него заполнены оба адреса.',
      'Что делать: проверять каждый шаг по операции события, а не доверять одной подписи «сетевое перемещение» или «запуск процесса».',
    ],
  },
  related_cases: {
    title: 'Связанные кейсы',
    body: [
      'Кейсы, влитые в этот при сборке пивотом или ручной корректировкой связей.',
      'Клик открывает связанный кейс в этом же окне.',
      'Что делать: смотреть на число связанных кейсов как на масштаб распространения — сколько отдельных срабатываний объединены в один разбор.',
    ],
  },
  entity: {
    title: 'Карточка сущности',
    body: [
      'История и окружение выбранной сущности по всем принятым событиям, а не только по событиям кейса: когда впервые и последний раз встречалась, из каких источников, в каких кейсах участвует и что происходило вокруг.',
      '«Частота в истории» — счётчик событий, а не модель поведения: «часто» означает три и более событий в накопленной истории и само по себе не говорит, что активность нормальна.',
      'Что делать: смотреть окружение и связанные кейсы. Если сущность встречается впервые или редко, событие в кейсе весит больше.',
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
  journal: {
    title: 'Журнал действий по кейсу',
    body: [
      'Все действия, изменившие состояние кейса: сборка, находки, подтверждение пакета, смена статуса. В записи — время, автор и суть действия.',
      'Журнал append-only и связан цепочкой хэшей: изменить прошлую запись нельзя, целостность проверяется отдельно по кнопке.',
      'Что делать: передавая смену, ссылаться на журнал, а не пересказывать сделанное. По нему же считается сокращение ручных действий.',
    ],
  },
  response: {
    title: 'Варианты реагирования',
    body: [
      'Действия, применимые к отличительным сущностям кейса: изоляция узла, сброс учётной записи, блокировка адреса, заморозка конвейера. Узлы, добранные расширением, показаны отдельной группой и по умолчанию не отмечены: они попали в кейс по узлу, а не по признаку атаки.',
      'ТАКТ их не выполняет и команд не отправляет. Это перечень для решения аналитика, исполняет его внешняя система после подтверждения.',
      'Что делать: отметить применимые пункты и подтвердить пакет. Подтверждение записывает состав пакета в журнал кейса и открывает текст для передачи ответственному.',
    ],
  },
  risk_class: {
    title: 'Класс риска',
    body: [
      'Низкий, средний, высокий или критический (в ответах API — коды LOW, MEDIUM, HIGH, CRITICAL) — балл риска, разложенный по порогам из конфигурации.',
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
      'Статус меняется кнопкой «изменить статус» в сводке, с обязательной причиной; сборка инцидента ставит «в разборе» и вердикта не выносит. Что делать: не оставлять кейс в разборе после завершения — по статусу видно, что уже закрыто.',
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
      'Доля признаков, вычисленных по событиям кейса без пропусков: 1.00 — данные полные. Пометка «(неполные)» означает частичную наблюдаемость; причины перечислены под значением — код приходит из ответа продукта (dq_reasons), выдуманный перевод хуже кода.',
      'Что делать: значение ниже 1.00 — причина запросить исходные журналы, а не понижать значимость инцидента. Неполнота снижает обоснованность вывода, но организационный документ не заменяет.',
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
      'Что делать: запросить перечисленное. Документ прикладывается вне этого окна (POST /cases/{id}/manual-permits); после этого вердикт пересчитывается, а оба состояния остаются в журнале.',
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
let currentCaseStatus = '';
let lastWorkspaceEvents = [];
let currentCaseEventCount = null;
let lastCaseFindings = [];

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
    const httpError = new Error(message);
    httpError.status = response.status;
    throw httpError;
  }
  return response.status === 204 ? null : response.json();
}

// Как api(), но возвращает и заголовки ответа — нужны для X-Total-Count при постраничном
// списке кейсов. Отдельная функция, чтобы не менять поведение существующих вызовов api().
async function apiWithHeaders(path, options) {
  const response = await fetch(`${API_BASE}${path}`, { cache: 'no-store', ...options });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return { data: response.status === 204 ? null : await response.json(), headers: response.headers };
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
  fillFilterOptions();
}

// Список статусов и классов риска в фильтре очереди строится из словаря продукта, а не из
// литералов кода: свой список разошёлся бы с продуктом при первом же добавлении значения.
function fillFilterOptions() {
  const fill = (select, table) => {
    for (const [code, title] of Object.entries(vocabulary[table] || {})) {
      const option = document.createElement('option');
      option.value = code;
      option.textContent = title;
      select.appendChild(option);
    }
  };
  fill($('#queueRisk'), 'risk_class');
  fill($('#queueStatus'), 'case_status');
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

// Контрольная сумма в 64 знака растягивает таблицу вдвое. Полное значение остаётся
// в подсказке и копируется по клику: аналитику оно нужно целиком, но не на экране.
function shorten(value, keep = 12) {
  const text = String(value ?? '');
  return text.length <= keep * 2 + 1 ? text : `${text.slice(0, keep)}…${text.slice(-keep)}`;
}

function copyable(value, label) {
  if (!value) return '';
  return `<button type="button" class="copyable" data-copy="${escapeHtml(value)}" title="${escapeHtml(value)}">${escapeHtml(label ?? shorten(value))}</button>`;
}

function artifactCell(event) {
  const items = event.artifacts || [];
  if (!items.length) return '';
  const first = `${term('artifact_type', items[0].type)}: ${copyable(items[0].value)}`;
  if (items.length <= 1) return first;
  const rest = items.slice(1).map((item) => `${term('artifact_type', item.type)}: ${item.value}`).join('; ');
  return `<span title="${escapeHtml(rest)}">${first} <span class="muted small">и ещё ${items.length - 1}</span></span>`;
}

function addressOf(entities) {
  if (!entities) return '';
  const parts = [entities.src_address, entities.dst_address].filter(Boolean);
  if (!parts.length) return '';
  return parts.map((value) => copyable(value)).join(' → ');
}

// --- Очередь ---------------------------------------------------------------

// Перерисовка неизменившейся очереди раз в 15 с сбрасывала фокус клавиатуры на body:
// пройти список с клавиатуры было невозможно. Сигнатура не учитывает selectedCaseId —
// подсветку выбранного кейса переключает updateActiveQueueItem() без перестройки DOM.
function queueSignature(items) {
  return items.map((item) => `${item.case_id}:${item.status}:${item.risk_score}:${item.event_count}`).join('|');
}

let lastQueueSignature = null;

function renderQueue() {
  const ordered = [...cases].sort(
    (a, b) => Number(b.risk_score) - Number(a.risk_score) || Number(b.event_count || 0) - Number(a.event_count || 0)
  );
  const signature = queueSignature(ordered);
  if (signature === lastQueueSignature) {
    updateActiveQueueItem();
    return;
  }
  lastQueueSignature = signature;

  const list = $('#queueList');
  const focusedCaseId = document.activeElement?.closest?.('.queue-item')?.dataset.caseId;
  list.replaceChildren();
  $('#queueEmpty').hidden = cases.length > 0;
  for (const item of ordered) {
    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.caseId = item.case_id;
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
  if (focusedCaseId) {
    list.querySelector(`[data-case-id="${CSS.escape(focusedCaseId)}"]`)?.focus();
  }
}

// Подсветка выбранного кейса без перестройки DOM: используется при выборе кейса, чтобы
// не пересобирать список (и не терять фокус) там, где данные очереди не изменились.
function updateActiveQueueItem() {
  for (const button of document.querySelectorAll('#queueList .queue-item')) {
    button.classList.toggle('active', button.dataset.caseId === selectedCaseId);
  }
}

// --- Окно инцидента --------------------------------------------------------

async function openCase(caseId) {
  selectedCaseId = caseId;
  // Сущность принадлежит кейсу, из которого её открыли: при смене кейса панель очищается,
  // иначе «Добавить в находки» запишет в новый кейс сущность из прежнего.
  resetEntityPanel();
  updateActiveQueueItem();
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
  currentCaseStatus = item.status || '';
  lastWorkspaceEvents = workspace.events || [];
  currentCaseEventCount = lastWorkspaceEvents.length;
  $('#staleCaseBanner').hidden = true;
  closeStatusForm();
  $('#caseId').textContent = item.case_id || '—';
  $('#caseStatus').textContent = term('case_status', item.status);
  $('#caseTitle').textContent = item.title || '—';
  $('#riskClass').textContent = term('risk_class', item.risk_class);
  $('#riskClass').className = `metric-value risk ${String(item.risk_class || '').toLowerCase()}`;
  $('#riskScore').textContent = score(item.risk_score);
  $('#eventCount').textContent = String((workspace.events || []).length);
  $('#dqScore').textContent = `${score(item.dq_score)}${item.dq_partial ? ' (неполные)' : ''}`;
  const dqReasons = item.dq_reasons || [];
  $('#dqReasons').hidden = !dqReasons.length;
  $('#dqReasons').textContent = dqReasons.length ? `Причины: ${dqReasons.join(', ')}` : '';
  $('#caseXai').textContent = item.xai_summary || '';

  renderConfidence(item.verdict_confidence);
  renderSources(workspace.events || []);
  // Названия инвариантов приходят из каталога продукта (`invariant_details`), а не собираются
  // здесь: каталог правил — источник правды и для API, и для АРМ.
  renderInvariants(item.invariant_details || [], item.invariant_hits || []);
  renderChain(workspace.events || [], item.correlation_evidence || []);
  renderGraph(workspace.graph || { nodes: [], edges: [] });
  renderReconstruction(workspace.attack_chain || {});
  renderRelatedCases(item.related_cases || []);
  renderResponse(workspace.events || [], workspace.artifacts || [], item.correlation_evidence || []);
  renderFindings(item.findings || []);
  renderJournal(item.audit_log || []);
}

// --- Реконструкция цепочки и связанные кейсы --------------------------------
//
// Оба блока приходят в том же ответе workspace/case, что уже был запрошен: attack_chain
// (точка входа + шаги) и related_cases (кейсы, влитые в этот при сборке пивотом или ручной
// корректировкой). Раньше это не показывалось на вкладке расследования вовсе — реконструкция
// была только в «Симуляции», а связанные кейсы виднелись лишь строкой хэшей в карточке сущности.

const CHAIN_STEP_KIND_RU = {
  process_spawn: 'запуск процесса',
  network_move: 'сетевое перемещение',
};

function renderReconstruction(attackChain) {
  const steps = attackChain.steps || [];
  $('#reconstructionEntry').textContent = attackChain.entry_point
    ? `Точка входа: ${attackChain.entry_point}`
    : 'Точка входа не определена';
  const list = $('#reconstructionSteps');
  list.replaceChildren();
  if (!steps.length) {
    list.innerHTML = '<li class="muted small">шагов нет</li>';
    return;
  }
  for (const step of steps) {
    const item = document.createElement('li');
    const kind = CHAIN_STEP_KIND_RU[step.kind] || step.kind;
    item.innerHTML = `<span class="mono small muted">${escapeHtml(utc(step.observed_at))}</span> ${escapeHtml(kind)}: <span class="mono">${escapeHtml(step.from_entity)}</span> → <span class="mono">${escapeHtml(step.to_entity)}</span> <span class="muted small">(${escapeHtml(step.operation)})</span>`;
    list.appendChild(item);
  }
}

function renderRelatedCases(relatedCases) {
  const box = $('#relatedCasesList');
  box.replaceChildren();
  if (!relatedCases.length) {
    box.innerHTML = '<span class="muted small">связанных кейсов нет</span>';
    return;
  }
  for (const caseId of relatedCases) {
    const chip = document.createElement('button');
    chip.type = 'button';
    chip.className = 'chip sm chip-button';
    chip.textContent = caseId;
    chip.addEventListener('click', () => openCase(caseId));
    box.appendChild(chip);
  }
}

// --- Журнал действий --------------------------------------------------------
//
// Append-only журнал кейса (`case.audit_log`), не отдельный расчёт: строка имеет вид
// `<время ISO> | <действие>[ | actor=<id>]`. Записи без `actor=` — операции конвейера,
// а не человека, показываются как «система».

function parseAuditLine(line) {
  const sepIndex = line.indexOf(' | ');
  const at = sepIndex >= 0 ? line.slice(0, sepIndex) : '';
  let action = sepIndex >= 0 ? line.slice(sepIndex + 3) : line;
  let actor = 'система';
  const actorSep = action.lastIndexOf(' | actor=');
  if (actorSep >= 0) {
    actor = action.slice(actorSep + 9).trim() || actor;
    action = action.slice(0, actorSep);
  }
  return { at, action, actor };
}

function renderJournal(auditLog) {
  const list = $('#journalList');
  list.replaceChildren();
  if (!auditLog.length) {
    list.innerHTML = '<li class="muted small">записей нет</li>';
    return;
  }
  // Новые действия сверху: журнал читают, чтобы понять, что случилось только что,
  // а не с чего кейс начинался.
  for (const line of [...auditLog].reverse()) {
    const { at, action, actor } = parseAuditLine(line);
    const item = document.createElement('li');
    item.className = 'journal-item';
    item.innerHTML = `<span class="journal-time">${escapeHtml(utc(at))}</span><span class="journal-actor">${escapeHtml(actor)}</span><span>${escapeHtml(action)}</span>`;
    list.appendChild(item);
  }
}

async function verifyAuditLedger() {
  if (!selectedCaseId) return;
  try {
    const result = await api(`/cases/${encodeURIComponent(selectedCaseId)}/audit-ledger/verify`);
    toast(
      result.ok
        ? `Целостность подтверждена: проверено записей — ${result.checked_entries}`
        : `Нарушение целостности: ${result.issue} (проверено ${result.checked_entries} из журнала)`
    );
  } catch (error) {
    toast(
      error.status === 501
        ? 'Проверка целостности недоступна для текущего хранилища'
        : `Проверка не выполнена: ${error.message}`
    );
  }
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

// Смена статуса кейса (POST /cases/{id}/decision). Список статусов строится из словаря
// продукта, а не из литералов кода: свой список статусов разошёлся бы с продуктом при первом
// же добавлении значения.
function openStatusForm() {
  const select = $('#statusFormSelect');
  select.replaceChildren();
  for (const [code, title] of Object.entries(vocabulary.case_status || {})) {
    if (code === currentCaseStatus) continue;
    const option = document.createElement('option');
    option.value = code;
    option.textContent = title;
    select.appendChild(option);
  }
  $('#statusFormReason').value = '';
  $('#statusFormSubmit').disabled = true;
  $('#statusFormError').hidden = true;
  $('#changeStatusButton').hidden = true;
  $('#statusForm').hidden = false;
  $('#statusFormReason').focus();
}

function closeStatusForm() {
  $('#statusForm').hidden = true;
  $('#changeStatusButton').hidden = false;
}

async function submitStatusForm() {
  if (!selectedCaseId) return;
  const status = $('#statusFormSelect').value;
  const reason = $('#statusFormReason').value.trim();
  if (!status || !reason) return;
  const button = $('#statusFormSubmit');
  button.disabled = true;
  $('#statusFormError').hidden = true;
  try {
    await api(`/cases/${encodeURIComponent(selectedCaseId)}/decision`, {
      method: 'POST',
      body: JSON.stringify({ status, reason }),
    });
    toast(`Статус изменён: ${term('case_status', status)}`);
    await openCase(selectedCaseId);
    await refresh();
  } catch (error) {
    const message =
      error.status === 403
        ? 'Недостаточно прав: смена статуса доступна второй линии'
        : `Не удалось изменить статус: ${error.message}`;
    $('#statusFormError').textContent = message;
    $('#statusFormError').hidden = false;
    button.disabled = false;
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

// Основание попадания события в кейс. Значение приходит из `correlation_evidence` ответа API:
// свой вывод здесь разошёлся бы с тем, что уходит в доказательный пакет.
const EVIDENCE_RULE_RU = {
  pivot: 'ядро',
  'host-expansion': 'расширение',
  manual: 'добавлено аналитиком',
};

function evidenceCell(item) {
  if (!item) return '<span class="muted small">—</span>';
  const label = EVIDENCE_RULE_RU[item.rule] || item.rule;
  const kind = item.rule === 'pivot' ? 'core' : 'expanded';
  return `<span class="evidence ${kind}" title="${escapeHtml(item.reason || '')}">${escapeHtml(label)}</span>`;
}

let lastChainEvents = [];
let lastChainEvidence = new Map();

function renderChain(events, correlationEvidence) {
  lastChainEvents = events;
  lastChainEvidence = new Map((correlationEvidence || []).map((item) => [item.event_id, item]));
  paintChain();
}

function paintChain() {
  const body = $('#chainBody');
  body.replaceChildren();
  const coreOnly = $('#coreOnly').checked;
  const ordered = [...lastChainEvents].sort((a, b) => String(a.observed_at).localeCompare(String(b.observed_at)));
  let coreCount = 0;
  let expandedCount = 0;
  for (const event of ordered) {
    const evidence = lastChainEvidence.get(event.event_id);
    const isCore = evidence ? evidence.rule === 'pivot' : true;
    if (isCore) coreCount += 1;
    else expandedCount += 1;
  }
  let shown = 0;
  for (const event of ordered) {
    const evidence = lastChainEvidence.get(event.event_id);
    const isCore = evidence ? evidence.rule === 'pivot' : true;
    if (coreOnly && !isCore) continue;
    shown += 1;
    const entities = event.entities || {};
    const row = document.createElement('tr');
    if (!isCore) row.className = 'row-expanded';
    row.innerHTML = `
      <td class="mono">${escapeHtml(utc(event.observed_at))}</td>
      <td>${evidenceCell(evidence)}</td>
      <td><span class="chip sm" title="${escapeHtml(`${term('event_source', event.source)} (${event.source})`)}">${escapeHtml(term('event_source', event.source))}</span></td>
      <td class="mono">${escapeHtml(event.operation)}</td>
      <td>${entityButton('host', entities.host_id)}</td>
      <td>${entityButton('user', entities.user_id)}</td>
      <td class="mono small">${addressOf(entities)}</td>
      <td class="small">${artifactCell(event)}</td>`;
    body.appendChild(row);
  }
  $('#chainCount').textContent = `Показано ${shown} из ${ordered.length} · ядро ${coreCount} · расширение ${expandedCount}`;
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
// Тип строки таблицы — не обозначение продукта из словаря, а поле сущности (те же коды, что
// в цепочке событий): host/user/address берут название из entity_type словаря, остальное —
// локальная подпись, специфичная для пакета реагирования.
const RESPONSE_TYPE_RU = { artifact: 'объект конвейера', pipeline: 'конвейер' };

function responseTypeLabel(type) {
  return RESPONSE_TYPE_RU[type] || term('entity_type', type);
}

// Значение объекта конвейера уже несёт классификатор префиксом (`artifact:app-setup.msi`,
// `pipeline:release-prod` — см. комментарий у renderResponse). Записывать поле type кода
// `artifact` поверх такого значения дало бы в журнале «artifact:artifact:app-setup.msi».
// Ближайшие коды каталога артефактов: `file` — файл конвейера, `repo` — сам конвейер/репозиторий.
function findingArtifactType(row) {
  if (row.type !== 'artifact') return row.type;
  if (row.value.startsWith('pipeline:')) return 'repo';
  if (row.value.startsWith('artifact:')) return 'file';
  return row.type;
}

function responseLineText(row) {
  if (row.type === 'pipeline') return row.action;
  const hostPart = row.host ? ` — узел ${row.host}` : '';
  return `${responseTypeLabel(row.type)} — ${row.value}${hostPart} — ${row.action}`;
}

let responseRows = [];

// Варианты реагирования строятся по отличительным сущностям инцидента (артефакты кейса
// с источником pivot-seed) — события, добранные расширением до уровня узла, содержат и
// штатную активность, предлагать по ним действия значит предлагать сброс учётных записей
// людей, которые в это время просто работали. Узлы расширения показаны отдельной, не
// отмеченной по умолчанию группой (F-08): по инциденту «компрометация ws-17» иначе не было
// видно вообще, что с ws-17 можно что-то сделать.
function renderResponse(events, artifacts, correlationEvidence) {
  const evidenceByEvent = new Map((correlationEvidence || []).map((item) => [item.event_id, item]));
  const hosts = new Set();
  const users = new Set();
  const addresses = new Set();
  const objects = new Set();
  let pipeline = false;
  const seeds = (artifacts || []).filter((item) => item.source === 'pivot-seed');
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
  const expandedHosts = new Set();
  for (const event of events) {
    const evidence = evidenceByEvent.get(event.event_id);
    const hostId = event.entities && event.entities.host_id;
    if (evidence && evidence.rule === 'host-expansion' && hostId) expandedHosts.add(hostId);
  }

  responseRows = [];
  if (seeds.length) {
    for (const host of hosts) {
      responseRows.push({ type: 'host', value: host, host, action: 'Изоляция узла', group: 'core', checked: true });
    }
    for (const user of users) {
      responseRows.push({ type: 'user', value: user, host: '', action: 'Сброс учётной записи', group: 'core', checked: true });
    }
    for (const address of addresses) {
      responseRows.push({ type: 'address', value: address, host: '', action: 'Блокировка адреса', group: 'core', checked: true });
    }
    if (objects.size) {
      for (const object of objects) {
        responseRows.push({
          type: 'artifact', value: object, host: '',
          action: 'Заморозка конвейера сборки до проверки объекта', group: 'core', checked: true,
        });
      }
    } else if (pipeline) {
      responseRows.push({ type: 'pipeline', value: '—', host: '', action: 'Заморозка конвейера сборки', group: 'core', checked: true });
    }
  }
  for (const host of expandedHosts) {
    responseRows.push({
      type: 'host', value: host, host,
      action: 'Изоляция узла (узел разбора, не отличительная сущность)', group: 'expanded', checked: false,
    });
  }

  paintResponse();
}

function paintResponse() {
  const wrap = $('#responseTableWrap');
  const empty = $('#responseEmpty');
  const body = $('#responseBody');
  body.replaceChildren();
  if (!responseRows.length) {
    wrap.hidden = true;
    empty.hidden = false;
    empty.textContent = 'кейс собран не пивотом: отличительные сущности не заданы, предлагать действия не по чему';
    $('#confirmResponseButton').disabled = true;
    return;
  }
  empty.hidden = true;
  wrap.hidden = false;
  responseRows.forEach((row, index) => {
    const tr = document.createElement('tr');
    if (row.group === 'expanded') tr.className = 'response-expanded';
    tr.innerHTML = `
      <td><input type="checkbox" data-response-index="${index}" ${row.checked ? 'checked' : ''} /></td>
      <td>${escapeHtml(responseTypeLabel(row.type))}</td>
      <td class="mono small">${escapeHtml(row.value)}</td>
      <td class="mono small">${escapeHtml(row.host)}</td>
      <td>${escapeHtml(row.action)}</td>`;
    body.appendChild(tr);
  });
  body.querySelectorAll('[data-response-index]').forEach((checkbox) => {
    checkbox.addEventListener('change', () => {
      responseRows[Number(checkbox.dataset.responseIndex)].checked = checkbox.checked;
      updateConfirmResponseState();
    });
  });
  updateConfirmResponseState();
}

function updateConfirmResponseState() {
  $('#confirmResponseButton').disabled = !responseRows.some((row) => row.checked);
}

function responsePackageText() {
  const lines = responseRows.filter((row) => row.checked).map(responseLineText);
  return `Пакет реагирования по кейсу ${selectedCaseId}:\n${lines.join('\n')}`;
}

function showResponsePackageModal(text) {
  lastFocused = document.activeElement;
  $('#modalTitle').textContent = 'Пакет реагирования — для передачи';
  const body = $('#modalBody');
  body.replaceChildren();
  const pre = document.createElement('pre');
  pre.className = 'response-package-text';
  pre.textContent = text;
  body.appendChild(pre);
  const hint = document.createElement('p');
  hint.className = 'muted small';
  hint.textContent = 'Текст записан в журнал кейса. Скопируйте его для передачи ответственному.';
  body.appendChild(hint);
  $('#modal').hidden = false;
  $('#modalClose').focus();
}

async function confirmResponsePackage() {
  if (!selectedCaseId) return;
  const checked = responseRows.filter((row) => row.checked);
  if (!checked.length) return;
  const button = $('#confirmResponseButton');
  button.disabled = true;
  const text = responsePackageText();
  try {
    await api(`/cases/${encodeURIComponent(selectedCaseId)}/findings`, {
      method: 'POST',
      body: JSON.stringify({
        text,
        artifacts: checked
          .filter((row) => row.type !== 'pipeline')
          .map((row) => ({ type: findingArtifactType(row), value: row.value, host_id: row.host || '' })),
      }),
    });
    if (navigator.clipboard) navigator.clipboard.writeText(text).catch(() => {});
    toast('Пакет реагирования подтверждён и записан в журнал кейса');
    showResponsePackageModal(text);
    await openCase(selectedCaseId);
  } catch (error) {
    toast(`Пакет не подтверждён: ${error.message}`);
    button.disabled = false;
  }
}

// --- Сущность и находки ----------------------------------------------------

function resetEntityPanel() {
  selectedEntity = null;
  $('#entityBody').hidden = true;
  $('#entityEmpty').hidden = false;
  $('#entityId').textContent = '';
  $('#entityType').textContent = '—';
  $('#entityFacts').replaceChildren();
  $('#entityEnvironment').replaceChildren();
  $('#findingComment').value = '';
}

async function openEntity(type, id) {
  selectedEntity = { type, id };
  $('#entityEmpty').hidden = true;
  $('#entityBody').hidden = false;
  $('#entityType').textContent = term('entity_type', type);
  $('#entityId').textContent = id;
  $('#findingComment').value = '';
  const facts = $('#entityFacts');
  facts.replaceChildren();
  // На одноколоночной раскладке карточка уезжает вниз страницы: без этого клик
  // выглядит как «ничего не произошло».
  if (window.matchMedia('(max-width: 1200px)').matches) {
    $('#entityBody').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  for (const button of document.querySelectorAll('.entity-link')) {
    button.classList.toggle('active', button.dataset.entityType === type && button.dataset.entityId === id);
  }
  const environment = $('#entityEnvironment');
  environment.replaceChildren();
  try {
    const card = await api(`/entities/${encodeURIComponent(type)}/${encodeURIComponent(id)}/card`);
    const typicality = card.typicality || {};
    const eventCount = card.event_count ?? (card.environment || []).length;
    // «Частота в истории» — счётчик событий, а не модель поведения: explanation с бэкенда
    // приходит на английском для журналов, а не для интерфейса аналитика, поэтому здесь не
    // показывается — считаем по event_count сами, тем же порогом, что и typicality.status.
    let frequency = typicality.status || '—';
    if (typicality.status === 'first_seen') frequency = 'первое появление';
    else if (typicality.status === 'rare') frequency = 'редко: менее 3 событий';
    else if (typicality.status === 'typical') frequency = `часто: 3 и более событий (${eventCount})`;
    const rows = [
      ['Событий всего', eventCount],
      ['Частота в истории', frequency],
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
    const recent = (card.environment || []).slice(0, 10);
    if (!recent.length) {
      environment.innerHTML = '<li class="muted small">событий нет</li>';
    } else {
      for (const event of recent) {
        const item = document.createElement('li');
        item.innerHTML = `<span class="mono small muted">${escapeHtml(utc(event.observed_at))}</span> <span class="chip sm" title="${escapeHtml(event.source)}">${escapeHtml(term('event_source', event.source))}</span> <span class="mono small">${escapeHtml(event.operation)}</span>`;
        environment.appendChild(item);
      }
      const total = document.createElement('li');
      total.className = 'muted small';
      total.textContent = `всего в истории: ${card.environment_total ?? recent.length}`;
      environment.appendChild(total);
    }
  } catch (error) {
    const dt = document.createElement('dt');
    dt.textContent = 'Частота в истории';
    const dd = document.createElement('dd');
    dd.textContent = `недоступна: ${error.message}`;
    facts.append(dt, dd);
    environment.innerHTML = '<li class="muted small">окружение недоступно</li>';
  }
}

function renderFindings(findings) {
  lastCaseFindings = findings;
  const list = $('#findingList');
  list.replaceChildren();
  if (!findings.length) {
    list.innerHTML = '<li class="muted small">находок нет</li>';
    return;
  }
  for (const finding of findings) {
    const text = finding.text || `${finding.entity_type || ''}: ${finding.entity_id || ''}`;
    const meta = [];
    if (finding.author) meta.push(finding.author);
    if (finding.created_at) meta.push(utc(finding.created_at));
    if ((finding.event_ids || []).length) meta.push(`событий: ${finding.event_ids.length}`);
    const row = document.createElement('li');
    row.innerHTML = `<div>${escapeHtml(text)}</div>${meta.length ? `<div class="muted small">${escapeHtml(meta.join(' · '))}</div>` : ''}`;
    list.appendChild(row);
  }
}

// Идентификаторы событий кейса, где встречается сущность: находка привязывается к
// доказательству (ТЗ §5.5), а не остаётся текстовой пометкой без ссылки на события.
function eventIdsForEntity(entity) {
  const fieldByType = { host: 'host_id', user: 'user_id', process: 'process_id' };
  const field = fieldByType[entity.type];
  if (!field) return [];
  return lastWorkspaceEvents.filter((event) => event.entities && event.entities[field] === entity.id).map((event) => event.event_id);
}

async function addFinding() {
  if (!selectedEntity || !selectedCaseId) return;
  const comment = $('#findingComment').value.trim();
  const baseText = `${term('entity_type', selectedEntity.type)}: ${selectedEntity.id}`;
  const text = comment ? `${baseText} — ${comment}` : baseText;
  if (lastCaseFindings.some((item) => item.text === text)) {
    toast('Эта сущность уже в находках');
    return;
  }
  const button = $('#addFinding');
  button.disabled = true;
  try {
    await api(`/cases/${encodeURIComponent(selectedCaseId)}/findings`, {
      method: 'POST',
      body: JSON.stringify({
        text,
        event_ids: eventIdsForEntity(selectedEntity),
        artifacts: [{ type: selectedEntity.type, value: selectedEntity.id }],
      }),
    });
    toast('Находка записана в журнал кейса');
    $('#findingComment').value = '';
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

const QUEUE_PAGE_LIMIT = 100;

function queueQueryString() {
  const params = new URLSearchParams({ sort: 'risk_score_desc', limit: String(QUEUE_PAGE_LIMIT) });
  const risk = $('#queueRisk').value;
  const status = $('#queueStatus').value;
  const search = $('#queueSearch').value.trim();
  if (risk) params.set('risk_classes', risk);
  if (status) params.set('status', status);
  if (search) params.set('title_contains', search);
  return params.toString();
}

async function refresh() {
  try {
    const { data, headers } = await apiWithHeaders(`/cases?${queueQueryString()}`);
    cases = Array.isArray(data) ? data : data.items || [];
    renderQueue();
    const total = headers.get('X-Total-Count');
    $('#queueCount').textContent =
      total !== null ? `Показано ${cases.length} из ${total}` : `Показано ${cases.length}`;
    setConnection('ok');
    $('#lastSync').textContent = `обновлено ${utc(new Date().toISOString())} UTC`;
    // Опрос обновляет только очередь; открытая карточка кейса иначе могла молча устареть.
    // Сравнение — по сводке из той же очереди, полная перерисовка карточки произошла бы
    // резко под курсором аналитика и сбросила бы прокрутку/отметки в пакете реагирования.
    if (selectedCaseId) {
      const openSummary = cases.find((item) => item.case_id === selectedCaseId);
      if (openSummary) {
        const stale = openSummary.status !== currentCaseStatus || Number(openSummary.event_count) !== currentCaseEventCount;
        $('#staleCaseBanner').hidden = !stale;
      }
    }
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
  const copyButton = event.target.closest('[data-copy]');
  if (copyButton) {
    navigator.clipboard.writeText(copyButton.dataset.copy).then(
      () => toast('Значение скопировано'),
      () => toast('Скопировать не удалось: буфер обмена недоступен')
    );
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
$('#changeStatusButton').addEventListener('click', openStatusForm);
$('#statusFormCancel').addEventListener('click', closeStatusForm);
$('#statusFormSubmit').addEventListener('click', submitStatusForm);
$('#statusFormReason').addEventListener('input', () => {
  $('#statusFormSubmit').disabled = !$('#statusFormReason').value.trim();
});
$('#coreOnly').addEventListener('change', paintChain);
$('#confirmResponseButton').addEventListener('click', confirmResponsePackage);
$('#verifyLedgerButton').addEventListener('click', verifyAuditLedger);
$('#staleCaseRefresh').addEventListener('click', () => {
  $('#staleCaseBanner').hidden = true;
  if (selectedCaseId) openCase(selectedCaseId);
});

let queueSearchTimer = null;
$('#queueSearch').addEventListener('input', () => {
  clearTimeout(queueSearchTimer);
  queueSearchTimer = setTimeout(refresh, 300);
});
$('#queueRisk').addEventListener('change', refresh);
$('#queueStatus').addEventListener('change', refresh);

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
        <span class="chip sm" title="${escapeHtml(step.source)}">${escapeHtml(term('event_source', step.source))}</span>
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
    `Чем выделено: ${detection.selected_by_title_ru || 'не зафиксировано'}. ${detection.reason || ''}`,
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

// Словарь грузится до первой отрисовки: иначе очередь успела бы показать коды, а затем
// перерисоваться словами — мигание на пустом месте.
loadVocabulary().then(() => {
  refresh();
  pollTimer = setInterval(refresh, POLL_MS);
});
