# G01: готовая маскировка и сохраняемый UDP-сеанс

19 ноября 2026. Следующий конечный цикл после диагностического dpi-v2.
Все старые test теперь development; их нельзя назвать новым финалом.

## Гипотеза

Готовый sing-box VLESS/REALITY перевозит TCP до первой ноды. Тонкий локальный
адаптер сохраняет SID → UDP socket и передаёт uint32-length + UDP datagram.
Это должно устранить XUDP zero/large truncation и смену native UDP tuple при
перезапуске только внешнего core, с меньшим расходом, чем постоянные v3 cells.

```text
native UDP → local Go adapter → local sing-box TCP → REALITY
  → sing-box ON FIRST NODE → loopback Go adapter → fixed IWP UDP1090
```

Внутренний plaintext TCP разрешён только на literal loopback. На сервере
назначение фиксировано оператором. SID — случайные 32 байта, тот же при outer
reconnect; токен проверяется до создания UDP socket. Shared token означает
общего principal: SID не привязан к отдельному UUID. Внешняя авторизация —
REALITY/VLESS; node-local compromise вне защиты. Не изобретаем TLS/шифрование.

## A. Конечный engineering checkpoint перед новым DPI-сбором

1. Кодек: точные UDP0/1/1200/60000/65507, запрет oversized до allocation,
   ограниченный handshake и stage deadlines, partial I/O, malformed input.
2. Локальный smoke через настоящий pinned REALITY: два SID; старый attachment
   отменяется до нового; плохой токен не получает UDP state. Зафиксировать tuple
   у UDP-получателя до/после forced TCP close и двухсекундного core restart.
3. Четыре fresh native deployment: два v2 baseline, два framed REALITY.
   Это development viability, не статистическая проверка населения/FP.
   Для каждого новый native identity/data directory; никакого переноса неудачных
   routes предыдущей identity. Receiver остаётся на той же первой ноде.
4. У каждого максимум три фиксированные warmup HTTP попытки, все сохраняются.
   Без успешного последнего baseline дальнейший app-результат inconclusive.
5. Измеряемый этап45s: nonce4096/16384 в начале; на10s outer connection reset
   (v2 WSS rotation / REALITY core restart на2s), новые nonce после reset.
   Native процесс и UDP-адаптер при этом не перезапускаются. Максимум recovery
   ожидания30s; отдельно gate восстановления ≤10s от окончания interruption.

Базовые цели A: точность0..65507; неизменный UDP tuple для прежнего SID;
изоляция разных SID; настоящий post-reconnect `.bdx` nonce; отсутствие raw UDP
обхода. Расход: реальные cipher bytes / реальные native UDP bytes, цель ≤2x
на одинаковой полезной нагрузке, idle отдельно. Очереди ≤100ms — измеряемая цель,
не гарантия произвольного входа. Нарушение остаётся провалом, не заменяется
поднятым лимитом. Stop audit после четырёх deployment: продолжать сбор DPI
можно только с отдельным зафиксированным решением о жизнеспособности кандидата.

## B. Следующий fresh DPI checkpoint, если A жизнеспособен

До его запуска нужен отдельный `freeze.json`: source/binary/config SHA,
точные группы, seed, очередь запуска, длительность, окна и budgets. Без него
коллектор должен отказать. Конечный план:72 matched local benign sessions,
12 новых публичных browser sessions,12 fresh native deployment для baseline
и кандидата. Train/validation/test назначаются whole deployment/session,
варианты и reconnect одного deployment не расходятся по split. Порядок
контрбалансирован; одинаковые сетевые условия у обеих меток. Новые независимые
deployments не считаются независимыми сетями/операторами.

Основная метрика — session/group OR любого решения во всех окнах и reconnects.
Совокупность окон/правил калибруется совместно на benign train/validation.
Публикуются flow FP, group FP, eligible FP, abstention, per-family coverage.
Цель5% эмпирическая; при меньшем59 test-groups даже0FP не доказывает верхнюю
95%-границу ниже5%. Поздние окна — первичная часть политики, не постфактум
применение раннего порога к другой области.

Длительность каждой записи45s. Окна0–2,8–10,18–20,28–30s от первого TLS23
и первые2s каждого reconnect; одинаковое расписание у benign и positive.
Доступность объявленного окна подтверждается до его конца. Полный outer PCAP
сохраняется bounded capture256MiB на группу; dropped packets/достижение cap
помечают incomplete/censored. Извлечение TLS streaming; лимита2048 записей нет.
Не требуем активности в каждом окне, но различаем sparse и censored.

На adapter пишутся UTC packet metadata (direction,bytes,session hash,connection,
UDP tuple) и интервальные counters. Native-positive eligibility требует UDP
в конкретном классифицируемом окне и nonce `.bdx` с временем service/client;
wrapper-only и app failures — отдельные категории. Прямой UDP1090 запрещён.
Для всех классов один PCAP observer/clock; NetLog только дополняет playback
evidence. Смена TLS stack/cert/origin проверяется отдельно, не служит единственным
отличием меток. Общий group verdict сохраняется при reconnect на30s.

Сначала train/validation → инженерная гипотеза и изменение → frozen adapter/
DPI policy → новый sealed test. Test не выбирает пороги или следующий профиль.
Классический DPI основной, forest — отдельный сильный противник с собственными
FP gates. Невыполнение цели не разрешает ослабить DPI ради заявления об обходе.

## Обязательный результат цикла

Кратко: tuple/recovery/UDP correctness, расход/задержка, свежий FP/TP и scope,
что осталось неработающим. Все попытки и невалидные baseline сохраняются.
Дальше — один явно описанный следующий шаг, без бесконечного набора контролей.
Версии и параметры A фиксируются в run manifest до первого smoke/native теста.

## A: уточнение исполнения до первого native запуска

Подготовленный helper обслуживает отдельный `.bdx:8082` и пишет JSON UTC для
nonce join. Warmup: ровно три запроса на5/15/25s, timeout8s. Измеряемые запросы
на0/3/12/17/22/27/32/37s фазы45s, timeout5s. Реальное завершение interruption
определяется по runtime UTC; recovery засчитывает только запрос, начавшийся
после него. Пересекающиеся запросы сохраняются отдельно.

У v2 двухсекундный client TCP443 DROP и WSS rotation; у framed режима —
двухсекундная остановка только outer core. Native и адаптер сохраняют PID.
Очереди пока FIFO без expiry. Input → write-start и blocked-write измеряются
отдельно, включая outage; 100ms gate не обходится исключением старых пакетов.
На framed получателе timestamp и overflow counter есть также у downlink FIFO.

Явное отклонение порядка: сначала исполняются четыре native deployment.
Полный Linux UDP/framing0..65507 уже проверен как код, но isolated REALITY
zero/large-datagram smoke остаётся pending отдельным bounded run. Нельзя
подменять его unit-тестом или объявлять PASS по native MTU-пакетам.
Это уточнение записано до сбора, не выбрано по результату native эксперимента.
