# G03 / B: новый DPI против жизнеспособного транспорта

19 ноября 2026. Протокол задаётся до B-трафика. G01/G02 и прежние test — только
development. A2 выбран как кандидат: framed TCP через REALITY, client expiry100ms.
Default retain в продукте не меняется; native crypto и IWP также не меняются.

## Что проверяем

Primary task: отличить **любой наш circumvention transport** от ordinary HTTPS
и legitimate WSS. Backend, клиент и app могут быть синтетическими, это отмечается.
Google/YouTube — отдельные настоящие публичные визиты. REALITY с другим payload
допустим только как diagnostic stratum, не как benign в primary FP calibration:
цензор вправе пытаться блокировать всю семью REALITY.

Отдельные scope labels: wrapper-only; native UDP в конкретном окне; nonce/полезная
нагрузка end-to-end в окне и в deployment; app failure. Обнаружение wrapper-only
валидно для primary transport task, но не является доказательством передачи
данных BelNet. Уровни и denominators публикуются раздельно.

## Сравнимая точка и горизонт наблюдения

Все классы проходят один локальный Docker CONNECT egress; native VLESS использует
HTTP dial detour, Chrome/Go WSS — обычный CONNECT. Relay не расшифровывает TLS;
это measurement fixture, не дополнительный VPS в продуктовой архитектуре.
PCAP — одна Linux VM clock domain. NetLog/CDP лишь подтверждает работу браузера.

Native и matched ordinary destination используют443. На первой ноде REALITY443
имеет genuine lab HTTPS/WSS fallback18444 и фиксированный framed receiver21990.
C++1090 и его PID не меняются. Старый принадлежащий лаборатории Go443 можно
остановить только после сохранения PID/exe/config и rollback команды.
`.test`/self-signed/SPKI — lab artifacts, не доказательство Internet TLS/probe
indistinguishability. IP, порт, SNI и cert values не входят в выбранные признаки;
TLS/client/cert/origin strata всё равно показываются отдельно.

**Primary horizon80s одинаков для ordinary и native. Его VM timestamp снимается
до запуска клиента и первого outerconnect.** Начальные TLS prefixes
PRIMARY; сложную bootstrap часть нельзя убрать в diagnostic. Capture82s с2s
grace. Новые flows в grace не создают новых обязательств primary.

Primary sampled windows: [0,8,16,24,32,40,48,56,64,72,78] секунд, каждое2s,
плюс первые2s всех новых TCP/TLS flows/reconnect внутри80s. First64 records —
только ограничение одного окна; подсчёт/coverage продолжается до конца80s.
Полный80s PCAP остаётся для long-flow/whole-session признаков на B1 train/val.
Набор окон сам по себе не объявляется непрерывным DPI каждой микросекунды.
Финальная политика перечисляет ровно свои окна/whole-flow признаки.

Глобальный file-order skew между разными5tuple — diagnostic, не автоматический
отказ всей группы. Genuine flow/record-causal clock issues остаются invalid.
PCAP не сортируется. Record completion учитывает max constituent/availability
timestamps; standalone G03 observer version/source/hash фиксируется отдельно.

## Конечная когорта и разделение

Всего96 основных session/deployment:

| Stratum | Train | Validation | Sealed test |
|---|---:|---:|---:|
| 72 matched local ordinary,6families | 36 | 18 | 18 |
| 12 public Chrome visits,4families | 4 | 4 | 4 |
| 12 fresh native deployments,3workloads | 6 | 3 | 3 |

Публичные family: Google homepage, настоящее YouTube playback, docs, downloads.
Один visit каждого family в каждом split. Видео Big Buck Bunny повторяется:
это session holdout, не проверка нового видео. CAPTCHA/HTTP error — benign TLS,
но не успешный поиск/воспроизведение; failures не перезапускаются до успеха.
CONNECT делает Chrome explicit TCP-only; QUIC/HTTP3 здесь не оценивается.

Local family: download/upload/RPC/push/chat/idle, по12 физических session:
6train/3val/3test. Для RPC/download/upload это по3 ordinary replica каждого
native source-workload (4 разных source-plan на family); seed/cadence/sizes
общие внутри пары, nonce и TLS session новые. Для push/chat/idle каждый source
новый. Клиенты Chrome и Go WSS сбалансированы18/18 train и9/9 validation/test.
36 matched sessions повторяют application cadence/sizes native
источников; ещё36 long-flow push/chat/idle controls держат legitimate WSS до80s, чтобы признак
«долгая TLS connection» не стал label shortcut. Объём ограничен заранее.

Native: RPC/download/upload, по4 deployment (2train/1val/1test). Каждый со свежей
native identity/data directory. Paired source-workload variants разных классов
имеют согласованный split, но не объединяются в одну физическую session FP.
Labels/class/group/split не передаются в wire; fixed16hex seed/fixed64hex nonce.
Workload source-ID и actual group-ID — только metadata. Задержки и сетевые
условия одинаково назначаются обоим классам, порядок контрбалансируется.

Начальные35s: native bootstrap и ровно3 функциональных warmup на5/15/25s,
timeout8s. Отдельная initial RPC attempt в0s обеспечивает ранний TLS у matched
ordinary; native получает такую же попытку. Её возможный cold-start отказ
сохраняется отдельно. Ordinary matched получает аналогичный старт, long/public traffic
не обрезается. Следующие45s — общий variable workload engine. Initial traffic
входит в primary80s. Native warmup failure сохраняется, end-to-end вывод
inconclusive; это не отсутствие детекта или удачный обход.

Машинные группы и порядок: [assignments.json](assignments.json), генератор
[make-assignments.cjs](make-assignments.cjs). Всего96 групп:71 B1 и25 B2.
Одновременно не более3 групп и1 native. Native равномерно распределён по слотам;
варианты одного source-workload не запускаются в одном batch. Все shadow-группы
работают без искусственного interruption; отдельный A2 проверил restart.

До B1 acquisition — полный `freeze-b1.json`: source/ELF/config/assets SHA,
observer semantics, группы/splits, workload seed derivation, client stacks,
порядок/ресурсный cap, capture/UTC и исходная версия транспорта. Train/val seed
открыты; test seed commitment делает независимый collector, значения не
используются для разработки и раскрываются только после policy freeze.
До готового freeze collector обязан отказать.

## B1 → инженерный ответ → B2

Сначала только B1:71 train/validation session/deployment из таблицы.
Defender может использовать B1 positive и negative, но никогда не читает test.
Основной противник — явные детерминированные правила, forest — отдельный.
Проверяем конкретные признаки, включая частые26-byte records как гипотезу
split header/payload writes. Их наличие не считается уникальным fingerprint
без измеренных ordinary FP. Не добавляем arbitrary sleep, чтобы пройти r10.

Допускается один явно записанный инженерный ответ по B1. Если изменён wrapper,
final adaptive attacker должен последним увидеть новый candidate: максимум6
дополнительных fresh native train/validation deployments (3/3, все3family).
Это optional development, не замена test. Все старые candidate failures остаются.

Затем freeze exact candidate, observer, rules/models и thresholds. B2 запускает
ровно25 новых sealed test session/deployment (22negative,3native) ПОСЛЕ этого UTC.
Никакого заранее записанного test или перебора до удачи. После чтения B2 — stop
audit; следующий цикл требует новой когорты/протокола.

## FP, coverage и блокировка

Primary FP — whole-session/group OR любой admissible hit во всех объявленных
окнах/flows/reconnects и persistent decision. Калибровка совокупная на benign
train/validation; дополнительно direct-rule-hit flow FP≤5%. Нельзя раздать
каждому правилу/окну собственные5%, затем скрыть рост OR. Eligible FP,
abstention, stack/family и capture coverage показываются отдельно.

При22 условно независимых normal test groups даже0FP дал бы одностороннюю95%
верхнюю границу около12.7%, не доказательство population FP≤5%. Фактически в test
16 negative source-workload clusters: повторные matched seeds не IID. Отдельно
показываем source-cluster OR FP; формулу22 IID не выдаём за доверительный интервал
этой когорты. Цель5% — empirical experimental gate.
Повторные окна не считаются независимыми людьми/сетями. IP-ban collateral вне
конкретной captured session не выдаётся за измеренный flow FP.

Каждое объявленное окно должно быть covered до конца: sparse ≠ censored.
Raw PCAP cap256MiB/group, ≤4 active groups; cap/packet drops/accounting mismatch,
missing SYN/TCP gap/clock anomalies сохраняются как unknown/incomplete.
Count cap2048 отсутствует. Full80s raw, capture start/end и counters сохраняются.
Все условия capture/file/metadata валидируются, а не заменяются abstention→bypass.

Native eligibility связывается с UTC UDP input/delivery counters, receiver tuple
и nonce/operation proof из .bdx service. SHA/bytes/RPC и duration проверяются
отдельно. Прямой UDP1090 запрещён и captured. App success, detector verdict и
реальное закрытие TCP — три результата. Fresh active enforcement после freeze
допускает только bounded private-client deny30s по найденному verdict; повторные
входы не обходят память. Долгий native25s/5min desync остаётся известным риском.

Итог конечного B: свежие FP/TP/coverage, functional delivery/reconnect, цена/потери,
что не получилось и один обоснованный следующий шаг. Без ISP/mainnet guarantees.
