# REALITY с настоящим BelNet

**Первое подключение работает. После перезапуска sing-box бесшовного восстановления
в этом опыте нет.** Вместо UDP echo использован настоящий C++ BelNet и nonce HTTP
сервис внутри `.bdx` сети.

```text
BelNet client 10.88.0.41
  UDP → DNAT → local sing-box 19091 / 19092
  TCP / REALITY / VLESS / Vision / XUDP → first BelNet node 19443
  sing-box на той же ноде → её настоящий IWP UDP 1090
  BelNet paths с hops=3 → .bdx HTTP service
```

В каждом entry namespace отдельно работали sing-box и TLS decoy. Дополнительного
VPS нет. Decoy — закрытый self-signed TLS1.3 endpoint: это проверка интеграции,
а не доказательство маскировки под обычный публичный сайт.

| Группа | Split | Nonce HTTP успешно | Пригодные TLS потоки |
|---|---|---:|---:|
| coldstart 0 | train | 2 / 2 | 1 |
| restart 1 | train | 0 / 2 | 2 |
| restart 2 | train | 0 / 2 | 2 |
| restart 3 | validation | 0 / 2 | 1 |
| restart 4 | test | 0 / 2 | 0 |
| restart 5 | test | 0 / 2 | 0 |

Coldstart: ответы на свежие nonce, тело 4096 / 16384 байта, 329 / 36 ms.
Затем перезапускали только клиентский sing-box; native BelNet, его ключ и процесс
оставались теми же. Первые два запроса после restart получили HTTP timeout20s;
следующие восемь — ошибки lookup `.bdx` около5s. Наблюдение после первой ротации
продолжалось примерно113s; восстановление позднее этого времени не проверялось.

Нативный лог содержит5 `established` и18 `fully closed` событий для разных
контекстов, включая повторное установление entry сессий. Это не18 независимых
disconnects. Точные строки сохранены в `native-events.json`; приложение при этом
после ротаций не прошло ни одного nonce proof.

Server route принудительно направляет UDP только на `10.88.0.11:1090` или
`10.88.0.12:1090` соответствующей первой ноды; остальные назначения reject.
У клиента raw UDP1090 к прочим нодам запрещён. `iptables.txt` сохраняет правила.
Используется свежая identity и копии текущих подписанных contacts шести нод.
Native binary — TESTNET build с ранее документированным queue-wakeup patch;
точные image/binary SHA-256 находятся в manifest. Три configured hops в маленьком
testnet не гарантируют три разных оператора или три неповторяющихся identity.

## Данные и границы вывода

`out/dpi-v2/mature-native/trials.json` содержит все12 nonce попыток.
`observations.json` содержит6 полных TLS/TCP prefixes: train5 / validation1 / test0.
`reassembled.json` содержит причины исключения остальных потоков. Последний PCAP
пуст: это отсутствие пригодного наблюдения, а не успешный обход.

PCAP использует timestamp завершения записи; основной эксперимент — клиентские
socket callbacks. Применять frozen DPI к этим6 потокам можно только как отдельную
exploratory проверку. Все6 групп разделяют один native процесс и его историю:
заранее назначенные split не делают их независимыми клиентами. Модель и threshold
здесь не обучались, DPI ничего не блокировал.

До/после UDP source port не измерены парой в этом опыте. Предыдущий изолированный
[mature baseline](../mature/README.md) обнаружил смену server UDP source при restart;
это объяснение согласуется с потерей continuity, но здесь не доказано причинно.
Дополнительный loopback UDP metadata capture видит также другие процессы общего
entry namespace; весь этот трафик нельзя приписывать нашему клиенту.

## Повторение

Нужны уже запущенные шесть native relays и `.bdx` nonce service, актуальные fixtures,
свободный IP `.41`, Docker image и pinned sing-box из соседнего mature baseline.
Runner не запускает и не перезапускает существующие ноды/основной клиент.

```sh
node lab/dpi-v2/mature-native/runner.cjs
node lab/dpi-v2/mature-native/extract.cjs
node lab/dpi-v2/mature-native/summarize.cjs
```

Существующий результат и native identity runner откажется перезаписать. Для нового
опыта нужен новый run/data каталог и отдельное заранее назначенное разбиение.
Extractor использует существующий offline reassembler: меняет только port selector
443→19443 и возвращает null timestamp для пустого PCAP. Исходные PCAP неизменны.
Первый отказ парсера на пустом capture сохранён в `extraction-attempts.json`.

Credentials и decoy keys находятся только в ignored `out/.../private/`.
Все созданные `bb-dpi-mature-*` контейнеры удалены; существующие ноды и основной
клиент оставлены работающими. Ничего не публиковалось и не отправлялось наружу.
