# DPI / BelNet lab

Краткий результат: [RESULT.md](RESULT.md). Эта лаборатория проверяет
обнаружение, реальное закрытие соединения и доставку BelNet отдельно.
Все native измерения — частный TESTNET, исходный BelNet480aafb3 с ранее
зафиксированной queue-wakeup правкой. Native3 настроенных hops могут
повторять relay identities. Mainnet и реальный ISP не проверялись.

Архитектураv3: локальный UDP → TLS1.3/WebSocket → процесс на первой ноде →
её фиксированный IWP UDP. Ячейки фрагментируют датаграммы; poll/reply, размер,
паузы и bounded pipeline задаёт профиль. Дополнительного VPS нет.
Слои шифрования BelNet не меняются. V3 — opt-in исследовательский режим;
CLI v2 и сохранение UDP socket между WSS-переподключениями остаются.

## Проверки кода

```sh
go test -race ./...
go vet ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o lab/dpi-v2/bin/main.test .
docker exec bb-dpi-v2-client /lab/dpi-v2/bin/main.test \
  -test.run TestCellsCarryCompleteUDPAndCancel -test.v
```

Linux socket test проверяет0/1/1200/8192/60000/65507 байт. Darwin по умолчанию
ограничивает UDP maxdgram9216, поэтому там большие размеры проверяет кодек,
а полный сетевой путь — Linux. Пакетный transport не даёт ACK/reliable delivery:
запись, прерванная после извлечения ячейки из очереди, может потерять UDP.

## Повторение измерений

Нужен уже собранный native Docker runtime и отдельные частныеfixtures/CA/token:
см. [native setup](../../docs/NATIVE_TRANSPORT.md). Одного checkout недостаточно
для воспроизведения бинарного BelNet TESTNET. Исходные ключи не входят в отчёт.
Скрипты отказываются перезаписывать измеренныеrun directories.

1. Собрать Linux transport/control в `bin/`, runtime по `Dockerfile`.
2. `python3 lab/dpi-v2/bootstrap.py` запускает только частный testnet и клиента.
3. `acquire.py` собирает v2/v3; `rounds.py` —15 заранее объявленных вариантов.
   После смены server binary нужен новый native client identity; старый run
   сохраняется. Проверять реальную готовность HTTP, а не только запуск процесса.
4. `cmd/control` собирает matched не-echo нагрузки. Использовать новый seed,
   целые группы и тот же TraceHeader; предварительные fixture не являются final.
   Реальный браузерный сбор описан в `real/` и не использует профиль пользователя.
5. `dataset.py` соединяет eligible данные. Зафиксировать `dataset-final.json`
   и `late-dataset-final.json` до обучения/финальной оценки.
6. `classical/series.py` сохраняет15 политик, calibration snapshots и final test.
   `cmd/evaluate` — отдельный вспомогательный forest. Test не участвует вFit.
7. `enforce.py` делает отдельную live проверку на прогретом native клиенте.
   REJECT ограничен private entry namespace, source10.88.0.40, TCP443;
   finally удаляет точное правило. Пользовательские host firewall не меняются.

Точные параметры находятся в `PROTOCOL.md`, `rounds/plan.json`, исходных
командах/JSON. Нарушения FPR, неполные окна, неудачный прогрев, DNS/HTTP timeout,
невалидный старый runtime и native outages сохранены отдельно.
JSON/PCAP и временные ключи лежат в ignored `out/` и `run/`; их нельзя считать
готовым публичным пакетом. Исторический15-model run не переименован в эти15
инженерных гипотез.

Не входит в результат: IP-block обход/выдача адресов, production rootless hook
в BelNet, mainnet admission, мобильная упаковка, защита от correlation и
доказанная неотличимость от браузерного HTTPS. Утечка адреса позволяет IP-block;
утечка токена требует ротации и не расшифровывает чужие TLS-сессии.
