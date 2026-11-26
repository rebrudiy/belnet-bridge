# Независимый review

Изменения родительских файлов не выполнялись. Данные реального трафика заморожены отдельно.

1. **P2, lifecycle:** v3 не отменял WebSocket при `p.closed`; после смерти UDP
   продолжал dummy polling. Родитель подтвердил и добавил watcher + regression test.
2. **P2, epochs:** старый монитор сохраняет model/hash/enforce на Accept, а cooldown
   берёт из текущего `serverLab`. После `/model` reset запоздалый старый verdict
   может записать deny в новый раунд. Нужна проверка generation перед deny/enforce
   либо обязательное завершение старых соединений перед сменой модели.
   Родитель подтвердил и добавил generation check для deny и закрытия соединения.
3. **P2, память lab:** `persistent_cooldown` append в Accept не обрезает decisions,
   хотя основной путь ограничивает список до 100000. Повторные запрещённые входы
   обходят ограничение памяти. Лучше общий bounded append helper.

Burst: реальный loopback TCP/TLS, burst8×8192, read/write socket buffers 512 — PASS.
На net.Pipe без буферизации poll1 блокируется: сервер пишет reply, клиент пишет
следующий poll и ещё не читает. Через2s context timeout. Это подтверждает зависимость
от доступной буферизации, но не воспроизводит проблему на обычном TCP. Возможное
усиление — читать replies одновременно с отправкой, сохраняя максимум8 outstanding.

Проверка retained sessions: lease берётся до upgrade, attach cancel/join перед заменой,
release обновляет idle lifetime; явного нового race/повреждения UDP не найдено.
Смена соединения создаёт новый encoder/decoder и может потерять queued/частичный UDP:
это явно допускаемая семантика потери, не reliable delivery. Размер0 сохраняется отдельно
от dummy, максимальный поддерживаемый datagram65507 помещается в codec.
Capture recorder ограничен12s/2048records, payload не сохраняет. Новых блокеров не найдено.

Два дополнительных теста находятся в `.go.txt`, чтобы `go test ./...` не пытался
собрать их как отдельный пакет. Они запускаются через Go overlay, без правки root:

```sh
go test -overlay out/dpi-v2/real/review/overlay.json \
  -run TestReviewBurstBoundedSocketBackpressure -count=1 -timeout 20s .
go test -overlay out/dpi-v2/real/review/overlay.json \
  -run TestReviewBurstUnbufferedDuplex -count=1 -timeout 15s .
```

Второй тест намеренно воспроизводит отказ и возвращает ненулевой exit code.
Наблюдения сохранены в `out/dpi-v2/real/review/results.json`.
