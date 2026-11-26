# G03 R2: исправленный сбор, затем инженерный ответ

19 ноября 2026. Поправка к [исходному протоколу](PROTOCOL.md), до нового трафика.
Цель, классы, 80s primary, окна, нагрузки и бюджет FP остаются прежними.
Основной противник — классические сетевые правила; ML — дополнительный.

## Почему новый запуск

Первый B1 остановлен после 15/71 групп: 11 отверг frozen observer,
2 native capture имеют несовпадающие packet counters, 7 browser helper
завершились по watchdog. [Независимый аудит](../../out/dpi-g03/root-review/b1-checkpoint.json)
сохраняет эти ошибки. Старые группы — development стенда; калибровка на них
запрещена. Старые freeze, PCAP, observer и решения не переписываются.

## Что исправляем

| Проблема | R2 | Что по-прежнему запрещает вывод |
|---|---|---|
| Порядок встречных TCP-направлений в файле | Отдельная диагностика; явная маска чувствительных правил | Настоящее нарушение причинности внутри направления |
| Захват при продолжающемся трафике | Quiesce после82s, 500ms drain, затем bounded stop | Drops, cap, missing counters, несошедшийся packet accounting |
| Завершение Chrome после замера | Ограниченное ожидание выхода, проверка жизненного цикла | Watchdog/forced cleanup остаются ошибками, session.json их не отменяет |

Observer-v2 сохраняет исходный PCAP. Проверки TCP sequence, конфликтующих
overlap, gap, максимального времени constituent/доступности записи и
причинности внутри направления остаются строгими. Logical metadata merge
выбирает earliest64 завершённых records одного окна; сохраняются raw timestamp
и ordinal. Это новая семантика, а не исправление старых результатов.

При неоднозначном порядке встречных records, включая совпадающие timestamps,
маскируются r05/r06/r10/r15 в затронутом окне и lf05 в whole-flow наблюдении.
Маска применяется **до калибровки и evaluation**, привязана к версии/хешу
observer и проверяется ensemble. Длины и корректные признаки внутри одного
направления могут остаться пригодными. Нулём, искусственной задержкой или
подправленным timestamp отсутствующее свидетельство не заменяется.
Полный контракт маски, schema и тесты должны быть зафиксированы до R2 freeze.

В82s quiesce атомарно запрещает новые CONNECT и закрывает существующие;
process/listeners/network namespace остаются живы. После500ms drain tcpdump
останавливается с таймаутом. Admin — literal loopback, без публикации наружу.
VM-время снимается до/после quiesce и остановки capture. Не повторяем stop
или workload до совпадения счётчиков.

[Две development-проверки](quiesce-preflight/README.md) дали точные packet
счётчики, но по24B down wire сверх forwarded bytes во время quiesce.
Их qualified=false сохраняется. В R2 полнота PCAP и forwarded-byte accounting
публикуются раздельно. Весь непереданный хвост показывается с VM timestamp;
только доказанно post82s хвост не считается потерей внутри primary/grace.
Содержимое зашифрованного record не угадывается. Необъяснённое расхождение
внутри измеряемого горизонта остаётся UNKNOWN. Native UDP-потери проверяются
отдельно; эти24B не являются доказательством потери UDP или BelNet disconnect.

## Свежая когорта и запрет утечки test

[assignments-r2.json](assignments-r2.json): те же96 group IDs, source seeds,
splits, batches и нагрузки. Все71 train/validation запускаются заново со свежими
TLS/native identities и355 новыми nonce (main, initial,3warmup на группу).
Старые15 не добавляются в знаменатель новой калибровки. Повторяемые source
plans по-прежнему не считаются независимыми workload samples.

Все25 test rows идентичны исходным. Используется **тот же** private test vault
и его SHA из первого B1 freeze; его нельзя пересоздать или перезаписать.
Значения test не читаются при разработке политики. Fresh train/validation
nonce и происхождение зафиксированы генератором; сам файл не разрешает сбор.

Новый collector freeze должен включать эту поправку, assignments-r2, версии
и SHA observer-v2/longflow-v2/ensemble/runtime-v2, helper/ELF/config/assets,
старый test commitment и все тайминги. До полного freeze новый B1 запрещён.
Старые исходники и binary pins проверяются по старому архиву.

Перед полным B1 — ровно одна qualification-партия Q из3 свежих80s групп:
native RPC, Chrome Google, Go WSS idle. План — [qualification-r2.json](qualification-r2.json).
Те же v2 binaries/pipeline и проверки качества, отдельные q- IDs, diagnostic scope,
development split и новые nonce. Q не читает private test vault, не расходует
nonce основного B1 и не входит в calibration/FP/TP. Её собственный freeze обязателен.
Цель — проверить интеграцию таймингов, teardown, capture и native proof.
Провал сохраняется и останавливает основной сбор до явного исправления и новой
версии; повторов до удачи нет. Даже успешная Q не заменяет все71 B1 группы.

## Решение после сбора

15 коротких,6 whole-flow и2 capture-order правила получают **одну совместную калибровку**:
group OR и direct-hit flow FP≤5% на train/validation. Flow denominator общий;
whole-flow не создаёт фиктивного второго TCP flow. Source-cluster OR FP,
coverage, masks, sparse/disabled abstention и functional native proof
публикуются отдельно. Недостаток данных не означает успешный обход.

Два companion-признака считают alternation и равные соседние длины в порядке
завершения TLS decoding при чтении capture (ordinal), без выводов о временном интервале.
Они сохраняют доступный наблюдателю вид даже при маске logical-time правил.
Capture order зависит от сенсора; он не объявляется точным физическим порядком.
Их версии/формулы/ordinal provenance фиксируются вместе с остальными23;
отдельного FP-бюджета у этой пары нет. Обычные coverage-ошибки маска не отменяет.

Далее — один измеренный ответ транспорта, максимум6 свежих native development
групп для последнего ответа детектора и финальный freeze до25 новых B2 test
сессий. После просмотра test пороги не меняются. Активная блокировка требует
отдельной конечной проверки; shadow verdict её не доказывает.
R2 не считается одной из15 адаптивных итераций улучшения обхода: это исправление
измерений. ISP/mainnet и распространение скрытых адресов остаются вне scope.
