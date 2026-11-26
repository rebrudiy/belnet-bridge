# G03: остановленный контроль стенда

**После15 из71 B1-сессий остановили сбор: стенд не прошёл проверку качества.
Классификатор не калибровали; результата обхода или FPR здесь нет.**

| Наблюдение | Результат |
|---|---:|
| Физические сессии | 13 обычных +2 native |
| Полное покрытие по исходному строгому parser | 4/15 |
| Incomplete по parser | 11/15 |
| Native outer packet accounting | 2 unknown |
| Chrome teardown timeout после сохранения session | 7/9 |
| Проверенные frozen inputs | 91/91 совпадают |

Все проверенные timestamp reversals были между противоположными направлениями
одного TCP flow; per-stream reversals не обнаружены. Исходный parser ошибочно
смешивал это с нарушением причинного порядка. Сырые PCAP, строгие отчёты и
неудачные результаты сохранены. Для следующей версии заданы отдельные правила
порядка и явные маски неоднозначных adjacency features.

Оба native main-клиента получили данные через `.bdx`; сервис подтвердил8 из10
nonce-попыток. Две initial-попытки завершились до запуска DNS. Main-запросы
закончили на80.104/80.108с, поэтому это deployment proof, без утверждения, что
все main-байты лежат внутри PRIMARY80s. Внешний raw UDP1090:0 записанных пакетов,
ещё58 прямых попыток остановили DROP rules.

В native логах0 established-session timeout и0 fully-closed; при этом56 pending
и56 outbound-attempt timeout сообщений. Это не112 независимых disconnects.
PID, SID и UDP tuple постоянны в пяти доступных snapshots; последний79s не
покрывает всю финальную часть78–80s.

Собственные контейнеры удалены. Старые Go443 listeners восстановлены с точными
argv/environment и проверенными PID. Остальные56 B1-сессий не запускали.
Новый R2 сначала проходит отдельный диагностический qualification batch.

Проверить: [независимый контроль](../../out/dpi-g03/root-review/b1-checkpoint.json),
[native audit](../../out/dpi-g03/root-review/native-checkpoint.md),
[остановка](../../out/dpi-g03/collector-checkpoint/operator-stop.json),
[восстановление](../../out/dpi-g03/collector-checkpoint/cleanup-restoration.json),
[R2 протокол](PROTOCOL-R2.md).
