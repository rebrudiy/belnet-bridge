# G02 / A2: не передавать устаревшую native UDP очередь

19 ноября 2026. Все G01 данные, код и ELF до изменения архивированы.
Причина следующего шага: G01 overall32/32phase, framed16/16 и низкий overhead,
но client enqueue→write-start доходил до1.6s при двухсекундном outer outage.

## Предварительно заданная гипотеза

Opt-in `udp-stream-client -max-queue-age 100ms` отбрасывает datagram, если
на момент write-start его возраст после UDP receive превышает100ms.
По умолчанию0: retain, прежнее поведение. Server downlink policy не меняется.
Wire handshake, SID, токен, фиксация target и native crypto не меняются.
Write-start относится к локальной записи Go adapter → core. Буферизация
самого core, внешний TCP и фактическая IWP доставка этим пределом не ограничены.

Это контракт **freshness у передаваемых клиентом datagram**, а не обещание
доставки всех UDP за100ms. Expired input считается потерянным; его реальные
байты/число/возраст сохраняются. All-input maximum не уменьшается исключением
expired. Blocked-write измеряется отдельно; outage не исключается из истории.

## Конечный план

Четыре новых native deployment, порядок ABBA:

| Deployment | Режим |
|---|---|
| 1 | Framed REALITY, retain0 |
| 2 | Framed REALITY, max-age100ms |
| 3 | Framed REALITY, max-age100ms |
| 4 | Framed REALITY, retain0 |

Для каждого новый native identity/data directory. Все это development;
старые test не используются как новый holdout. Ровно три warmup запроса
на5/15/25s, timeout8s, затем45s фаза с nonce4096/16384 на0/3/12/17/22/27/32/37s,
timeout5s. Client core останавливается на10s и запускается через2s.
Native и UDP adapter сохраняют PID. Ни reroll до успеха, ни последующий
подбор порога expiry по этим четырём случаям не допускаются.

Перед экспериментальным deployment/traffic фиксируются actual adapter/core/helper ELF SHA,
config/private-asset SHA, source/build evidence, версия и план. Один run ID,
отдельный файл на каждую попытку. Начало/конец interruption фиксируются в VM
UTC; host-vs-VM offset и uncertainty измеряются, свежесть proof проверяется
в одной clock domain. PCAP и packet metadata тоже VM UTC.
Offline key generation и syntax checks в Docker --network none допускаются
до freeze, чтобы можно было зафиксировать уже существующие config/binary SHA.

## Гейты и отчёт

- Точность UDP и SID/tuple continuity не должны ухудшиться; Linux0..65507
  и malformed/cancel/lifecycle tests остаются обязательными.
- Дляexpiry ни один успешно отправленный datagram не имеет возраста
  input→write-start>100ms. Отдельно retained/expired/forwarded/write-failed,
  queue overflow, bytes, actual observed age и blocked-write.
- Все8 фазовых HTTP результатов на deployment и свежие post-restart nonce
  сохраняются. Отдельно ≤10s observation gate для первого гарантированно
  нового успешного ответа, без заявления о точном моменте recovery.
- Receiver FIFO остаётся отдельно измеренным. Нельзя назвать max-forward-age
  end-to-end latency или отсутствие потерь; TCP head-of-line остаётся.
- Расход оценивается на одной фазе по actual cipher/native UDP, с учётом
  retransmission/заголовков и clock uncertainty. Dummy, idle и native retransmits
  показываются отдельно, при отсутствии доказательства — unmeasured.
- Здоровый последний warmup обязателен; при его отказе app comparison
  inconclusive. Native/adapter PID и tuple проверяются до/после interruption.

После четырёх deployment — stop audit и явное решение. B по-прежнему закрыт.
Никаких claims о FPR/DPI/ISP по этому UDP freshness checkpoint.
