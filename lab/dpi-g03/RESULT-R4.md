# R4: исходный сбор завершён

19 ноября2026 UTC /20 ноября по Москве. Частный BelNet TESTNET, исходный
адаптер A2. Классические адаптивные циклы: **0/15**; это исходный замер.

| Проверка | Результат |
|---|---:|
| Новые train/validation сессии |71/71:62 ordinary TLS/WSS,9 BelNet |
| Raw capture, metadata, время, source pins |71/71;136 pins совпали |
| Строгая semantic coverage |68/71;3 UNKNOWN |
| Основные native RPC/download/upload |9/9 с nonce и точными counters |
| Все native попытки, включая старт и прогрев |35/45 подтверждены |
| Полная длительность на обоих концах |33/45; все9 main входят |
| Начальные DNS-отказы / timeout прогрева |9 /1 |
| Наблюдаемые native eth0 UDP1090 утечки |0 |
| Established-session timeout / fully-closed log |0 /0 |
| Pending / outbound-establish notifications |265 /265; не независимые disconnects |

Три UNKNOWN: validation Google, validation long-chat-3, train matched-upload-2-r2.
Во всех — partial TLS record. Для Google все13 accepted proxy connections
совпали с уникальными TCP bytes в обоих направлениях; gaps/conflicts не найдены.
UNKNOWN сохранены. Две validation-группы дают worst-case FP floor2/22=9,09%:
этому строгому view нельзя выдать сертификат бюджета5%.

Клиентские main-запросы заканчиваются на80,055–80,139s: подтверждена доставка, но полная
длительность операции не помещается внутрь основного80s интервала. Отсутствие
двух видов log-сообщений не доказывает отсутствие всех BelNet disconnects;
сохранены startup failures, first-hop warnings и неполные stream checkpoints.

[Строгий аудит](../../out/dpi-g03/root-review/b1-r4-acquisition-final.json) ·
[Native proof и отказы](../../out/dpi-g03/root-review/b1-r4-native-final.json) ·
[Допуск к новому анализу](../../out/dpi-g03/root-review/b1-r4-analysis-release.json).

Actual v4 fit отвергнут из-за ошибки consumer при TLS-потоке, начавшемся до
primary barrier и продолжающемся внутри него. Policy не создана; TPR/FPR
не получены. [Ошибка](../../out/dpi-g03/b1-r4-analysis-v4/fit.log) сохранена.
[FP floor](../../out/dpi-g03/root-review/b1-r4-uncertainty-floor.json) — отдельный
арифметический предел, не результат обучения или оценки модели.

Следующий отдельный view читает TLS header до завершения body. Он выбран после51
development-группы; это открытое изменение анализа. Старые результаты остаются.
Финальные25 test-сессий закрыты. Обход нового DPI или реального ISP пока не доказан.
