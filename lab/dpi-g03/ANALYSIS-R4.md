# R4: анализ с явной неопределённостью

Решение принято во время B1, после первых15/71 development-групп.
Это пересмотр анализа после просмотра train/validation, не исходная
preregistration. Все71 acquisition выполняются по прежнему freeze;25 test
остаются закрыты. Предыдущие результаты, source pins и UNKNOWN сохраняются.

## Причина

В validation Google tcpdump и PCAP содержат одинаковые13623 пакета,
kernel drops0. При этом observer-v4 сообщает primary partial TLS record.
Независимая сверка всех13 accepted proxy connections подтвердила точные
зашифрованные bytes в обе стороны; TCP gaps/conflicts не найдены.
Две downstream TLS-записи остались частичными; ещё одна TCP-пара не несёт
payload. Это не основание переписать frozen coverage verdict.

[Raw acquisition audit](../../out/dpi-g03/root-review/b1-r4-progress-02.json) ·
[Wire audit](../../out/dpi-g03/root-review/b1-r4-google-wire.json).

## Что считаем

| Слой | Значение |
|---|---|
| Acquisition | Счётчики, PCAP, процесс capture, timing и provenance |
| Semantic coverage | Можно ли полностью восстановить нужные признаки |
| Наблюдаемое обнаружение | Правило сработало на проверяемом пригодном view |
| Неопределённость | Пропущенные признаки могли изменить решение |
| Native delivery | Отдельный nonce/count/integrity proof приложения |

Одинаковые packet counts не превращают semantic UNKNOWN в полный результат.
Ошибки metadata/provenance и непригодные окна не дают признаков для scoring.
Пригодные ранние окна можно сохранить как ограниченные наблюдения.

## Совместный бюджет ошибок

Для каждого benign train/validation split отдельно:

- `observed_FP` — группы с наблюдаемым rule hit.
- `unknown` — группы с неполной semantic/capture coverage.
- `worst_case_FP = size(observed_hit_groups UNION unknown_groups)`.
- `worst_case_FPR = worst_case_FP / all_declared_benign_groups`.

Unknown, уже имеющий observed hit, считается один раз. Неполная benign-группа
расходует один потенциальный FP до выбора порогов. Она остаётся в знаменателе.
Все правила, окна и переподключения используют один общий бюджет5%.

Для actual flows считаем тот же union по physical primary flow inventory,
включая SYN-only попытки без TLS; grace-only не входят. Flow-specific unknown
разрешён только если все причины неполноты проверяемо сопоставлены потокам.
Неразрешённая global/capture/index/provenance ошибка затрагивает все primary
flows группы. Неполный или недостоверный inventory запрещает certification:
неизвестное количество потоков нельзя заменить удобным знаменателем.

Если один только uncertainty floor превышает5%, результат —
`INCONCLUSIVE`, без certified policy. Данные не удаляются, целевой бюджет
не увеличивается и новая сессия не заменяет неудачную. Observed/eligible FPR,
support и worst-case FPR публикуются отдельно.

## Положительные группы и финальная проверка

Пригодный observed hit на incomplete positive — нижняя граница обнаружения.
Отсутствие hit при неполных данных означает UNKNOWN, а не обход.
Отсутствие TLS-признаков — abstention. Failed native requests остаются failed.

Новый analysis implementation — отдельный ensemble-v4. V2/V3 и их frozen
результаты не меняются. Actual fitting начинается только после полного71-group
аудита и проверки этого контракта. Финальные policies и transport ELF
замораживаются до нового B2; его UNKNOWN подчиняются тем же правилам.

Цель остаётся прежней:15 фактических парных classical-DPI/wrapper циклов,
затем рефакторинг и понятная документация. Этот пересмотр анализа циклом
не считается. Shadow PCAP scoring не является live DPI enforcement.
