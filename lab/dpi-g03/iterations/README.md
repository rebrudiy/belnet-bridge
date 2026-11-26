# 15 адаптивных classical DPI / transport циклов

Сейчас **0 фактических циклов, 15 pending**. Это offline ledger и планировщик metadata. Он не запускает collector, Docker, fit, Chrome и не открывает test seeds.

```sh
node --test lab/dpi-g03/iterations/index.test.cjs
node lab/dpi-g03/iterations/cli.cjs validate lab/dpi-g03/iterations/ledger.json
```

API: `require('./lab/dpi-g03/iterations/index.cjs')` экспортирует `createLedger`, `validateLedger`, `planNativeRound`, `rowDigest`, `digest`. Все ссылки на артефакты имеют `{path, sha256}`; SHA проверяется по фактическим bytes. Пути vault/B2 запрещены. CLI запускается из корня репозитория.

## Один цикл

1. После полного B1-аудита выбрать измеренный **train** признак. Записать гипотезу, UTC и SHA baseline (цикл1) либо `rowDigest` предыдущей завершённой строки. Следующие14 гипотез заранее не заполняются.
2. Изменить classical правило/порог, зафиксировать source, ELF и policy. Изменение текста/времени/названия правила не считается. Для engineered rules сравниваются реальные terms, thresholds и memberships.
3. Повторить joint FP на **том же полном benign train/validation corpus**, все правила/flows/windows/reconnects вместе. Группы и flow inventory сохраняются; бюджет5% отдельно для каждого split.
4. После измерений выбрать реальное изменение wrapper source+ELF либо transport settings. Подготовленный ранее бинарник допустим, если его выбор действительно сделан сейчас. Capture repair и ML не являются циклом.
5. Freeze кандидата, затем3–6 новых native deployments: RPC/download/upload, оба development split, по одному одновременно, новые identity и nonce. Сохранить все5 initial/warmup/main попыток, включая DNS failures.
6. Classical attacker получает последний ход после свежего трафика; повторить его shadow verdict и benign FP. Зафиксировать bytes, input→write-start latency и учёт forwarded/expired/dropped/failed UDP.
7. Закрыть строку `accepted` или `rejected` с причиной. Следующая гипотеза появляется только после этого результата.

`accepted` означает пригодность выбранного варианта по проверяемым условиям, **не гарантированный DPI bypass**. Отчёт отдельно показывает detection, abstention, nonce delivery и FP. Shadow PCAP scoring не доказывает live blocking/recovery.

## Минимальные evidence-артефакты

Полный синтетический пример DTO создаётся функцией `fixture()` в `index.test.cjs`; это тестовые временные файлы, не данные B1.

| Ссылка manifest | Обязательная проверка |
|---|---|
| `feature` | измеренный train feature, raw evidence, время до выбора гипотезы |
| `detector_delta` | before/after policy, actual semantic delta, source/ELF/engine hashes |
| `benign_initial`, `benign_final` | raw evaluation, неизменные IDs/denominators, actual observed FP counts и ratio |
| `wrapper_build` | before/after source+ELF/settings, build binding, адаптивное время выбора |
| `native_proof` | новые identity,80s capture,3 семейства, nonce/service byte proof, raw sources |
| `last_attack` | policy freeze после последнего native capture, raw classical verdict каждого нового group |
| `cost` | application/outer bytes, полный баланс bridge UDP inputs, VM-clock latency, raw sources |

Manifest имеет `kind: measured_classical_transport_pair`, `origin: actual_measurement` и ссылки из таблицы. Source manifest содержит `kind: source_manifest, files:[{path,sha256,logical_path}]`. ELF проверяется по bytes и SHA. Нормализованные DTO не заменяют первичные источники: collector/analysis adapter должен сформировать их из master/index/results/service/PCAP и сохранить ссылку на каждый вход. Ledger проверяет доступные связи и арифметику, не является независимым PCAP decoder.

Развёрнутый wrapper обязан быть ELF. Для offline DPI допустим также фактически
использованный macOS ARM64 Mach-O executable: проверяются magic, архитектура,
тип executable и границы заголовка команд. SHA policy должен ссылаться именно
на измеренный score engine; Linux-бинарником его задним числом не подменяем.

Baseline:71 исходных primary train/validation groups, master+index refs, `benign_corpus_sha256`, `measurement_contract_sha256`, `completed_at`. Healthy baseline: `kind: healthy_primary_B1, healthy:true`. По [ANALYSIS-R4](../ANALYSIS-R4.md) допустим полный acquisition с неопределённостью: `kind: completed_primary_B1, acquisition_complete:true, analysis_status: INCONCLUSIVE`; semantic UNKNOWN сохраняется.

Для нового worst-case evidence обязательное поле `analysis_contract: r4-worst-case-benign-fp-v1` совпадает с policy. Validator заново считает `union(observed hit, incomplete)` по всем declared benign groups и `union(hit flows, potentially_affected_primary_flows)` по actual primary flow inventory. Каждая affected flow должна находиться в inventory; `uncertainty_bounded` проверяется. Raw `coverage_complete:false` сохраняется.

Сверяются actual v4 metrics: `worst_case_false_positive_groups`, `worst_case_group_fpr`, `worst_case_direct_rule_hit_false_positive_flows`, `worst_case_direct_flow_fpr`, `unbounded_benign_inventory_groups`, `incomplete_benign_potential_false_positive_groups`. Certified допустим, если оба worst-case FPR≤5% отдельно на train и validation и inventory bounded. Например,1 unknown из22 групп может укладываться в бюджет; unknown+hit одной группы/flow считается один раз. Если uncertainty floor превышает5% или inventory unbounded, итог INCONCLUSIVE, без successful acceptance; фактически измеренный rejected цикл сохраняется. При unbounded inventory worst-case flow FPR обязан быть null.

Старый strict evidence без analysis contract остаётся совместимым: любой UNKNOWN требует явный `certification: INCONCLUSIVE` и запрещает accepted. Сам анализ ensemble-v4 остаётся отдельным; ledger проверяет его raw decisions/metrics и не заменяет decoder. Неизвестный native capture или неучтённые UDP inputs не превращаются в доказательство обхода.

`loss` здесь относится только к bridge input→forward-write, а `latency` — к очереди до начала записи. Это не измерение всей сетевой потери или end-to-end задержки. При0 forwarded latency явно not-applicable, а не0ms.

## Подключение существующего native runner

```js
const { planNativeRound } = require('./lab/dpi-g03/iterations/index.cjs');
const plan = planNativeRound(ledger, 1, {
  source_manifest: {path:'candidate/source.json',sha256:'...'},
  elf: {path:'candidate/wrapper.elf',sha256:'...'},
  build_record: {path:'candidate/build.json',sha256:'...'}
});
```

Текущая строка должна быть `in_progress` с причинно связанной гипотезой. План содержит6 deployments по умолчанию (`replicas:1` даёт3), `scope:primary`, `experiment_role:candidate-development`, `stages.B1` с singleton batches. Test rows отсутствуют; generation плана не начинает измерения.

Lead интегрирует план: клонирует candidate preparation descriptor через существующий adaptive helper, pins новый ELF/source/settings/configs, формирует новый master freeze и запускает **неизменный** collector:

```sh
node lab/dpi-g03/runtime-v5/collect.cjs --freeze MASTER
```

Затем adapter связывает raw результаты с evidence DTO и per-group collector SHA в новом ensemble. Этот scaffold не меняет runtime/production/ensemble и не запускает acquisition автоматически. Синтетические fixtures никогда не увеличивают `actual_complete_cycles`, даже при `allowSynthetic:true`. Refactoring, последняя adaptive verification и B2 остаются отдельными последующими шагами.
