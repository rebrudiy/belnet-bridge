# G03 R3: immediate capture и проверка тяжёлой загрузкой

Поправка до нового трафика к [R2](PROTOCOL-R2.md). Цель, классы,23 правила,
80s primary,2s prefix grace, source partitions и FP-бюджеты не меняются.

R2 остановлен после24/71 групп. У native download:20663 PCAP records против
20669 received by filter, kernel drops0. В [независимой TCP-проверке](../../out/dpi-g03/root-review/r2-download-wire/audit.json)
все уникальные payload bytes совпали с обоими proxy-туннелями; gaps/conflicts
не найдены. Это не устанавливает природу шести отсутствующих пакетов и
исходные first-arrival timestamps. **Старый UNKNOWN и запрет калибровки сохранены.**
Отдельно Chrome idle имеет SYN-only попытку без ответа и без TCP payload;
старый observer пометил её missing_syn_ack и отверг всю группу. Финальный
независимый audit R2:22/24 acquisition-qualified; калибровка запрещена.
Обе предыдущие остановленные когорты остаются development стенда.

## Завершение capture

1. tcpdump запускается с `--immediate-mode`; фактический argv фиксируется.
2. После82s — прежний quiesce, минимум500ms drain, живой process/netns.
3. В отдельном ограниченном интервале≤2500ms собираются SIGUSR1 stats.
   Нужны два последовательных одинаковых triplet: captured=received, drops=0.
4. Затем bounded stop. Из stderr берётся **последний** полный набор счётчиков;
   он снова сравнивается с числом raw PCAP records. Missing/mismatch/drop/cap/
   forced cleanup остаются UNKNOWN. Успешные промежуточные stats его не отменяют.

SIGUSR1 сообщает статистику, не гарантирует flush. Согласно
[исходникам libpcap1.10.3](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.3/pcap-linux.c),
kernel counters могут включать ещё не прочитанные пакеты, а immediate mode
обходит буферизацию TPACKET_V3. Это обосновывает следующую проверку;
причина старого расхождения этим не доказана. См. также
[tcpdump4.99.3 manual](https://raw.githubusercontent.com/the-tcpdump-group/tcpdump/tcpdump-4.99.3/tcpdump.1.in).

Ожидание stats — ограниченная часть завершения той же сессии, не повтор
нагрузки до удачи. Время ожидания и все snapshots сохраняются. Primary окна
по-прежнему заканчиваются в80s; дополнительный хвост capture не расширяет
знаменатель и не добавляет новые primary reconnect obligations.

## Нулевая нагрузка при незавершённом TCP connect

Observer-v3/longflow-v3 отдельно описывают попытку с captured SYN, отсутствующим
SYNACK и **нулевым TCP payload во всём capture**, включая SYN/TFO и retransmits.
Это no-TLS abstention с сохранением реального flow denominator, без догадки
о причине отсутствия ответа. Такая попытка сама по себе не означает capture loss.
ANY TCP payload при missing SYN/SYNACK, TCP gap/conflict, malformed/capped data
по-прежнему означает UNKNOWN. Ordering/mask semantics не меняются.
Старый R2 missing_syn_ack flag не переписывается; новые версии/SHA обязательны.

## Qualification и следующий B1

[qualification-r3.json](qualification-r3.json): одна партия из native **download**,
Chrome Google и Go WSS idle. Новые15 nonce, q- IDs, diagnostic/development;
никакого test vault, fit или включения этих3 групп в FP/TP. Native main теперь
проверяет тяжёлую загрузку, на которой R2 выявил проблему; startup RPC сохранены.
Freeze должен закрепить runtime-v3, actual capture argv/stats contract и все ELF.
Провал сохраняется; автоматического повторного запуска нет.

После прохождения qualification — все71 fresh B1 группы заново, с355 новыми
nonce. Seed/plans/batches и25 sealed test rows сохраняются; исходный private
vault и его SHA не заменяются. R3 assignments создаются отдельно, старые файлы
не переписываются. Без полного нового freeze основной сбор запрещён.

Ни одно исправление capture не считается адаптивной итерацией обхода DPI.
Изолированный coalesce candidate остаётся невыбранным до допустимых B1-данных.
Новые23-rule/ML verdicts являются shadow-анализом: live DPI blocking и обход
реального ISP этим не доказываются. Native UDP deny и доставка проверяются отдельно.
