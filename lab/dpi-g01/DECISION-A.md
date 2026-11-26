# A: продолжение после инженерной проверки

Четыре fresh native deployment:32/32 запросов измеряемой фазы успешны;
10/12 warmup, первые два неудачных не удалялись. Native и Go adapter PID/start
не менялись. У framed получателя оба SID/UDP tuple пережили outer-core restart.
Отдельный REALITY smoke точно передал UDP0..65507 до/после restart; ошибка
schema в самом smoke helper сохранена, функциональные raw данные проверены.

Предварительный независимый wire audit: framed TCP bytes / native UDP≈1.083x,
с IP≈1.283x; v2≈2.67–2.86x. Прямой UDP1090 с клиента не обнаружен.
Это private development, не доказательство маскировки от реального ISP.
У a01 kernel/filter accounting не совпал:1782 сохранённых против1797 полученных
фильтром, хотя kernel drops0. Поэтому его wire bounds относятся только к
наблюдаемым байтам. У обоих framed и последнего v2 accounting совпал; нельзя
объявлять все четыре capture полностью учтёнными.

Гарантированно свежие успешные запросы после interruption завершились через
наблюдаемые4.9–5.3s, при пятсекундном расписании проб. Это не точное время
доступности. Mac/VM часы отличаются: raw subsecond recovery в runtime summary
не используется; независимый аудит учёл измеренный offset interval.

**Queue100ms gate провален:** клиент ждал до1.60/1.56s во время двухсекундной
остановки core. Receiver downlink FIFO<1ms, overflow не наблюдался. Доставка
и расход улучшились, но нельзя объявить все критерии выполненными.

Решение: большой DPI-сбор B пока не запускать. Следующий конечный A2 проверяет
opt-in freshness policy100ms в четырёх новых контрбалансированных deployment,
с сохранением expired/drop/write-failure и all-input age. Retain остаётся default.
Это новая гипотеза с новой фиксацией до сбора, не переименование результата A.
Исходные data,source,ELF и failed infrastructure attempt сохранены.
