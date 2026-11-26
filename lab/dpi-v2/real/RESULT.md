# Реальный обычный трафик: результат

29 визитов, 25 заранее назначенных групп. Успешны 14 визитов / 13 групп.
239 пригодных TLS/TCP потоков; 29 отдельных поздних окон. Это контроли, не результат обхода DPI.

| Нагрузка | Успешно / попыток | TLS/TCP потоки |
|---|---:|---:|
| docs | 4 / 5 | 53 |
| download | 2 / 5 | 16 |
| google | 3 / 10 | 38 |
| youtube | 5 / 9 | 132 |

Train / validation / test: 118 / 57 / 64 потока, но всего 5 / 4 / 4 независимые успешные группы.
Модель нельзя оценивать так, будто все 239 потоков независимы.

Google homepage реально загрузилась во всех трёх split. Семь попыток Google Search
получили CAPTCHA/429: их не обходили и не выдавали за успешный поиск.

YouTube: пять настоящих воспроизведений, два разных video ID. Новые validation/test BBB
через TCP: 7.28 / 6.10 секунд playback и 2,401,425 / 1,743,254 media response bytes.
BBB уже есть в train: это новые сессии, не проверка нового контента.
Четыре других видео-визита без playback сохранены как ошибки.

Работают Wikipedia, RFC8446, Python docs, Go docs; MDN недоступен.
Cloudflare validation download: ровно 524,288 body bytes. RFC9000 test download успешен.
Две другие Cloudflare нагрузки и Gutenberg недоступны.

181 пригодный TCP поток неуспешных нагрузок сохранён отдельно.
Пилот Google homepage и пилот YouTube исключены из всех split.

QUIC/HTTP3 не оценивался TLS/TCP моделью. Нативный YouTube может передавать media
через HTTP3; TCP observations такого визита включают другие соединения Chrome.
Сырые callbacks и TLS stacks Chrome/Go отличаются; один egress и мало групп
не дают FPR для провайдера. Начальные окна включают encrypted TLS1.3 handshake.

Замороженные данные: `out/dpi-v2/real/frozen-20261119/`.
Подробности: `evidence.json`, происхождение и SHA-256: `manifest.json`.
Сборщик и ограничения: [README](README.md).
