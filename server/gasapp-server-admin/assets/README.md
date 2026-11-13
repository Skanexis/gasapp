# Сторонние файлы админ-центра

Встроены в программу (`include_str!`): админ-центр не ходит в интернет и
не грузит ничего чужого во время работы.

| Файл | Откуда | Версия | Проверка | Лицензия |
|---|---|---|---|---|
| `tabler.min.css` | npm `@tabler/core`, `dist/css/tabler.min.css` | 1.7.1 (2026-10-23) | sha512 пакета `sC42sr/uslr7kIZwyBPESWJKRm1E4hYAMMZyLDoyG0ZlEOlglRW0L5c1gf8x6i+QApT+AtHm10fDP1j2WgQJpg==` | MIT (заголовок файла) |
| `../src/icons.rs` (38 иконок) | npm `@tabler/icons`, `icons/outline/*.svg` | 3.50.0 (2026-10-27) | sha512 пакета `HflLxyrH1cqC7s7jzQGSjpsTAVIoaf7+/yHjbdM59rJQBMjliibp+LYhDPFxOMcwa1M8DNpOk6ENzQiWn9a1Dg==` | MIT (`TABLER-ICONS-LICENSE.txt`) |

Версии взяты не моложе двух недель на день встраивания (2026-11-13) —
защита от свежеподменённого пакета. Обновлять так же: сверить sha512 с
реестром npm, заменить файл, прогнать `cargo test -p gasapp-server-admin`.
