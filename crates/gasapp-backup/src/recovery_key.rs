// SPDX-License-Identifier: Apache-2.0

//! Recovery key: 256 бит в Crockford Base32 с контрольной суммой.
//!
//! # Что это за ключ
//!
//! Единственное, чем можно расшифровать резервную копию. Сервер его
//! не знает, устройство не хранит, восстановления по почте или SMS
//! не существует (обещание №4 раздела 2). Поэтому ключ обязан
//! переживать перенос человеком: его переписывают на бумагу,
//! диктуют вслух и набирают заново через год.
//!
//! # Почему Crockford Base32, а не BIP-39
//!
//! 24 слова BIP-39 требуют словаря на каждом языке интерфейса,
//! а ошибка в переводе словаря означает потерю доступа к данным.
//! Base32 языконезависим.
//!
//! Из алфавита Crockford исключены `I`, `L`, `O` и `U`: первые три
//! путаются с `1` и `0` при переписывании от руки, `U` исключён
//! автором кодировки, чтобы случайная комбинация не сложилась
//! в бранное слово. При разборе `I` и `L` принимаются как `1`,
//! а `O` как `0` — это не послабление, а исправление ровно той
//! ошибки, ради которой символы и убраны из алфавита.
//!
//! # Про длину
//!
//! ⚠️ В UI kit ключ показан семью группами по четыре символа — это
//! 140 бит, а не 256. Здесь групп тринадцать: 52 символа по 5 бит
//! дают 260 бит, из которых 256 — ключ и 4 — контрольная сумма
//! (раздел 12.2 плана).
//!
//! # Про контрольную сумму
//!
//! 🔐 Четыре бита CRC проверяются **до** Argon2id. Это не про
//! криптографию, а про то, чтобы опечатка в 52 символах отвергалась
//! мгновенно, а не после нескольких секунд вывода ключа с 256 МиБ
//! памяти. Гарантия здесь честная и ограниченная: CRC-4 ловит все
//! одиночные битовые ошибки и все пачки длиной до 4 бит, а ошибка
//! в целом символе — это пачка до 5 бит, поэтому она проходит мимо
//! с вероятностью 1/16. Проверка отсекает большинство опечаток
//! дёшево; окончательный ответ даёт AEAD-тег резервной копии.

use gasapp_types::{GasAppError, Result, Secret};
use zeroize::Zeroize;

/// Длина ключа в байтах.
pub const KEY_LEN: usize = 32;

/// Число символов Base32 в записи ключа.
///
/// 52 × 5 бит = 260 бит = 256 бит ключа + 4 бита CRC.
pub const SYMBOL_COUNT: usize = 52;

/// Символов в одной группе записи.
pub const GROUP_LEN: usize = 4;

/// Число групп: 52 символа по 4 в группе.
///
/// Значение записано числом, а не делением: деление целых запрещено
/// правилами проекта, потому что остаток от него молча теряется.
/// Согласованность с [`SYMBOL_COUNT`] и [`GROUP_LEN`] проверяется
/// на этапе компиляции — константа ниже не соберётся, если тройка
/// разойдётся.
pub const GROUP_COUNT: usize = 13;

/// Проверка согласованности размеров во время компиляции.
///
/// Индексация массива длины 1 значением, отличным от нуля, — ошибка
/// компиляции. Поэтому расхождение `GROUP_COUNT × GROUP_LEN`
/// с [`SYMBOL_COUNT`] обнаруживается сборкой, а не тестом.
const _GROUPS_COVER_ALL_SYMBOLS: [(); 1] = [(); (GROUP_COUNT * GROUP_LEN == SYMBOL_COUNT) as usize];

/// Приставка, с которой печатается ключ.
pub const PREFIX: &str = "GASAPP";

/// Алфавит Crockford Base32.
///
/// Порядок значим: позиция символа и есть его значение.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Полином CRC-4: x⁴ + x + 1, без старшего бита.
///
/// Примитивный полином — при нём CRC обнаруживает все одиночные
/// битовые ошибки и все пачки длиной до четырёх бит.
const CRC4_POLY: u8 = 0b0011;

/// Разобранный recovery key.
///
/// # Зачем отдельный тип
///
/// Вывод BRK принимает [`RecoveryKey`], а не строку. Поэтому
/// «запустить Argon2id на непроверенном вводе» — это код, который
/// не компилируется, а не ошибка, которую нужно не забыть проверить.
/// Контрольная сумма к моменту вывода уже сверена: другого способа
/// получить значение этого типа из текста нет.
///
/// Тип не реализует `Clone`, `Debug` и `Display`: содержимое —
/// секрет (Правило 4), а размножать копии ключа по памяти незачем.
/// Для показа пользователю есть [`RecoveryKey::to_display_string`],
/// каждый вызов которого обязан просмотреть ревьюер.
pub struct RecoveryKey(Secret<[u8; KEY_LEN]>);

impl RecoveryKey {
    /// Генерирует новый ключ из системного генератора.
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rng.fill_bytes(&mut bytes);

        Self(Secret::new(bytes))
    }

    /// Оборачивает готовые байты.
    ///
    /// Нужен восстановлению: ключ уже разобран, повторно кодировать
    /// его в текст, чтобы тут же разобрать обратно, незачем.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Возвращает байты ключа.
    #[must_use]
    pub const fn expose_bytes(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }

    /// Разбирает ключ из текста, набранного человеком.
    ///
    /// Принимается всё, что человек может написать: любой регистр,
    /// дефисы и пробелы в любых местах, приставка `GasApp-` или её
    /// отсутствие, `I`/`l` вместо `1` и `O` вместо `0`.
    ///
    /// 🔐 Проверка контрольной суммы происходит здесь — то есть
    /// до любого обращения к Argon2id.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — не то число символов, символ вне
    /// алфавита либо несовпадение контрольной суммы.
    ///
    /// Хвостовых битов здесь не бывает и проверять их не нужно:
    /// 52 символа по 5 бит дают ровно 260 бит, то есть кодировка
    /// сходится без остатка. Этим запись ключа отличается от
    /// ссылки на контакт, где 32 байта в base32 оставляют хвост.
    pub fn parse(input: &str) -> Result<Self> {
        let symbols = normalize(input)?;

        // 33 байта = 264 бита; записываются первые 260, хвост остаётся
        // нулевым и в ключ не попадает.
        let mut buffer = [0u8; KEY_LEN + 1];

        for (index, symbol) in symbols.iter().enumerate() {
            let value = decode_symbol(*symbol)?;
            let offset = index.saturating_mul(5);

            for bit in 0..5usize {
                // Биты значения идут от старшего к младшему.
                let shift = 4u32.saturating_sub(u32::try_from(bit).unwrap_or(4));

                if (value >> shift) & 1 == 1 {
                    set_bit(&mut buffer, offset.saturating_add(bit))?;
                }
            }
        }

        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(buffer.get(..KEY_LEN).ok_or(GasAppError::Malformed)?);

        // Контрольная сумма лежит в старших четырёх битах 33-го байта:
        // это биты 256..259 общего потока.
        let tail = *buffer.get(KEY_LEN).ok_or(GasAppError::Malformed)?;
        let stored = (tail >> 4) & 0x0f;

        buffer.zeroize();

        if stored != crc4(&key) {
            // 🔐 Разобранные байты обнуляются до возврата: неудачный
            // разбор не должен оставить их лежать в стеке.
            key.zeroize();

            return Err(GasAppError::Malformed);
        }

        Ok(Self(Secret::new(key)))
    }

    /// Печатает ключ так, как его показывают пользователю.
    ///
    /// 🔐 Каждый вызов — точка, где секрет становится строкой,
    /// которую можно случайно записать в лог. Вызывать только там,
    /// где ключ показывается человеку на защищённом экране
    /// (`FLAG_SECURE` на Android, раздел 12.4).
    #[must_use]
    pub fn to_display_string(&self) -> String {
        let key = self.0.expose_secret();

        let mut buffer = [0u8; KEY_LEN + 1];
        // Через `get_mut`, а не индексом: паника здесь запрещена
        // так же, как и в остальном коде крейта.
        if let Some(head) = buffer.get_mut(..KEY_LEN) {
            head.copy_from_slice(key);
        }
        if let Some(tail) = buffer.get_mut(KEY_LEN) {
            *tail = crc4(key) << 4;
        }

        let mut out = String::with_capacity(
            PREFIX
                .len()
                .saturating_add(SYMBOL_COUNT)
                .saturating_add(GROUP_COUNT),
        );
        out.push_str(PREFIX);

        for index in 0..SYMBOL_COUNT {
            if index % GROUP_LEN == 0 {
                out.push('-');
            }

            let mut value = 0u8;
            let offset = index.saturating_mul(5);

            for bit in 0..5usize {
                value <<= 1;
                if bit_at(&buffer, offset.saturating_add(bit)) {
                    value |= 1;
                }
            }

            out.push(char::from(
                *ALPHABET.get(usize::from(value)).unwrap_or(&b'0'),
            ));
        }

        buffer.zeroize();

        out
    }

    /// Возвращает группу под номером `index` (с нуля).
    ///
    /// Нужен экрану подтверждения записи: пользователя просят ввести
    /// три случайные группы, и сверять их нужно с эталоном, а не
    /// со всей строкой.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — номер группы вне диапазона.
    pub fn group(&self, index: usize) -> Result<String> {
        if index >= GROUP_COUNT {
            return Err(GasAppError::Malformed);
        }

        let display = self.to_display_string();
        let group = display
            .split('-')
            // Первая часть — приставка `GasApp`, группы идут после неё.
            .nth(index.saturating_add(1))
            .ok_or(GasAppError::Malformed)?;

        Ok(group.to_owned())
    }

    /// Сверяет введённую пользователем группу с эталонной.
    ///
    /// Сравнение нечувствительно к регистру и к тем же заменам
    /// символов, что и [`RecoveryKey::parse`]: человек, записавший
    /// `O` вместо `0`, записал ключ правильно.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — номер группы вне диапазона.
    pub fn check_group(&self, index: usize, input: &str) -> Result<bool> {
        let expected = self.group(index)?;
        let entered = normalize_symbols(input);

        Ok(entered == expected.as_bytes())
    }
}

/// Приводит ввод к 52 символам алфавита.
///
/// Приставка, дефисы и пробелы отбрасываются, регистр приводится
/// к верхнему, `I`/`L` заменяются на `1`, `O` — на `0`.
fn normalize(input: &str) -> Result<Vec<u8>> {
    let symbols = normalize_symbols(input);

    if symbols.len() != SYMBOL_COUNT {
        return Err(GasAppError::Malformed);
    }

    Ok(symbols)
}

/// Общая нормализация символов без проверки длины.
fn normalize_symbols(input: &str) -> Vec<u8> {
    let trimmed = input.trim();

    // Приставка снимается и в верхнем, и в нижнем регистре: человек
    // может набрать «GasApp-...», «gasapp ...» или вовсе без неё.
    let body = trimmed
        .strip_prefix(PREFIX)
        .or_else(|| trimmed.strip_prefix(PREFIX.to_lowercase().as_str()))
        .unwrap_or(trimmed);

    body.bytes()
        .filter(|byte| !byte.is_ascii_whitespace() && !matches!(byte, b'-' | b'_'))
        .map(|byte| match byte.to_ascii_uppercase() {
            // Замены Crockford: символы, которых нет в алфавите
            // именно потому, что их путают с цифрами.
            b'I' | b'L' => b'1',
            b'O' => b'0',
            other => other,
        })
        .collect()
}

/// Переводит символ алфавита в его значение.
fn decode_symbol(symbol: u8) -> Result<u8> {
    let position = ALPHABET
        .iter()
        .position(|candidate| *candidate == symbol)
        .ok_or(GasAppError::Malformed)?;

    u8::try_from(position).map_err(|_| GasAppError::Malformed)
}

/// Ставит бит номер `index` в буфере (нумерация от старшего бита).
fn set_bit(buffer: &mut [u8], index: usize) -> Result<()> {
    let byte = buffer
        .get_mut(index.checked_div(8).ok_or(GasAppError::Malformed)?)
        .ok_or(GasAppError::Malformed)?;
    let shift = 7u32.saturating_sub(u32::try_from(index % 8).unwrap_or(7));

    *byte |= 1u8 << shift;

    Ok(())
}

/// Читает бит номер `index` (нумерация от старшего бита).
fn bit_at(buffer: &[u8], index: usize) -> bool {
    let Some(byte) = buffer.get(index.checked_div(8).unwrap_or(0)) else {
        return false;
    };
    let shift = 7u32.saturating_sub(u32::try_from(index % 8).unwrap_or(7));

    (byte >> shift) & 1 == 1
}

/// Считает CRC-4 по полиному x⁴ + x + 1.
///
/// Данные обрабатываются побитно от старшего бита каждого байта.
/// Реализация прямолинейная, без таблицы: 32 байта считаются
/// за микросекунды, а таблица — это ещё одно место, где можно
/// ошибиться незаметно.
fn crc4(data: &[u8]) -> u8 {
    let mut crc = 0u8;

    for byte in data {
        for bit in 0..8u32 {
            let shift = 7u32.saturating_sub(bit);
            let input = (byte >> shift) & 1;
            let top = (crc >> 3) & 1;

            crc = (crc << 1) & 0x0f;

            if top ^ input == 1 {
                crc ^= CRC4_POLY;
            }
        }
    }

    crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Запись ключа round-trip: показали — набрали — тот же ключ.
    #[test]
    fn display_round_trips() {
        let key = RecoveryKey::generate(&mut OsRng);
        let text = key.to_display_string();

        let parsed = RecoveryKey::parse(&text).expect("свой же ключ обязан разбираться");

        assert_eq!(parsed.expose_bytes(), key.expose_bytes());
    }

    /// Формат записи — ровно тот, что обещан разделом 12.2.
    #[test]
    fn display_has_thirteen_groups_of_four() {
        let key = RecoveryKey::from_bytes([0x5Au8; KEY_LEN]);
        let text = key.to_display_string();

        let parts: Vec<&str> = text.split('-').collect();

        assert_eq!(parts.first().copied(), Some(PREFIX));
        assert_eq!(
            parts.len(),
            GROUP_COUNT + 1,
            "ожидались приставка и 13 групп: {text}"
        );

        for group in parts.iter().skip(1) {
            assert_eq!(group.len(), GROUP_LEN, "группа не из 4 символов: {group}");
        }
    }

    /// 🔐 В самом ключе нет символов, которые путаются при переписывании.
    ///
    /// Проверяются только 52 символа ключа, а не вся строка:
    /// приставка `GasApp` содержит `I`, но её никто не переписывает
    /// как данные — она одинакова у всех ключей и служит меткой
    /// формата, а не носителем битов.
    #[test]
    fn display_never_contains_confusable_symbols() {
        // Перебор случайных ключей: запрещённый символ мог бы
        // возникнуть только при определённом значении пятёрки бит,
        // и один ключ его бы не показал.
        for _ in 0..200 {
            let key = RecoveryKey::generate(&mut OsRng);
            let text = key.to_display_string();
            let body = text
                .strip_prefix(PREFIX)
                .expect("приставка на месте")
                .to_owned();

            for forbidden in ['I', 'L', 'O', 'U'] {
                assert!(
                    !body.contains(forbidden),
                    "в записи оказался символ {forbidden}: {text}"
                );
            }
        }
    }

    /// 🧪 Задача M6: опечатка ловится контрольной суммой.
    ///
    /// Проверяется не «какая-то ошибка», а именно доля пойманных:
    /// CRC-4 обязан отсекать подавляющее большинство замен символа.
    #[test]
    fn typo_is_caught_by_checksum() {
        let key = RecoveryKey::from_bytes([0x11u8; KEY_LEN]);
        let text = key.to_display_string();

        let mut total = 0usize;
        let mut caught = 0usize;

        // Каждая позиция, каждый другой символ алфавита.
        for position in 0..text.len() {
            if text.as_bytes().get(position) == Some(&b'-') {
                continue;
            }

            for replacement in ALPHABET {
                let mut bytes = text.clone().into_bytes();
                if bytes.get(position) == Some(replacement) {
                    continue;
                }
                if let Some(slot) = bytes.get_mut(position) {
                    *slot = *replacement;
                }

                let Ok(candidate) = String::from_utf8(bytes) else {
                    continue;
                };

                total += 1;
                if RecoveryKey::parse(&candidate).is_err() {
                    caught += 1;
                }
            }
        }

        assert!(total > 0, "тест не подобрал ни одной опечатки");

        // CRC-4 пропускает примерно 1/16 замен. Порог 85 % оставляет
        // запас на распределение, но ломается, если проверку убрать
        // совсем (тогда доля упала бы до нуля).
        //
        // Сравнение умножением, а не делением: деление целых теряет
        // остаток молча, и порог поплыл бы вместе с ним.
        assert!(
            caught * 100 > total * 85,
            "контрольная сумма поймала лишь {caught} из {total} опечаток"
        );
    }

    /// Ключ верной длины, но с испорченной суммой, не принимается.
    #[test]
    fn wrong_checksum_is_rejected() {
        let key = RecoveryKey::from_bytes([0x22u8; KEY_LEN]);
        let text = key.to_display_string();

        // Последний символ несёт четыре бита CRC: меняем его так,
        // чтобы значение точно отличалось.
        let mut bytes = text.into_bytes();
        let last = bytes.len().saturating_sub(1);
        let original = bytes.get(last).copied().unwrap_or(b'0');
        let replacement = if original == b'0' { b'1' } else { b'0' };
        if let Some(slot) = bytes.get_mut(last) {
            *slot = replacement;
        }

        let broken = String::from_utf8(bytes).expect("ASCII");

        assert!(matches!(
            RecoveryKey::parse(&broken),
            Err(GasAppError::Malformed)
        ));
    }

    /// Ввод человека принимается в любом разумном виде.
    #[test]
    fn human_input_is_normalized() {
        let key = RecoveryKey::generate(&mut OsRng);
        let canonical = key.to_display_string();

        let without_prefix = canonical
            .strip_prefix("GASAPP-")
            .expect("приставка на месте")
            .to_owned();
        let lowercase = canonical.to_lowercase();
        let spaced = canonical.replace('-', " ");
        let squashed = canonical.replace('-', "");
        let padded = format!("  {canonical}  ");

        for variant in [&without_prefix, &lowercase, &spaced, &squashed, &padded] {
            let parsed = RecoveryKey::parse(variant)
                .unwrap_or_else(|_| panic!("вариант не разобрался: {variant}"));

            assert_eq!(parsed.expose_bytes(), key.expose_bytes());
        }
    }

    /// `I`, `L` и `O` принимаются как `1`, `1` и `0`.
    ///
    /// Ровно ради этого символы и убраны из алфавита: человек,
    /// переписавший ключ от руки, почти наверняка их спутает.
    #[test]
    fn confusable_symbols_are_accepted_on_input() {
        let key = RecoveryKey::generate(&mut OsRng);
        let canonical = key.to_display_string();

        let confused = canonical
            .chars()
            .map(|symbol| match symbol {
                '1' => 'I',
                '0' => 'O',
                other => other,
            })
            .collect::<String>();

        let parsed = RecoveryKey::parse(&confused).expect("замены обязаны приниматься");

        assert_eq!(parsed.expose_bytes(), key.expose_bytes());
    }

    /// Слишком короткий и слишком длинный ввод отвергаются.
    #[test]
    fn wrong_length_is_rejected() {
        let key = RecoveryKey::generate(&mut OsRng);
        let canonical = key.to_display_string();

        let short = canonical
            .get(..canonical.len().saturating_sub(1))
            .unwrap_or("");
        let long = format!("{canonical}Z");

        assert!(RecoveryKey::parse(short).is_err());
        assert!(RecoveryKey::parse(&long).is_err());
    }

    /// Символ вне алфавита отвергается, а не заменяется молча.
    #[test]
    fn symbol_outside_alphabet_is_rejected() {
        let key = RecoveryKey::generate(&mut OsRng);
        let mut bytes = key.to_display_string().into_bytes();

        // `U` исключён из алфавита Crockford и заменам не подлежит.
        if let Some(slot) = bytes.last_mut() {
            *slot = b'U';
        }

        let broken = String::from_utf8(bytes).expect("ASCII");

        assert!(matches!(
            RecoveryKey::parse(&broken),
            Err(GasAppError::Malformed)
        ));
    }

    /// Два сгенерированных ключа не совпадают.
    #[test]
    fn generated_keys_differ() {
        let first = RecoveryKey::generate(&mut OsRng);
        let second = RecoveryKey::generate(&mut OsRng);

        assert_ne!(first.expose_bytes(), second.expose_bytes());
    }

    /// Группы нумеруются с нуля и совпадают с записью.
    #[test]
    fn groups_match_display() {
        let key = RecoveryKey::generate(&mut OsRng);
        let display = key.to_display_string();
        let expected: Vec<&str> = display.split('-').skip(1).collect();

        for (index, group) in expected.iter().enumerate() {
            assert_eq!(key.group(index).expect("группа"), *group);
        }

        assert!(key.group(GROUP_COUNT).is_err(), "групп ровно 13");
    }

    /// Подтверждение группы: верный ввод принимается, неверный — нет.
    #[test]
    fn group_confirmation_checks_input() {
        let key = RecoveryKey::generate(&mut OsRng);
        let group = key.group(3).expect("группа");

        assert!(key.check_group(3, &group).expect("проверка"));
        assert!(key.check_group(3, &group.to_lowercase()).expect("проверка"));
        assert!(!key.check_group(3, "ZZZZ").expect("проверка"));
        // Чужая группа не подходит, даже будучи верной сама по себе.
        let other = key.group(4).expect("группа");
        if other != group {
            assert!(!key.check_group(3, &other).expect("проверка"));
        }
    }

    /// CRC-4 не постоянен: иначе он ничего бы не проверял.
    #[test]
    fn crc_depends_on_data() {
        let first = crc4(&[0u8; KEY_LEN]);
        let mut differing = [0u8; KEY_LEN];
        differing[0] = 1;

        let values: Vec<u8> = (0..64u8).map(|seed| crc4(&[seed; KEY_LEN])).collect();
        let distinct = values
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len();

        assert_ne!(first, crc4(&differing), "CRC не заметил разницы в бите");
        assert!(distinct > 1, "CRC постоянен — проверки нет");
    }
}
