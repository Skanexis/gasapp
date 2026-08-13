// SPDX-License-Identifier: Apache-2.0

//! Отпечатки ключей и safety numbers.
//!
//! Safety number — это единственное место, где криптографическая проверка
//! выполняется **человеком**. Поэтому здесь важна не только корректность
//! вычисления, но и форма представления: ADR-022 предписывает 60 десятичных
//! цифр, 12 групп по 5.
//!
//! Причина отказа от hex, который был в UI kit: при сверке голосом или
//! глазами путаются `B`/`8`, `D`/`0`, на слух — `C`/`G` и `F`/`E`. Ошибка
//! сверки означает, что пользователь считает канал проверенным, когда он
//! не проверен. Это худший возможный исход экрана верификации, поэтому
//! формат отображения здесь — решение о безопасности, а не об оформлении.
//!
//! Вычисление самого отпечатка (итеративный SHA-512) появится в M2 вместе
//! с тестовыми векторами. Здесь определены тип, представление и сравнение.

use core::fmt;

use aegis_types::{AegisError, Result};
use subtle::{Choice, ConstantTimeEq};

/// Количество байт отпечатка одной стороны.
const FINGERPRINT_BYTES: usize = 30;

/// Байт на одну группу цифр.
const BYTES_PER_GROUP: usize = 5;

/// Цифр в одной группе.
const DIGITS_PER_GROUP: usize = 5;

/// Групп в отпечатке одной стороны.
const GROUPS_PER_FINGERPRINT: usize = 6;

/// Отпечаток должен нацело разбиваться на группы: остаток означал бы
/// молча отброшенные байты, то есть потерю энтропии в safety number.
const _: () = assert!(GROUPS_PER_FINGERPRINT * BYTES_PER_GROUP == FINGERPRINT_BYTES);

/// Всего цифр в safety number (две стороны).
pub const SAFETY_NUMBER_DIGITS: usize = GROUPS_PER_FINGERPRINT * DIGITS_PER_GROUP * 2;

/// ADR-022 предписывает ровно 60 цифр. Проверяется на этапе компиляции,
/// чтобы правка любой из констант выше не изменила формат молча.
const _: () = assert!(SAFETY_NUMBER_DIGITS == 60);

/// Отпечаток публичного identity-ключа одной стороны.
///
/// 30 байт, полученных из итеративного хеширования identity-ключа.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; FINGERPRINT_BYTES]);

impl Fingerprint {
    /// Оборачивает 30 байт отпечатка.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; FINGERPRINT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Возвращает байты отпечатка.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; FINGERPRINT_BYTES] {
        &self.0
    }

    /// Преобразует отпечаток в 30 десятичных цифр (6 групп по 5).
    ///
    /// Каждые 5 байт трактуются как big-endian число и приводятся по модулю
    /// 100000, давая пять цифр. Пять байт — это 2^40, что заметно больше
    /// 100000, поэтому распределение остатков практически равномерное.
    #[must_use]
    pub fn digits(&self) -> [u8; GROUPS_PER_FINGERPRINT * DIGITS_PER_GROUP] {
        let mut out = [0u8; GROUPS_PER_FINGERPRINT * DIGITS_PER_GROUP];

        for (group_index, chunk) in self.0.chunks_exact(BYTES_PER_GROUP).enumerate() {
            // 5 байт → u64. Сдвиги ограничены 32 битами, переполнение невозможно.
            let mut value: u64 = 0;
            for byte in chunk {
                value = (value << 8) | u64::from(*byte);
            }

            // Модуль и деление по ненулевым константам; value < 2^40,
            // поэтому ни переполнения, ни деления на ноль быть не может.
            #[allow(
                clippy::integer_division,
                clippy::arithmetic_side_effects,
                clippy::cast_possible_truncation
            )]
            {
                let mut remainder = value % 100_000;
                for digit_index in (0..DIGITS_PER_GROUP).rev() {
                    let position = group_index * DIGITS_PER_GROUP + digit_index;
                    if let Some(slot) = out.get_mut(position) {
                        *slot = (remainder % 10) as u8;
                    }
                    remainder /= 10;
                }
            }
        }

        out
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Отпечаток вычисляется из публичного ключа и не секретен,
        // но в логах он не нужен — печатаем только признак наличия.
        f.write_str("Fingerprint(..)")
    }
}

/// Safety number пары собеседников — 60 десятичных цифр.
///
/// Порядок конкатенации отпечатков **лексикографический**, а не «свой/чужой».
/// Иначе Алиса и Боб увидели бы разные числа и не смогли бы их сверить.
///
/// # Примеры
///
/// ```
/// use aegis_protocol::{Fingerprint, SafetyNumber};
///
/// let a = Fingerprint::from_bytes([0x11; 30]);
/// let b = Fingerprint::from_bytes([0x22; 30]);
///
/// // Обе стороны получают одинаковое число независимо от порядка аргументов.
/// assert_eq!(SafetyNumber::new(&a, &b), SafetyNumber::new(&b, &a));
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SafetyNumber([u8; SAFETY_NUMBER_DIGITS]);

impl SafetyNumber {
    /// Строит safety number из двух отпечатков.
    #[must_use]
    pub fn new(local: &Fingerprint, remote: &Fingerprint) -> Self {
        // Лексикографический порядок гарантирует, что обе стороны
        // независимо получат одну и ту же последовательность.
        let (first, second) = if local.as_bytes() <= remote.as_bytes() {
            (local, remote)
        } else {
            (remote, local)
        };

        let mut digits = [0u8; SAFETY_NUMBER_DIGITS];
        let head = first.digits();
        let tail = second.digits();

        for (slot, value) in digits.iter_mut().zip(head.iter().chain(tail.iter())) {
            *slot = *value;
        }

        Self(digits)
    }

    /// Возвращает цифры как значения 0–9.
    #[must_use]
    pub const fn digits(&self) -> &[u8; SAFETY_NUMBER_DIGITS] {
        &self.0
    }

    /// Сравнивает два safety number за константное время.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> Choice {
        self.0.as_slice().ct_eq(other.0.as_slice())
    }

    /// Разбирает safety number из строки, введённой или отсканированной.
    ///
    /// Пробелы и переводы строк игнорируются, поэтому строку можно вставить
    /// из буфера обмена в том виде, в каком она показана на экране.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`], если после удаления пробелов осталось
    /// не ровно 60 символов или встретился не-цифровой символ.
    pub fn parse(input: &str) -> Result<Self> {
        let mut digits = [0u8; SAFETY_NUMBER_DIGITS];
        let mut count = 0usize;

        for ch in input.chars().filter(|c| !c.is_whitespace()) {
            let value = ch.to_digit(10).ok_or(AegisError::Malformed)?;
            let slot = digits.get_mut(count).ok_or(AegisError::Malformed)?;

            // to_digit(10) возвращает 0..=9, приведение всегда корректно.
            #[allow(clippy::cast_possible_truncation)]
            {
                *slot = value as u8;
            }

            count = count.checked_add(1).ok_or(AegisError::Malformed)?;
        }

        if count != SAFETY_NUMBER_DIGITS {
            return Err(AegisError::Malformed);
        }

        Ok(Self(digits))
    }

    /// Форматирует safety number для показа: 4 строки по 3 группы из 5 цифр.
    ///
    /// Такая раскладка задана ADR-022: она помещается на экране телефона
    /// целиком даже при увеличенном размере шрифта, а группы по пять цифр
    /// удобно диктовать голосом.
    #[must_use]
    pub fn to_display_block(&self) -> String {
        let mut out = String::with_capacity(SAFETY_NUMBER_DIGITS + 16);

        for (index, digit) in self.0.iter().enumerate() {
            if index != 0 {
                if index % (DIGITS_PER_GROUP * 3) == 0 {
                    out.push('\n');
                } else if index % DIGITS_PER_GROUP == 0 {
                    out.push(' ');
                }
            }
            out.push(char::from(b'0'.saturating_add(*digit)));
        }

        out
    }
}

impl fmt::Display for SafetyNumber {
    /// Однострочное представление: 12 групп по 5 цифр через пробел.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, digit) in self.0.iter().enumerate() {
            if index != 0 && index % DIGITS_PER_GROUP == 0 {
                f.write_str(" ")?;
            }
            write!(f, "{digit}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SafetyNumber({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_number_has_exactly_sixty_digits() {
        assert_eq!(SAFETY_NUMBER_DIGITS, 60);

        let sn = SafetyNumber::new(
            &Fingerprint::from_bytes([0x01; 30]),
            &Fingerprint::from_bytes([0x02; 30]),
        );
        assert_eq!(sn.digits().len(), 60);
    }

    #[test]
    fn all_values_are_decimal_digits() {
        let sn = SafetyNumber::new(
            &Fingerprint::from_bytes([0xFF; 30]),
            &Fingerprint::from_bytes([0x00; 30]),
        );
        assert!(sn.digits().iter().all(|d| *d <= 9));
    }

    /// Ключевое свойство: обе стороны должны увидеть одно и то же число,
    /// иначе сверка по телефону невозможна в принципе.
    #[test]
    fn ordering_of_arguments_does_not_matter() {
        let a = Fingerprint::from_bytes([0xAA; 30]);
        let b = Fingerprint::from_bytes([0xBB; 30]);

        assert_eq!(SafetyNumber::new(&a, &b), SafetyNumber::new(&b, &a));
    }

    #[test]
    fn different_peers_give_different_numbers() {
        let me = Fingerprint::from_bytes([0x01; 30]);
        let peer_one = Fingerprint::from_bytes([0x02; 30]);
        let peer_two = Fingerprint::from_bytes([0x03; 30]);

        assert_ne!(
            SafetyNumber::new(&me, &peer_one),
            SafetyNumber::new(&me, &peer_two)
        );
    }

    /// ADR-022: 4 строки по 3 группы из 5 цифр.
    #[test]
    fn display_block_layout_matches_adr_022() {
        let sn = SafetyNumber::new(
            &Fingerprint::from_bytes([0x12; 30]),
            &Fingerprint::from_bytes([0x34; 30]),
        );
        let block = sn.to_display_block();
        let lines: Vec<&str> = block.lines().collect();

        assert_eq!(lines.len(), 4, "ожидалось 4 строки");
        for line in lines {
            let groups: Vec<&str> = line.split(' ').collect();
            assert_eq!(groups.len(), 3, "в строке должно быть 3 группы: {line:?}");
            for group in groups {
                assert_eq!(group.len(), 5, "группа должна быть из 5 цифр: {group:?}");
                assert!(group.chars().all(|c| c.is_ascii_digit()));
            }
        }
    }

    #[test]
    fn single_line_display_has_twelve_groups() {
        let sn = SafetyNumber::new(
            &Fingerprint::from_bytes([0x7A; 30]),
            &Fingerprint::from_bytes([0x5C; 30]),
        );
        assert_eq!(sn.to_string().split(' ').count(), 12);
    }

    /// Строку можно скопировать с экрана вместе с переводами строк
    /// и вставить обратно — это основной способ сверки в UI.
    #[test]
    fn display_block_round_trips_through_parse() {
        let sn = SafetyNumber::new(
            &Fingerprint::from_bytes([0x9E; 30]),
            &Fingerprint::from_bytes([0x41; 30]),
        );

        assert_eq!(SafetyNumber::parse(&sn.to_display_block()).unwrap(), sn);
        assert_eq!(SafetyNumber::parse(&sn.to_string()).unwrap(), sn);
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(SafetyNumber::parse("12345").is_err());
        assert!(SafetyNumber::parse(&"1".repeat(59)).is_err());
        assert!(SafetyNumber::parse(&"1".repeat(61)).is_err());
        assert!(SafetyNumber::parse(&"1".repeat(60)).is_ok());
    }

    #[test]
    fn parse_rejects_non_digits() {
        let mut input = "1".repeat(59);
        input.push('A');
        assert!(SafetyNumber::parse(&input).is_err());
    }

    #[test]
    fn constant_time_comparison_is_correct() {
        let a = SafetyNumber::new(
            &Fingerprint::from_bytes([0x01; 30]),
            &Fingerprint::from_bytes([0x02; 30]),
        );
        let b = SafetyNumber::new(
            &Fingerprint::from_bytes([0x01; 30]),
            &Fingerprint::from_bytes([0x03; 30]),
        );

        assert!(bool::from(a.ct_eq(&a)));
        assert!(!bool::from(a.ct_eq(&b)));
    }

    /// Отпечаток не должен попадать в логи целиком.
    #[test]
    fn fingerprint_debug_is_opaque() {
        let fp = Fingerprint::from_bytes([0xDE; 30]);
        assert_eq!(format!("{fp:?}"), "Fingerprint(..)");
    }
}
