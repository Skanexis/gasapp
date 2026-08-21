// SPDX-License-Identifier: Apache-2.0

//! QR-код safety number.
//!
//! # Зачем QR, если есть 60 цифр
//!
//! Сверка вручную — единственная криптографическая проверка, которую
//! выполняет человек, и она проваливается ровно там, где утомляет.
//! Шестьдесят цифр читают невнимательно: люди сверяют первые пять
//! и последние пять, а середину пропускают. Атака на этом и строится —
//! подобрать ключ с совпадающими краями дешевле, чем с совпадающими
//! всеми цифрами.
//!
//! QR убирает человека из сравнения: устройство сверяет все 60 цифр,
//! а человеку остаётся навести камеру.
//!
//! # Что кодируется
//!
//! Ровно те же 60 цифр, без разделителей и префиксов. Не URL и не
//! JSON: сканер, встретивший ссылку, откроет браузер, а адрес в QR —
//! это готовый фишинг под видом верификации.
//!
//! # Почему генерация в ядре
//!
//! Android и iOS сгенерировали бы QR своими средствами, и любое
//! расхождение в кодировании привело бы к тому, что устройства
//! не смогли бы сверить друг друга. Один генератор — одна форма.

use aegis_types::{AegisError, Result};

/// Матрица QR-кода: строки по столбцам, `true` — чёрный модуль.
///
/// Возвращается матрица, а не картинка: отрисовка зависит от
/// платформы, а размер модуля — от экрана. Ядро не знает ни того,
/// ни другого и не должно.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrMatrix {
    /// Сторона матрицы в модулях.
    pub size: usize,
    /// Модули построчно: `size * size` значений.
    pub modules: Vec<bool>,
}

impl QrMatrix {
    /// Значение модуля.
    ///
    /// Возвращает `false` за границами: отрисовщику удобнее получить
    /// белый модуль, чем проверять границы на каждом пикселе.
    #[must_use]
    pub fn module(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }

        y.checked_mul(self.size)
            .and_then(|offset| offset.checked_add(x))
            .and_then(|index| self.modules.get(index))
            .copied()
            .unwrap_or(false)
    }
}

/// Строит QR-код для safety number.
///
/// # Про уровень коррекции
///
/// Выбран средний (`M`, ~15 % восстановления). Низкий сделал бы код
/// нечитаемым при бликах и царапинах на экране, а высокий увеличил бы
/// матрицу и потребовал бы более крупного изображения — на экране
/// телефона это заметно.
///
/// # Errors
///
/// [`AegisError::Malformed`] — строка не состоит из цифр либо не
/// помещается в код. Обе ситуации означают ошибку вызывающего кода,
/// а не пользовательский ввод: safety number приходит из ядра.
pub fn safety_number_qr(digits: &str) -> Result<QrMatrix> {
    // Только цифры: любой другой символ означает, что сюда попало
    // не safety number, а, например, уже отформатированная строка
    // с пробелами. Кодировать её нельзя — сканер получит не то,
    // что покажет второе устройство.
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AegisError::Malformed);
    }

    let code = qrcode::QrCode::with_error_correction_level(digits, qrcode::EcLevel::M)
        .map_err(|_| AegisError::Malformed)?;

    let size = code.width();
    let colors = code.into_colors();

    Ok(QrMatrix {
        size,
        modules: colors
            .into_iter()
            .map(|color| color == qrcode::Color::Dark)
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Шестьдесят цифр safety number для проверок.
    const SAMPLE: &str = "123456789012345678901234567890123456789012345678901234567890";

    #[test]
    fn safety_number_fits_into_qr() {
        let matrix = safety_number_qr(SAMPLE).expect("код построен");

        assert!(matrix.size >= 21, "матрица меньше минимальной версии QR");
        assert_eq!(matrix.modules.len(), matrix.size * matrix.size);
    }

    /// 🔐 Разные safety number дают разные коды.
    ///
    /// Иначе QR не различал бы собеседников, и сверка через камеру
    /// проходила бы для кого угодно.
    #[test]
    fn different_numbers_give_different_codes() {
        let first = safety_number_qr(SAMPLE).expect("код");
        let second = safety_number_qr(
            "999456789012345678901234567890123456789012345678901234567890",
        )
        .expect("код");

        assert_ne!(first.modules, second.modules);
    }

    /// Один вход даёт один и тот же код.
    ///
    /// Без этого два устройства с одинаковым safety number показали бы
    /// разные картинки, и сверка не прошла бы никогда.
    #[test]
    fn generation_is_deterministic() {
        assert_eq!(
            safety_number_qr(SAMPLE).expect("код"),
            safety_number_qr(SAMPLE).expect("код")
        );
    }

    /// Нецифровой ввод отвергается.
    ///
    /// Форматированная строка с пробелами — самая вероятная ошибка
    /// вызывающего кода, и молча закодировать её значит показать
    /// пользователю код, который не совпадёт с кодом собеседника.
    #[test]
    fn formatted_string_is_rejected() {
        assert!(matches!(
            safety_number_qr("12345 67890"),
            Err(AegisError::Malformed)
        ));
    }

    /// Обращение за границы матрицы безопасно.
    #[test]
    fn out_of_bounds_module_is_white() {
        let matrix = safety_number_qr(SAMPLE).expect("код");

        assert!(!matrix.module(matrix.size, 0));
        assert!(!matrix.module(0, matrix.size));
    }
}
