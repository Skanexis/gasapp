// SPDX-License-Identifier: Apache-2.0

//! Незавершённая регистрация: имя и адрес почты, пока человек ходит
//! за кодом из письма.
//!
//! # Зачем это хранить
//!
//! Регистрация теперь идёт в два приёма: приложение просит письмо
//! с кодом, человек уходит в почту, возвращается и вводит код. Между
//! этими шагами приложение может заблокироваться по простою или быть
//! выгружено системой. База к этому моменту уже создана и зашифрована
//! PIN — а аккаунта в ней ещё нет.
//!
//! Без этой записи возвращение выглядело бы как вход в пустой аккаунт.
//! С ней экран входа видит «регистрация не закончена» и возвращает
//! человека к вводу кода с теми же именем и адресом.
//!
//! # 🔐 Где лежит адрес
//!
//! В зашифрованной базе (`SQLCipher`), под ключом из PIN — там же, где
//! остальные настройки. Запись стирается при успешной регистрации:
//! после неё адрес на устройстве не остаётся.

use gasapp_net::client::Transport;
use gasapp_types::{canonical_username, GasAppError, Result};

use super::Client;

/// Настройка с незавершённой регистрацией: имя и адрес через перевод строки.
const PENDING_SETTING: &str = "registration.pending";

/// Незавершённая регистрация.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRegistration {
    /// Имя, которое человек выбрал.
    pub username: String,
    /// Адрес почты, на который ушёл код.
    pub email: String,
}

impl<T: Transport> Client<T> {
    /// Запоминает имя и адрес незавершённой регистрации.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::InvalidUsername`] — имя не по правилу;
    /// * [`GasAppError::InvalidEmail`] — строка не похожа на адрес;
    /// * [`GasAppError::Storage`] — запись не удалась.
    pub fn set_pending_registration(&self, username: &str, email: &str) -> Result<()> {
        let username = canonical_username(username)?;
        let email = gasapp_net::email::normalize(email).ok_or(GasAppError::InvalidEmail)?;

        self.storage
            .set_setting_text(PENDING_SETTING, &format!("{username}\n{email}"))
    }

    /// Незавершённая регистрация, если она есть.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn pending_registration(&self) -> Result<Option<PendingRegistration>> {
        let Some(stored) = self.storage.setting_text(PENDING_SETTING)? else {
            return Ok(None);
        };

        Ok(stored
            .split_once('\n')
            .filter(|(username, email)| !username.is_empty() && !email.is_empty())
            .map(|(username, email)| PendingRegistration {
                username: username.to_owned(),
                email: email.to_owned(),
            }))
    }

    /// Стирает запись о незавершённой регистрации.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn clear_pending_registration(&self) -> Result<()> {
        // Пустая строка — «записи нет»: см. [`Self::pending_registration`].
        self.storage.set_setting_text(PENDING_SETTING, "")
    }
}
