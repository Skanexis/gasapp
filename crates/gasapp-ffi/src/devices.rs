// SPDX-License-Identifier: Apache-2.0

//! Несколько устройств на границе с платформой (`docs/protocol/MULTI-DEVICE.md`).
//!
//! Новое устройство: [`Messenger::start_device_link`] (ссылка для QR) →
//! [`Messenger::poll_device_link`] раз в пару секунд → шесть цифр на
//! экране → [`Messenger::finish_device_link`].
//!
//! Основное: [`Messenger::prepare_device_link`] (по снятому QR — шесть
//! цифр и вопрос «Подключить?») → [`Messenger::approve_device_link`].
//!
//! 🔐 Закрытый ключ аккаунта через эту границу не проходит никогда.

use gasapp_types::Timestamp;

use crate::messenger::{FfiAccount, Messenger};
use crate::{guard, FfiError};

/// Грант пришёл на новое устройство.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiLinkOffer {
    /// Шесть цифр — должны совпасть с цифрами на основном устройстве.
    pub code: String,
    /// Имя аккаунта, к которому подключаемся.
    pub username: String,
}

/// Своё устройство.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiOwnDevice {
    /// Идентификатор устройства.
    pub device_id: String,
    /// Это устройство.
    pub this_device: bool,
    /// Основное: только оно подключает и отключает устройства.
    pub primary: bool,
}

#[uniffi::export]
impl Messenger {
    /// Новое устройство: ссылка для QR (живёт 60 секунд). Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — устройство уже зарегистрировано либо сервер
    /// недоступен.
    pub fn start_device_link(&self, now_millis: i64) -> Result<String, FfiError> {
        let client = self.client()?;
        guard(|| {
            client.start_device_link(Timestamp::from_millis(now_millis), &mut rand_core::OsRng)
        })
    }

    /// Новое устройство: пришёл ли грант; `None` — ещё нет. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — связывание не начато, грант не сходится.
    pub fn poll_device_link(&self) -> Result<Option<FfiLinkOffer>, FfiError> {
        let client = self.client()?;
        Ok(
            guard(|| client.poll_device_link())?.map(|offer| FfiLinkOffer {
                code: offer.code,
                username: offer.username,
            }),
        )
    }

    /// Новое устройство: цифры сверены — устройство входит в аккаунт.
    /// Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — гранта нет либо сервер отказал.
    pub fn finish_device_link(&self, now_millis: i64) -> Result<FfiAccount, FfiError> {
        let client = self.client()?;
        let account = guard(|| {
            client.finish_device_link(Timestamp::from_millis(now_millis), &mut rand_core::OsRng)
        })?;
        Ok(FfiAccount {
            account_id: account.account_id.to_string(),
            device_id: account.device_id.to_string(),
            username: account.username,
        })
    }

    /// Основное устройство: QR нового — шесть цифр для сверки. Сетевой
    /// вызов. Грант уходит только после [`Messenger::approve_device_link`].
    ///
    /// # Errors
    ///
    /// [`FfiError::PremiumRequired`] — это не основное устройство или
    /// устройств уже пять; [`FfiError::Core`] — не QR связывания, срок
    /// вышел, запрос подменён либо сервер недоступен.
    pub fn prepare_device_link(&self, uri: String, now_millis: i64) -> Result<String, FfiError> {
        let client = self.client()?;
        guard(|| {
            client.prepare_device_link(
                &uri,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
    }

    /// Основное устройство: «Подключить» — грант уходит. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — подготовленного гранта нет, срок QR вышел
    /// (новое устройство уже показывает другой код).
    pub fn approve_device_link(&self, now_millis: i64) -> Result<(), FfiError> {
        let client = self.client()?;
        guard(|| client.approve_device_link(Timestamp::from_millis(now_millis)))
    }

    /// Свои устройства. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — сервер недоступен.
    pub fn own_devices(&self, now_millis: i64) -> Result<Vec<FfiOwnDevice>, FfiError> {
        let client = self.client()?;
        Ok(
            guard(|| client.own_devices(Timestamp::from_millis(now_millis)))?
                .into_iter()
                .map(|device| FfiOwnDevice {
                    device_id: device.device_id,
                    this_device: device.this_device,
                    primary: device.primary,
                })
                .collect(),
        )
    }

    /// Основное устройство отключает другое. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::PremiumRequired`] — это не основное устройство;
    /// [`FfiError::Core`] — такого устройства нет, сервер недоступен.
    pub fn unlink_device(&self, device_id: String, now_millis: i64) -> Result<(), FfiError> {
        let client = self.client()?;
        guard(|| client.unlink_device(&device_id, Timestamp::from_millis(now_millis)))
    }

    /// Основное ли это устройство (подключать и отключать можно только с
    /// него). Без сети.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn is_primary_device(&self) -> Result<bool, FfiError> {
        let client = self.reader()?;
        guard(|| client.is_primary_device())
    }
}

/// QR-код ссылки связывания (показывает новое устройство).
///
/// # Errors
///
/// [`FfiError::Core`] — строка не ссылка связывания либо не помещается
/// в код; [`FfiError::InvalidArgument`] — матрица не представима.
#[uniffi::export]
pub fn device_link_qr(uri: String) -> Result<crate::FfiQrMatrix, FfiError> {
    let matrix = guard(|| {
        // В код попадает только настоящая ссылка связывания.
        let code = gasapp_protocol::device_link::LinkCode::parse(&uri)?;

        gasapp_protocol::qr::encode_text(&code.to_uri())
    })?;

    Ok(crate::FfiQrMatrix {
        size: u32::try_from(matrix.size).map_err(|_| FfiError::InvalidArgument)?,
        modules: matrix.modules,
    })
}
