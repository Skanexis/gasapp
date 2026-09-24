// SPDX-License-Identifier: Apache-2.0

//! Сетевые настройки и отчёт центра безопасности (M7).
//!
//! # Прокси
//!
//! Режим выхода в сеть хранится в зашифрованной базе, а применяет его
//! платформенный транспорт (см. `aegis-net::proxy`). Ядро отвечает за то,
//! чтобы в базу не попало недопустимое значение и чтобы повреждённое
//! значение **не превратилось в прямое соединение**: пользователь,
//! включивший Tor, должен либо ходить через Tor, либо видеть ошибку.
//!
//! # Отчёт безопасности
//!
//! 🔐 Центр безопасности показывал счёт «9 из 10» константой, а строки
//! «2 устройства» и «1 заблокированный» — выдуманными числами. Экран,
//! который выдумывает состояние защиты, опаснее отсутствия экрана:
//! человек перестаёт проверять то, что считает проверенным.
//!
//! Здесь каждая проверка считается по состоянию, которое можно
//! проверить на устройстве. Проверок, требующих сервера или платформы
//! (например, аппаратное хранилище ключей), в отчёте нет — лучше
//! не показать пункт, чем показать его выполненным наугад.

use aegis_net::client::Transport;
use aegis_net::proxy::ProxyMode;
use aegis_types::{Result, Timestamp};

use super::Client;
use crate::backup::BackupService;

/// Ключ настройки прокси в хранилище.
pub const PROXY_SETTING: &str = "network_proxy";

/// Какой возраст резервной копии ещё считается свежим: неделя.
///
/// Неделя, а не сутки: копия делается в фоне и не должна краснеть
/// из-за одного пропущенного дня без сети. Больше недели — это уже
/// неделя переписки, которую не вернуть при потере телефона.
pub const BACKUP_MAX_AGE_MILLIS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Сколько контактов просматривается при проверке верификации.
///
/// Предел нужен только для того, чтобы запрос был ограничен; у одного
/// человека столько контактов не бывает.
const CONTACTS_TO_CHECK: u32 = 100_000;

/// Проверки центра безопасности, посчитанные по состоянию устройства.
// Булевы поля здесь — не флаги состояния, которые стоило бы свернуть
// в перечисление, а результаты независимых проверок: любая комбинация
// допустима и осмысленна. Перечисление из тридцати двух вариантов
// читалось бы хуже пяти названных полей.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityReport {
    /// Ключ восстановления создан — есть чем расшифровать копию.
    pub recovery_key_created: bool,
    /// Последняя резервная копия не старше [`BACKUP_MAX_AGE_MILLIS`].
    pub backup_recent: bool,
    /// Сколько контактов не сверены по safety number.
    pub unverified_contacts: u32,
    /// Sealed sender включён: ключ доступа опубликован.
    pub sealed_sender_enabled: bool,
    /// IP-адрес скрыт от сервера прокси или Tor.
    pub address_hidden: bool,
}

impl SecurityReport {
    /// Результаты проверок в одном месте.
    ///
    /// Счёт и число проверок выводятся отсюда, поэтому добавить
    /// проверку, забыв учесть её в сумме, нельзя.
    const fn results(&self) -> [bool; 5] {
        [
            self.recovery_key_created,
            self.backup_recent,
            self.unverified_contacts == 0,
            self.sealed_sender_enabled,
            self.address_hidden,
        ]
    }

    /// Сколько проверок пройдено.
    #[must_use]
    pub fn passed(&self) -> u32 {
        self.results()
            .into_iter()
            .fold(0u32, |sum, ok| if ok { sum.saturating_add(1) } else { sum })
    }

    /// Сколько проверок всего.
    #[must_use]
    pub fn total(&self) -> u32 {
        u32::try_from(self.results().len()).unwrap_or(u32::MAX)
    }
}

impl<T: Transport> Client<T> {
    /// Текущий режим выхода в сеть.
    ///
    /// # Errors
    ///
    /// [`aegis_types::AegisError::Storage`] — чтение не удалось;
    /// [`aegis_types::AegisError::Malformed`] — запись повреждена.
    /// 🔐 Повреждённая запись — ошибка, а не прямое соединение:
    /// платформа при ошибке обязана закрыть сеть, а не открыть её.
    pub fn proxy_mode(&self) -> Result<ProxyMode> {
        match self.storage.setting_text(PROXY_SETTING)? {
            // 🔐 Без настройки — Tor, а не прямое соединение: сервер
            // не должен видеть адреса, пока человек сам не решит иначе.
            None => Ok(ProxyMode::default()),
            Some(value) => ProxyMode::from_setting(&value),
        }
    }

    /// Сохраняет режим выхода в сеть.
    ///
    /// Недопустимый режим отвергается до записи: в базе не должно
    /// оказаться значения, которое потом не разберётся.
    ///
    /// # Errors
    ///
    /// [`aegis_types::AegisError::Malformed`] — режим недопустим;
    /// [`aegis_types::AegisError::Storage`] — запись не удалась.
    pub fn set_proxy_mode(&self, mode: &ProxyMode) -> Result<()> {
        mode.validate()?;

        self.storage
            .set_setting_text(PROXY_SETTING, &mode.to_setting())
    }

    /// Считает проверки центра безопасности.
    ///
    /// # Errors
    ///
    /// [`aegis_types::AegisError::Storage`] — чтение не удалось.
    pub fn security_report(&self, now: Timestamp) -> Result<SecurityReport> {
        let backup = BackupService::new(&self.storage);

        let recovery_key_created = backup.is_configured()?;
        let backup_recent = backup.last_backup_at()?.is_some_and(|moment| {
            now.as_millis().saturating_sub(moment.as_millis()) <= BACKUP_MAX_AGE_MILLIS
        });

        let unverified = self
            .storage
            .list_contacts(CONTACTS_TO_CHECK)?
            .iter()
            .filter(|contact| !contact.verified)
            .count();

        // 🔐 Повреждённая настройка прокси не засчитывается как скрытый
        // адрес: утверждать защиту, которую нельзя подтвердить, нельзя.
        let address_hidden = self.proxy_mode().is_ok_and(|mode| mode.hides_address());

        Ok(SecurityReport {
            recovery_key_created,
            backup_recent,
            unverified_contacts: u32::try_from(unverified).unwrap_or(u32::MAX),
            sealed_sender_enabled: self.sealed_sender_enabled()?,
            address_hidden,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_net::client::{HttpRequest, HttpResponse};
    use aegis_storage::Storage;
    use aegis_types::{AccountId, AegisError, ChatId};

    /// Транспорт, у которого нет сети: проверки отчёта её не касаются.
    struct NoNetwork;

    impl Transport for NoNetwork {
        fn execute(&self, _request: &HttpRequest) -> Result<HttpResponse> {
            Err(AegisError::Network)
        }
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_760_000_000_000)
    }

    fn open_storage() -> (Storage, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("каталог");
        let path = directory
            .path()
            .join("aegis.db")
            .to_string_lossy()
            .into_owned();

        (Storage::new(&path, &[0x5Au8; 32]).expect("база"), directory)
    }

    /// 🔐 Без настройки — Tor.
    #[test]
    fn proxy_defaults_to_tor() {
        let (storage, _dir) = open_storage();
        let client = Client::new(NoNetwork, storage);

        assert_eq!(client.proxy_mode().expect("режим"), ProxyMode::Orbot);
    }

    /// Режим сохраняется и читается обратно.
    #[test]
    fn proxy_mode_round_trips() {
        let (storage, _dir) = open_storage();
        let client = Client::new(NoNetwork, storage);

        client.set_proxy_mode(&ProxyMode::Orbot).expect("запись");
        assert_eq!(client.proxy_mode().expect("режим"), ProxyMode::Orbot);

        let socks = ProxyMode::Socks5 {
            host: "proxy.example.org".to_owned(),
            port: 1080,
        };
        client.set_proxy_mode(&socks).expect("замена");
        assert_eq!(client.proxy_mode().expect("режим"), socks);
    }

    /// Недопустимый режим не попадает в базу.
    #[test]
    fn invalid_proxy_is_not_stored() {
        let (storage, _dir) = open_storage();
        let client = Client::new(NoNetwork, storage);

        client.set_proxy_mode(&ProxyMode::Orbot).expect("запись");

        let invalid = ProxyMode::Socks5 {
            host: "user@proxy.example.org".to_owned(),
            port: 1080,
        };

        assert!(client.set_proxy_mode(&invalid).is_err());
        assert_eq!(
            client.proxy_mode().expect("режим"),
            ProxyMode::Orbot,
            "недопустимый режим затёр прежний"
        );
    }

    /// 🔐 Повреждённая запись — ошибка, а не прямое соединение.
    #[test]
    fn corrupted_proxy_setting_is_an_error() {
        let (storage, _dir) = open_storage();
        storage
            .set_setting_text(PROXY_SETTING, "мусор")
            .expect("запись");
        let client = Client::new(NoNetwork, storage);

        assert!(client.proxy_mode().is_err());
        assert!(
            !client.security_report(now()).expect("отчёт").address_hidden,
            "повреждённая настройка засчитана как скрытый адрес"
        );
    }

    /// На свежем устройстве пройдены проверка контактов (сверять пока
    /// некого) и скрытого адреса — Tor включён по умолчанию.
    #[test]
    fn fresh_device_report_is_honest() {
        let (storage, _dir) = open_storage();
        let client = Client::new(NoNetwork, storage);

        let report = client.security_report(now()).expect("отчёт");

        assert!(!report.recovery_key_created);
        assert!(!report.backup_recent);
        assert_eq!(report.unverified_contacts, 0);
        assert!(!report.sealed_sender_enabled);
        assert!(report.address_hidden, "Tor по умолчанию не засчитан");
        assert_eq!(report.passed(), 2);
        assert_eq!(report.total(), 5);
    }

    /// Непроверенный контакт проваливает проверку, проверенный — нет.
    #[test]
    fn unverified_contacts_are_counted() {
        let (unverified_storage, _first) = open_storage();
        let contact = AccountId::generate();
        unverified_storage
            .save_contact(
                &contact,
                &[0x11; 32],
                Some("bob"),
                Some(&ChatId::generate()),
                now(),
            )
            .expect("контакт");
        let unverified = Client::new(NoNetwork, unverified_storage);

        assert_eq!(
            unverified
                .security_report(now())
                .expect("отчёт")
                .unverified_contacts,
            1
        );

        let (verified_storage, _second) = open_storage();
        verified_storage
            .save_contact(
                &contact,
                &[0x11; 32],
                Some("bob"),
                Some(&ChatId::generate()),
                now(),
            )
            .expect("контакт");
        verified_storage
            .set_contact_verified(&contact, true, now())
            .expect("верификация");
        let verified = Client::new(NoNetwork, verified_storage);

        assert_eq!(
            verified
                .security_report(now())
                .expect("отчёт")
                .unverified_contacts,
            0
        );
    }

    /// Прокси засчитывается как скрытый адрес.
    #[test]
    fn proxy_counts_as_hidden_address() {
        let (storage, _dir) = open_storage();
        let client = Client::new(NoNetwork, storage);

        client.set_proxy_mode(&ProxyMode::Orbot).expect("запись");

        let report = client.security_report(now()).expect("отчёт");

        assert!(report.address_hidden);
        assert!(report.passed() <= report.total());
    }
}
