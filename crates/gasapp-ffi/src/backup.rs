// SPDX-License-Identifier: Apache-2.0

//! Граница FFI резервного копирования и File Vault.
//!
//! # 🔐 Что здесь не пересекает границу
//!
//! **Ключи.** Ни `K_vault`, ни BRK, ни ключи файлов. Recovery key
//! пересекает её строкой — но только в ту сторону, в какую его
//! показывают человеку, и обратно, когда человек его набирает.
//! Иначе нельзя: ключ существует ровно затем, чтобы пользователь
//! записал его на бумагу.
//!
//! Вывод `K_vault` целиком остаётся в Rust: платформа передаёт сюда
//! подтверждённый PIN, а не готовый ключ (см. `Vault::unlock`).
//!
//! # Про файлы
//!
//! Rust не пишет на диск ничего, кроме базы. Файл копии и блобы
//! vault возвращаются байтами, а записывает и читает их платформа —
//! ровно так же, как со вложениями. Причина та же: путь к файлу
//! и права на него — вопрос платформы, а не ядра.

use gasapp_backup::recovery_key::GROUP_COUNT;
use gasapp_backup::RecoveryKey;
use gasapp_core::client::Client;
use gasapp_types::{MessageId, Timestamp};

use crate::messenger::{ForeignTransport, Messenger};
use crate::{guard, FfiError};

/// Recovery key, показанный пользователю.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiRecoveryKey {
    /// Запись ключа: `GASAPP-XXXX-…`, 13 групп по 4 символа.
    ///
    /// 🔐 Показывается **один раз** и на защищённом экране
    /// (`FLAG_SECURE` на Android). Платформа обязана не класть её
    /// ни в буфер обмена по умолчанию, ни в снимок экрана.
    pub display: String,
    /// Сколько групп в записи — чтобы интерфейс не считал сам.
    pub group_count: u32,
}

/// Готовая резервная копия.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiBackup {
    /// Зашифрованный файл: его выгружает платформа.
    pub archive: Vec<u8>,
    /// Номер в цепочке.
    pub generation: u32,
    /// Полный ли это снимок.
    pub is_full: bool,
    /// Сколько строк вошло в копию.
    pub record_count: u32,
}

/// Метаданные копии, прочитанные без расшифровки тела.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiBackupMeta {
    /// Когда собрана копия, миллисекунды.
    pub created_at_millis: i64,
    /// Сколько записей внутри.
    pub record_count: u32,
    /// Сколько из них сообщений.
    pub message_count: u32,
    /// Метка устройства, собравшего копию.
    pub device_label: Option<String>,
}

/// Итог восстановления.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiRestore {
    /// Сколько строк применено.
    pub applied: u32,
    /// Сколько звеньев цепочки применено.
    pub links: u32,
    /// Когда сделана последняя копия цепочки.
    pub created_at_millis: i64,
    /// Сменился ли ключ безопасности устройства.
    ///
    /// Всегда `true`. Интерфейс обязан показать экран «ваш ключ
    /// безопасности изменился»: собеседники увидят это как смену
    /// safety number, и без объяснения смена выглядит как подмена.
    pub identity_changed: bool,
}

/// Итог возвращения аккаунта на новое устройство.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiRecoveredAccount {
    /// Аккаунт — с прежним именем, на новой identity.
    pub account: crate::messenger::FfiAccount,
    /// Итог восстановления переписки.
    pub restore: FfiRestore,
}

/// Состояние резервного копирования для Recovery Center.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiBackupStatus {
    /// Настроено ли копирование.
    pub configured: bool,
    /// Когда делалась последняя копия.
    pub last_backup_at_millis: Option<i64>,
}

/// Файл в vault.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiVaultFile {
    /// Идентификатор записи.
    pub file_id: String,
    /// Имя файла.
    pub name: String,
    /// Размер открытого файла в байтах.
    pub size: i64,
    /// Когда добавлен, миллисекунды.
    pub created_at_millis: i64,
    /// Путь к шифроблобу — по нему платформа читает файл.
    pub location: String,
}

/// Только что зашифрованный файл vault.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSealedVaultFile {
    /// Идентификатор записи.
    pub file_id: String,
    /// Шифроблоб — его платформа записывает по `location`.
    pub ciphertext: Vec<u8>,
}

/// Событие журнала безопасности.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSecurityEvent {
    /// Тип события.
    pub event_type: String,
    /// Подробности.
    pub details: String,
    /// Когда случилось, миллисекунды.
    pub timestamp_millis: i64,
}

/// Генерирует новый recovery key.
///
/// 🔐 Ключ существует только в возвращённой строке: он не пишется
/// ни в базу, ни в файл. Потерять его — значит потерять доступ
/// к копиям, и это осознанная цена обещания №4.
///
/// # Errors
///
/// [`FfiError::Panic`] — сбой генератора случайных чисел.
#[uniffi::export]
pub fn generate_recovery_key() -> Result<FfiRecoveryKey, FfiError> {
    let display = std::panic::catch_unwind(|| {
        RecoveryKey::generate(&mut rand_core::OsRng).to_display_string()
    })
    .map_err(|_| FfiError::Panic)?;

    Ok(FfiRecoveryKey {
        display,
        group_count: u32::try_from(GROUP_COUNT).unwrap_or(0),
    })
}

/// Проверяет, что набранный ключ похож на настоящий.
///
/// 🔐 Проверяется контрольная сумма — то есть опечатка отвергается
/// мгновенно, до дорогого Argon2id. Успех означает «строка выглядит
/// как ключ», а не «этот ключ открывает вашу копию»: второе
/// выясняется только попыткой расшифровать.
#[uniffi::export]
#[must_use]
pub fn validate_recovery_key(text: String) -> bool {
    RecoveryKey::parse(&text).is_ok()
}

/// Сверяет введённую группу с эталонной.
///
/// Нужно экрану подтверждения записи: у пользователя просят три
/// случайные группы, чтобы он не пролистал показ ключа не глядя.
///
/// # Errors
///
/// [`FfiError::InvalidArgument`] — ключ не разбирается либо номер
/// группы вне диапазона.
#[uniffi::export]
pub fn check_recovery_key_group(
    text: String,
    index: u32,
    entered: String,
) -> Result<bool, FfiError> {
    let key = RecoveryKey::parse(&text).map_err(|_| FfiError::InvalidArgument)?;
    let index = usize::try_from(index).map_err(|_| FfiError::InvalidArgument)?;

    key.check_group(index, &entered)
        .map_err(|_| FfiError::InvalidArgument)
}

#[uniffi::export]
impl Messenger {
    /// Делает резервную копию и отдаёт зашифрованный файл.
    ///
    /// Операция долгая: Argon2id с 256 МиБ памяти плюс чтение всей
    /// базы. Вызывать в фоновом потоке.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — recovery key не разбирается;
    /// [`FfiError::Core`] — сбой чтения базы или шифрования.
    pub fn create_backup(
        &self,
        recovery_key: String,
        device_label: Option<String>,
        now_millis: i64,
    ) -> Result<FfiBackup, FfiError> {
        let key = RecoveryKey::parse(&recovery_key).map_err(|_| FfiError::InvalidArgument)?;
        let client = self.client()?;

        let outcome = guard(|| {
            client.create_backup(
                &key,
                device_label.as_deref(),
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })?;

        Ok(FfiBackup {
            archive: outcome.archive,
            generation: outcome.generation,
            is_full: outcome.is_full,
            record_count: u32::try_from(outcome.record_count).unwrap_or(u32::MAX),
        })
    }

    /// Восстанавливает данные из цепочки копий.
    ///
    /// `links` — файлы в порядке создания: сначала полный снимок,
    /// затем инкременты. Разорванная цепочка отвергается целиком.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — recovery key не разбирается;
    /// [`FfiError::Core`] — цепочка разорвана, файл изменён либо
    /// ключ не тот.
    pub fn restore_backup(
        &self,
        recovery_key: String,
        links: Vec<Vec<u8>>,
        now_millis: i64,
    ) -> Result<FfiRestore, FfiError> {
        let key = RecoveryKey::parse(&recovery_key).map_err(|_| FfiError::InvalidArgument)?;
        let client = self.client()?;

        let outcome =
            guard(|| client.restore_backup(&key, &links, Timestamp::from_millis(now_millis)))?;

        Ok(FfiRestore {
            applied: u32::try_from(outcome.applied).unwrap_or(u32::MAX),
            links: u32::try_from(outcome.links).unwrap_or(u32::MAX),
            created_at_millis: outcome.created_at.as_millis(),
            identity_changed: outcome.identity_changed,
        })
    }

    /// 🔐 Возвращает аккаунт на новое устройство **с прежним именем**
    /// (`Client::recover_account`): копия восстанавливается в эту базу,
    /// создаётся новая identity, и ключ восстановления аккаунта из копии
    /// подписывает перепривязку.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — recovery key не разбирается;
    /// [`FfiError::Core`] — не тот ключ, цепочка разорвана, в копии нет
    /// ключа восстановления аккаунта либо сервер отказал.
    pub fn recover_account(
        &self,
        recovery_key: String,
        links: Vec<Vec<u8>>,
        now_millis: i64,
    ) -> Result<FfiRecoveredAccount, FfiError> {
        let key = RecoveryKey::parse(&recovery_key).map_err(|_| FfiError::InvalidArgument)?;
        let client = self.client()?;

        let (account, outcome) = guard(|| {
            client.recover_account(
                &key,
                &links,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })?;

        Ok(FfiRecoveredAccount {
            account: crate::messenger::FfiAccount {
                account_id: account.account_id.to_string(),
                device_id: account.device_id.to_string(),
                username: account.username,
            },
            restore: FfiRestore {
                applied: u32::try_from(outcome.applied).unwrap_or(u32::MAX),
                links: u32::try_from(outcome.links).unwrap_or(u32::MAX),
                created_at_millis: outcome.created_at.as_millis(),
                identity_changed: outcome.identity_changed,
            },
        })
    }

    /// Читает метаданные копии, не расшифровывая переписку.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — recovery key не разбирается;
    /// [`FfiError::Core`] — файл не разбирается либо ключ не тот.
    pub fn inspect_backup(
        &self,
        recovery_key: String,
        archive: Vec<u8>,
    ) -> Result<FfiBackupMeta, FfiError> {
        let key = RecoveryKey::parse(&recovery_key).map_err(|_| FfiError::InvalidArgument)?;

        let meta = guard(|| Client::<ForeignTransport>::inspect_backup(&key, &archive))?;

        Ok(FfiBackupMeta {
            created_at_millis: meta.created_at_millis,
            record_count: meta.record_count,
            message_count: meta.message_count,
            device_label: meta.device_label,
        })
    }

    /// Состояние резервного копирования для Recovery Center.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение базы не удалось.
    pub fn backup_status(&self) -> Result<FfiBackupStatus, FfiError> {
        let client = self.reader()?;

        let (configured, last) =
            guard(|| Ok((client.backup_configured()?, client.last_backup_at()?)))?;

        Ok(FfiBackupStatus {
            configured,
            last_backup_at_millis: last.map(|moment| moment.as_millis()),
        })
    }

    /// Забывает цепочку копий — при создании нового recovery key.
    ///
    /// ⚠️ Прежние файлы в облаке остаются читаемыми **старым**
    /// ключом: перешифровать их отсюда нельзя, и удалить их должен
    /// тот, кто ими владеет. Интерфейс обязан это сказать.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — запись не удалась.
    pub fn forget_backup_chain(&self) -> Result<(), FfiError> {
        let client = self.client()?;

        guard(|| client.forget_backup_chain())
    }

    /// Уплотняет базу, если пришёл срок.
    ///
    /// Возвращает `true`, если уплотнение выполнено. Вызывать
    /// при холодном старте в фоновом потоке: `VACUUM` переписывает
    /// файл целиком.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — уплотнение не удалось.
    pub fn maintain_storage(&self, now_millis: i64) -> Result<bool, FfiError> {
        let client = self.client()?;

        guard(|| client.maintain_storage(Timestamp::from_millis(now_millis)))
    }

    /// Читает журнал безопасности.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение не удалось.
    pub fn security_events(&self, limit: u32) -> Result<Vec<FfiSecurityEvent>, FfiError> {
        let client = self.reader()?;

        let events = guard(|| client.security_events(limit))?;

        Ok(events
            .into_iter()
            .map(|(event_type, details, timestamp)| FfiSecurityEvent {
                event_type,
                details,
                timestamp_millis: timestamp.as_millis(),
            })
            .collect())
    }

    /// Открывает File Vault после повторной аутентификации.
    ///
    /// 🔐 PIN передаётся сюда, а ключ vault наружу не выходит:
    /// вывод целиком происходит в ядре. Платформа обязана вызывать
    /// этот метод **только** после свежего подтверждения личности —
    /// ввода PIN или биометрии, — потому что ядро отличить свежее
    /// подтверждение от запомненного не может.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — PIN короче допустимого, соль не той
    /// длины либо сбой вывода ключей.
    pub fn unlock_vault(
        &self,
        pin: Vec<u8>,
        salt: Vec<u8>,
        now_millis: i64,
    ) -> Result<(), FfiError> {
        let pin = crate::pin_bytes(pin);
        let client = self.client()?;

        guard(|| {
            client.unlock_vault(
                crate::pin_text(&pin)?,
                &salt,
                Timestamp::from_millis(now_millis),
            )
        })
    }

    /// Заводит проверочное значение vault по заведомо верному PIN.
    ///
    /// 🔐 Платформа зовёт это **сразу после** того, как база открылась
    /// этим PIN, — единственный момент, когда верность PIN известна.
    /// После этого [`Self::unlock_vault`] отвергает неверный PIN даже
    /// в пустом vault, и опечатка при первом открытии не привязывает
    /// к себе первый добавленный файл.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — сбой вывода ключа или записи.
    ///
    /// Локальная запись — через клиент локальных операций: сетевой замок
    /// сразу после входа держит пополнение предключей через Tor, и вход
    /// ждал его десятки секунд.
    pub fn establish_vault_verifier(&self, pin: Vec<u8>, salt: Vec<u8>) -> Result<(), FfiError> {
        let pin = crate::pin_bytes(pin);
        let client = self.reader()?;

        guard(|| {
            client.establish_vault_verifier(crate::pin_text(&pin)?, &salt, &mut rand_core::OsRng)
        })
    }

    /// Закрывает vault и обнуляет его ключ.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — состояние vault недоступно.
    pub fn seal_vault(&self) -> Result<(), FfiError> {
        let client = self.client()?;

        guard(|| client.seal_vault())
    }

    /// 🔐 Сообщает ядру об уходе приложения в фон.
    ///
    /// Vault закрывается немедленно, не дожидаясь таймаута: в фоне
    /// экран попадает в снимок переключателя задач, а телефон —
    /// в чужие руки.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — состояние vault недоступно.
    pub fn on_background(&self) -> Result<(), FfiError> {
        let client = self.client()?;

        guard(|| client.on_background())
    }

    /// Открыт ли vault.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — состояние vault недоступно.
    pub fn is_vault_open(&self, now_millis: i64) -> Result<bool, FfiError> {
        let client = self.client()?;

        guard(|| client.vault_is_open(Timestamp::from_millis(now_millis)))
    }

    /// Сколько файлов в vault.
    ///
    /// Доступно и при закрытом vault: число файлов не говорит,
    /// какие они.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение не удалось.
    pub fn vault_file_count(&self) -> Result<u32, FfiError> {
        let client = self.reader()?;

        guard(|| client.vault_file_count())
    }

    /// Перечисляет файлы vault.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — vault закрыт либо чтение не удалось.
    pub fn vault_files(&self, limit: u32, now_millis: i64) -> Result<Vec<FfiVaultFile>, FfiError> {
        let client = self.client()?;

        let files = guard(|| client.vault_files(limit, Timestamp::from_millis(now_millis)))?;

        Ok(files
            .into_iter()
            .map(|row| FfiVaultFile {
                file_id: row.file_id.to_string(),
                name: row.name,
                size: row.size,
                created_at_millis: row.created_at.as_millis(),
                location: row.location,
            })
            .collect())
    }

    /// Кладёт файл в vault и отдаёт шифроблоб для записи на диск.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — vault закрыт либо шифрование не удалось.
    pub fn add_vault_file(
        &self,
        name: String,
        contents: Vec<u8>,
        location: String,
        now_millis: i64,
    ) -> Result<FfiSealedVaultFile, FfiError> {
        let client = self.client()?;

        let sealed = guard(|| {
            client.add_vault_file(
                &name,
                &contents,
                &location,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })?;

        Ok(FfiSealedVaultFile {
            file_id: sealed.file_id.to_string(),
            ciphertext: sealed.ciphertext,
        })
    }

    /// Расшифровывает файл vault.
    ///
    /// `ciphertext` — содержимое блоба, прочитанное платформой
    /// по пути из [`FfiVaultFile::location`].
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — идентификатор не разбирается;
    /// [`FfiError::Core`] — vault закрыт либо блоб подменён.
    pub fn open_vault_file(
        &self,
        file_id: String,
        ciphertext: Vec<u8>,
        now_millis: i64,
    ) -> Result<Vec<u8>, FfiError> {
        let parsed = parse_file_id(&file_id)?;
        let client = self.client()?;

        guard(|| client.open_vault_file(&parsed, &ciphertext, Timestamp::from_millis(now_millis)))
    }

    /// Убирает файл из vault и отдаёт путь к его блобу.
    ///
    /// Сам файл с диска стирает платформа: файловой системы ядро
    /// не касается.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — идентификатор не разбирается;
    /// [`FfiError::Core`] — vault закрыт либо удаление не удалось.
    pub fn delete_vault_file(
        &self,
        file_id: String,
        now_millis: i64,
    ) -> Result<Option<String>, FfiError> {
        let parsed = parse_file_id(&file_id)?;
        let client = self.client()?;

        guard(|| client.delete_vault_file(&parsed, Timestamp::from_millis(now_millis)))
    }
}

/// Разбирает идентификатор файла vault.
fn parse_file_id(raw: &str) -> Result<MessageId, FfiError> {
    uuid::Uuid::parse_str(raw)
        .map(MessageId::from_uuid)
        .map_err(|_| FfiError::InvalidArgument)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Сгенерированный ключ выглядит так, как обещано разделом 12.2.
    #[test]
    fn generated_key_has_the_promised_shape() {
        let key = generate_recovery_key().expect("ключ");

        assert_eq!(key.group_count, 13);
        assert!(key.display.starts_with("GASAPP-"));
        assert_eq!(
            key.display.split('-').count(),
            14,
            "приставка и 13 групп: {}",
            key.display
        );
    }

    /// Свой же ключ проходит проверку.
    #[test]
    fn generated_key_validates() {
        let key = generate_recovery_key().expect("ключ");

        assert!(validate_recovery_key(key.display));
    }

    /// 🔐 Опечатка отвергается проверкой.
    #[test]
    fn typo_fails_validation() {
        let key = generate_recovery_key().expect("ключ");

        assert!(!validate_recovery_key(format!("{}X", key.display)));
        assert!(!validate_recovery_key("не ключ вовсе".to_owned()));
        assert!(!validate_recovery_key(String::new()));
    }

    /// Подтверждение группы принимает верный ввод.
    #[test]
    fn group_check_accepts_the_right_group() {
        let key = generate_recovery_key().expect("ключ");
        let third = key
            .display
            .split('-')
            .nth(4)
            .expect("четвёртая группа")
            .to_owned();

        assert!(check_recovery_key_group(key.display.clone(), 3, third.clone()).expect("сверка"));
        assert!(!check_recovery_key_group(key.display, 3, "ZZZZ".to_owned()).expect("сверка"));
    }

    /// Номер группы вне диапазона — ошибка аргумента.
    #[test]
    fn group_index_out_of_range_is_an_error() {
        let key = generate_recovery_key().expect("ключ");

        assert!(matches!(
            check_recovery_key_group(key.display, 99, "ZZZZ".to_owned()),
            Err(FfiError::InvalidArgument)
        ));
    }

    /// Мусор вместо ключа не доходит до сверки групп.
    #[test]
    fn garbage_key_is_rejected_before_group_check() {
        assert!(matches!(
            check_recovery_key_group("мусор".to_owned(), 0, "ZZZZ".to_owned()),
            Err(FfiError::InvalidArgument)
        ));
    }

    /// Идентификатор файла разбирается только как UUID.
    #[test]
    fn file_id_must_be_a_uuid() {
        assert!(parse_file_id("не uuid").is_err());
        assert!(parse_file_id(&MessageId::generate().to_string()).is_ok());
    }
}
