// SPDX-License-Identifier: Apache-2.0

//! Оркестрация резервного копирования.
//!
//! # Что здесь происходит
//!
//! Между хранилищем и криптографией. `gasapp-storage` умеет читать
//! и писать строки, `gasapp-backup` — шифровать и проверять цепочку;
//! ни один из них не знает про другой. Здесь — порядок вызовов:
//! выгрузить, перевести в записи бандла, зашифровать, запомнить
//! состояние цепочки.
//!
//! # 🔐 Где живёт recovery key
//!
//! Нигде. Он приходит аргументом на время одного вызова и исчезает
//! вместе с ним. Ни один метод этого модуля не пишет его на диск
//! и не кладёт в поле структуры: обещание «recovery key никогда
//! не хранится на устройстве» (раздел 12.3) держится тем, что
//! хранить его тут просто негде.
//!
//! # Что происходит при восстановлении
//!
//! ```text
//!   Цепочка файлов ──▶ проверка SHA-256 звеньев
//!                            │
//!                            ▼
//!                      слияние бандлов
//!                            │
//!                            ▼
//!         ┌──── История сообщений ──▶ в базу
//!         ├──── Контакты и настройки ──▶ в базу
//!         ├──── Identity-ключ ────────▶ 🔴 НЕ восстанавливается
//!         └──── Сессии ───────────────▶ 🔴 НЕ восстанавливаются
//! ```
//!
//! Две последние строки — решение раздела 12.5, и оно означает,
//! что после восстановления собеседники увидят «safety number
//! changed». Это правильное поведение, а не дефект: устройство
//! действительно новое. Интерфейс обязан это объяснить —
//! см. [`RestoreOutcome::identity_changed`].

use gasapp_backup::bundle::{
    AttachmentRecord, BackupBundle, ChatRecord, ContactRecord, MessageRecord, SettingRecord, ID_LEN,
};
use gasapp_backup::{BackupChain, KdfParams, RecoveryKey};
use gasapp_storage::backup::{BackupChainState, BackupExport, ChatBackupRow};
use gasapp_storage::{
    ContactRow, MessageStatus, Storage, StoredAttachment, StoredMessage, VaultFileRow,
};
use gasapp_types::{AccountId, ChatId, Ciphertext, GasAppError, MessageId, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

/// Сколько инкрементов делать до следующего полного снимка.
///
/// После этого числа звеньев цепочка начинается заново. Причина
/// не в безопасности, а в стоимости восстановления: цепочку
/// из сотни файлов нужно скачать целиком, и потеря любого звена
/// делает бесполезными все последующие.
pub const INCREMENTS_BEFORE_FULL: u32 = 30;

/// Как часто уплотнять базу: раз в неделю.
///
/// `VACUUM` переписывает файл целиком, поэтому чаще незачем,
/// а реже — значит дольше держать освобождённые страницы удалённых
/// сообщений в файле.
pub const VACUUM_INTERVAL_MILLIS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Итог создания резервной копии.
#[derive(Debug, Clone)]
pub struct BackupOutcome {
    /// Зашифрованный файл — его выгружает платформа.
    pub archive: Vec<u8>,
    /// Номер поколения в цепочке.
    pub generation: u32,
    /// Полный ли это снимок.
    pub is_full: bool,
    /// Сколько строк вошло в копию.
    pub record_count: usize,
}

/// Итог восстановления.
#[derive(Debug, Clone)]
pub struct RestoreOutcome {
    /// Сколько строк применено к базе.
    pub applied: usize,
    /// Сколько звеньев цепочки применено.
    pub links: usize,
    /// Когда сделана последняя копия цепочки.
    pub created_at: Timestamp,

    /// Имя аккаунта из копии — для возвращения аккаунта
    /// (`Client::recover_account`).
    pub username: Option<String>,

    /// Сменился ли identity-ключ устройства.
    ///
    /// Всегда `true`: восстановление не переносит приватный
    /// identity-ключ (раздел 12.5), значит устройство получает новый.
    /// Поле существует не ради значения, а ради того, чтобы вызов
    /// восстановления обязан был на него посмотреть — интерфейс
    /// показывает экран «ваш ключ безопасности изменился», и забыть
    /// его показать нельзя, не проигнорировав это поле явно.
    pub identity_changed: bool,
}

/// Резервное копирование поверх хранилища.
///
/// # Про заимствование
///
/// Держит ссылку на хранилище, а не владеет им: копия — это одна
/// из операций над той же базой, с которой работает клиент, а не
/// отдельная её жизнь.
pub struct BackupService<'a> {
    storage: &'a Storage,
    params: KdfParams,
}

impl core::fmt::Debug for BackupService<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupService")
    }
}

impl<'a> BackupService<'a> {
    /// Создаёт службу с параметрами растягивания по умолчанию.
    #[must_use]
    pub const fn new(storage: &'a Storage) -> Self {
        Self::with_params(
            storage,
            KdfParams {
                memory_kib: gasapp_backup::kdf::DEFAULT_MEMORY_KIB,
                iterations: gasapp_backup::kdf::DEFAULT_ITERATIONS,
                parallelism: gasapp_backup::kdf::DEFAULT_PARALLELISM,
            },
        )
    }

    /// Создаёт службу с заданными параметрами растягивания.
    ///
    /// # Зачем это нужно
    ///
    /// ⚠️ План (ADR-018) прямо отмечает: 256 МиБ на бюджетном
    /// телефоне могут кончиться отказом по памяти. Устройство,
    /// которому параметры по умолчанию не по силам, понижает их
    /// здесь — и они уезжают в заголовок копии, чтобы восстановление
    /// на другом устройстве повторило именно этот выбор.
    ///
    /// Параметры действуют только на **новую** цепочку: продолжение
    /// существующей всегда берёт те, которыми она начата, иначе BRK
    /// вышел бы другим и звенья перестали бы открываться одним ключом.
    #[must_use]
    pub const fn with_params(storage: &'a Storage, params: KdfParams) -> Self {
        Self { storage, params }
    }

    /// Делает резервную копию.
    ///
    /// Полный снимок или инкремент выбирается сам: инкремент, если
    /// цепочка уже начата и не переросла [`INCREMENTS_BEFORE_FULL`];
    /// полный снимок в остальных случаях.
    ///
    /// # 🔐 Про recovery key
    ///
    /// Ключ используется здесь и не сохраняется. После возврата
    /// из метода в памяти остаётся только зашифрованный файл.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение или запись базы не удались;
    /// [`GasAppError::Crypto`] — сбой вывода ключей или шифрования;
    /// [`GasAppError::Malformed`] — данные не помещаются в пределы
    /// формата копии.
    pub fn create<R: RngCore + CryptoRng>(
        &self,
        recovery_key: &RecoveryKey,
        device_label: Option<&str>,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<BackupOutcome> {
        let previous = self.storage.backup_chain_state()?;

        // 🔐 Тот ли ключ продолжает цепочку.
        //
        // Прежде ключ не сверялся: любой годный по контрольной сумме ключ —
        // старый с бумажки после смены или чужой, введённый тем, кому
        // дали разблокированный телефон, — дописывал инкремент, который
        // настоящим ключом не открывается. Состояние цепочки при этом
        // сдвигалось, и всё, что попало в это звено, из копий пропадало
        // молча. Теперь неверный ключ — отказ до сборки файла.
        //
        // Цепочка, заведённая до проверочного значения, сверить нечем:
        // она начинается заново полным снимком, и значение заводится.
        let verified = match previous.as_ref() {
            Some(state) => self.verified_chain(recovery_key, state)?,
            None => None,
        };

        // Инкремент возможен, только если прежняя цепочка цела, сверена
        // и не слишком длинная.
        let continuing = verified.filter(|(_, state)| {
            state.generation < INCREMENTS_BEFORE_FULL
                && state.last_digest.len() == gasapp_backup::archive::DIGEST_LEN
        });

        let (mut chain, is_full) = match continuing {
            Some((chain, _)) => (chain, false),
            None => (BackupChain::start(recovery_key, self.params, rng)?, true),
        };

        // Полный снимок берёт всё; инкремент — изменившееся после
        // отметки прошлой копии.
        let since = if is_full {
            None
        } else {
            previous.as_ref().map(|state| state.watermark)
        };

        let export = self.storage.export_for_backup(since, now)?;
        let record_count = export.record_count();
        let bundle = export_to_bundle(&export, now);

        let archive = if is_full {
            chain.seal_full(&bundle, device_label, rng)?
        } else {
            chain.seal_increment(&bundle, device_label, rng)?
        };

        // 🔐 Состояние цепочки записывается **после** успешной сборки
        // файла. Обратный порядок оставил бы отметку сдвинутой при
        // сбое шифрования — то есть следующий инкремент пропустил бы
        // данные, которые в копию так и не попали.
        self.storage.save_backup_chain_state(&BackupChainState {
            salt: chain.salt().to_vec(),
            memory_kib: chain.params().memory_kib,
            iterations: chain.params().iterations,
            parallelism: chain.params().parallelism,
            generation: chain.generation(),
            last_digest: chain.last_digest().to_vec(),
            watermark: now,
            last_backup_at: Some(now),
        })?;
        self.storage.set_setting_text(
            KEY_CHECK_SETTING,
            &key_check_record(chain.salt(), &chain.key_check()?),
        )?;

        // Надгробия уехали в копию — держать их дальше незачем.
        self.storage.prune_tombstones(now)?;

        Ok(BackupOutcome {
            archive,
            generation: chain.generation(),
            is_full,
            record_count,
        })
    }

    /// Цепочка, продолженная этим ключом, — если он её ключ.
    ///
    /// `Ok(None)` — сверить нечем (цепочка заведена до проверочного
    /// значения либо её состояние испорчено): начинать заново.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] — ключ не тот;
    /// [`GasAppError::Storage`] — чтение не удалось.
    fn verified_chain<'s>(
        &self,
        recovery_key: &RecoveryKey,
        state: &'s BackupChainState,
    ) -> Result<Option<(BackupChain, &'s BackupChainState)>> {
        let Some(record) = self.storage.setting_text(KEY_CHECK_SETTING)? else {
            return Ok(None);
        };
        let Ok(salt) = to_salt(&state.salt) else {
            return Ok(None);
        };
        // Значение другой цепочки (после смены ключа или восстановления
        // состояние сброшено, а запись осталась) — сверять не с чем.
        let Some(expected) = parse_key_check_record(&record, &salt) else {
            return Ok(None);
        };

        let digest =
            to_digest(&state.last_digest).unwrap_or([0u8; gasapp_backup::archive::DIGEST_LEN]);
        let chain = BackupChain::resume(
            recovery_key,
            salt,
            KdfParams {
                memory_kib: state.memory_kib,
                iterations: state.iterations,
                parallelism: state.parallelism,
            },
            state.generation,
            digest,
        )?;

        let presented = chain.key_check()?;
        let same = presented
            .iter()
            .zip(expected.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
        if !same {
            return Err(GasAppError::Crypto);
        }

        Ok(Some((chain, state)))
    }

    /// Читает метаданные копии, не расшифровывая тело.
    ///
    /// Нужно Recovery Center: показать «последняя копия два часа
    /// назад, 1247 сообщений», не вытягивая всю переписку.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — файл не разбирается;
    /// [`GasAppError::Crypto`] — не тот recovery key.
    pub fn inspect(
        recovery_key: &RecoveryKey,
        archive: &[u8],
    ) -> Result<gasapp_backup::ArchiveMeta> {
        let header = gasapp_backup::ArchiveHeader::from_bytes(archive)?;
        let chain = BackupChain::resume(
            recovery_key,
            header.salt,
            header.params,
            header.generation,
            [0u8; gasapp_backup::archive::DIGEST_LEN],
        )?;

        chain.peek(archive)
    }

    /// Восстанавливает данные из цепочки копий.
    ///
    /// Звенья передаются в порядке создания. Цепочка проверяется
    /// целиком **до** записи в базу: разорванная цепочка — отказ,
    /// а не частичное восстановление.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — цепочка пуста, разорвана либо
    /// собрана не в том порядке;
    /// [`GasAppError::Crypto`] — не тот recovery key либо файл изменён;
    /// [`GasAppError::Storage`] — запись в базу не удалась.
    pub fn restore(
        &self,
        recovery_key: &RecoveryKey,
        links: &[Vec<u8>],
        now: Timestamp,
    ) -> Result<RestoreOutcome> {
        let restored = BackupChain::restore(recovery_key, links)?;

        let export = bundle_to_export(&restored.bundle, now);
        let applied = self.storage.import_from_backup(&export)?;

        // 🔐 Восстановление записывается в журнал безопасности.
        // Событие важное: с этого момента собеседники увидят смену
        // safety number, и человек должен иметь возможность
        // проверить, откуда она взялась.
        self.storage.log_security_event(
            "backup_restored",
            Some(&format!("links={}", links.len())),
            now,
        )?;

        // Цепочка после восстановления начинается заново: продолжать
        // чужую нельзя — устройство другое, и его данные разойдутся
        // с тем, что лежит в облаке.
        self.storage.clear_backup_chain_state()?;

        Ok(RestoreOutcome {
            applied,
            links: restored.applied,
            created_at: Timestamp::from_millis(restored.meta.created_at_millis),
            username: restored.bundle.username.clone(),
            // Всегда: приватный identity-ключ в копию не входит.
            identity_changed: true,
        })
    }

    /// Когда делалась последняя копия.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn last_backup_at(&self) -> Result<Option<Timestamp>> {
        Ok(self
            .storage
            .backup_chain_state()?
            .and_then(|state| state.last_backup_at))
    }

    /// Настроено ли резервное копирование.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn is_configured(&self) -> Result<bool> {
        Ok(self.storage.backup_chain_state()?.is_some())
    }

    /// Забывает цепочку — например, при смене recovery key.
    ///
    /// Следующая копия начнётся полным снимком под новым ключом.
    /// Старые файлы в облаке при этом остаются читаемыми **старым**
    /// ключом: перешифровать их отсюда невозможно, и удалить их —
    /// задача того, кто ими владеет.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn forget_chain(&self) -> Result<()> {
        self.storage.clear_backup_chain_state()
    }

    /// Уплотняет базу, если пришёл срок.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — уплотнение не удалось.
    pub fn maintain(&self, now: Timestamp) -> Result<bool> {
        self.storage.vacuum_if_due(now, VACUUM_INTERVAL_MILLIS)
    }

    /// Сколько файлов лежит в vault.
    ///
    /// Не требует открытого vault: число файлов показывается
    /// на закрытом экране как «в хранилище 3 файла». Имена — нет.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn vault_file_count(&self) -> Result<u32> {
        self.storage.vault_file_count()
    }

    /// Перечисляет файлы vault.
    ///
    /// # 🔐 Про доступ
    ///
    /// Метод не проверяет состояние vault сам: проверку делает
    /// вызывающий, у которого есть [`VaultGuard`](crate::vault::VaultGuard).
    /// Вызывать его на закрытом vault нельзя — список имён файлов
    /// говорит достаточно и без содержимого.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn vault_files(&self, limit: u32) -> Result<Vec<VaultFileRow>> {
        self.storage.list_vault_files(limit)
    }
}

/// Переводит соль из базы в массив нужной длины.
fn to_salt(raw: &[u8]) -> Result<[u8; gasapp_backup::kdf::SALT_LEN]> {
    raw.try_into().map_err(|_| GasAppError::Storage)
}

/// Переводит хеш из базы в массив нужной длины.
fn to_digest(raw: &[u8]) -> Result<[u8; gasapp_backup::archive::DIGEST_LEN]> {
    raw.try_into().map_err(|_| GasAppError::Storage)
}

/// Настройка с проверочным значением ключа цепочки копий.
const KEY_CHECK_SETTING: &str = "backup_key_check";

/// Запись проверочного значения: `соль:значение`, hex.
///
/// Соль — чтобы значение прежней цепочки (после смены ключа или
/// восстановления состояние сброшено, а запись осталась) не сверялось
/// с новой.
fn key_check_record(salt: &[u8], check: &[u8]) -> String {
    format!("{}:{}", crate::client::hex(salt), crate::client::hex(check))
}

/// Проверочное значение из записи — если оно этой цепочки.
fn parse_key_check_record(
    record: &str,
    salt: &[u8; gasapp_backup::kdf::SALT_LEN],
) -> Option<[u8; gasapp_backup::kdf::KEY_LEN]> {
    let (salt_hex, check_hex) = record.split_once(':')?;

    if crate::client::unhex(salt_hex).ok()?.as_slice() != salt.as_slice() {
        return None;
    }

    crate::client::unhex(check_hex).ok()?.try_into().ok()
}

/// Переводит выгрузку хранилища в записи бандла.
///
/// 🔐 Перевод механический и полный: каждое поле выгрузки имеет
/// ровно одно место в бандле. Обратное преобразование
/// ([`bundle_to_export`]) обязано быть его точной парой, иначе
/// восстановление потеряет данные молча.
fn export_to_bundle(export: &BackupExport, now: Timestamp) -> BackupBundle {
    BackupBundle {
        account_id: export.account_id.as_ref().map(|id| *id.as_bytes()),
        username: export.username.clone(),
        created_at_millis: now.as_millis(),
        messages: export.messages.iter().map(message_to_record).collect(),
        contacts: export.contacts.iter().map(contact_to_record).collect(),
        chats: export.chats.iter().map(chat_to_record).collect(),
        attachments: export
            .attachments
            .iter()
            .map(attachment_to_record)
            .collect(),
        settings: export
            .settings
            .iter()
            .map(|(key, value)| SettingRecord {
                key: key.clone(),
                value: *value,
            })
            .collect(),
        tombstones: export.tombstones.iter().map(|id| *id.as_bytes()).collect(),
        account_recovery: export
            .account_recovery
            .map(gasapp_backup::bundle::AccountRecoverySecret),
        contact_pq_hashes: export
            .contact_pq_hashes
            .iter()
            .map(|(account, hash)| gasapp_backup::bundle::ContactPqRecord {
                account_id: *account.as_bytes(),
                pq_identity_hash: *hash,
            })
            .collect(),
        channels: export.channels.as_ref().map(|channels| {
            channels
                .iter()
                .map(|channel| gasapp_backup::bundle::ChannelRecord {
                    channel_id: channel.channel_id,
                    secret: channel.secret,
                    verify_key: channel.verify_key,
                    signing_key: channel.signing_key,
                    title: channel.title.clone(),
                    muted: channel.muted,
                    sub_token: channel.sub_token,
                    joined_at_millis: channel.joined_at.as_millis(),
                    admin_labels: channel.admin_labels.clone(),
                })
                .collect()
        }),
    }
}

/// Переводит бандл обратно в форму, которую понимает хранилище.
fn bundle_to_export(bundle: &BackupBundle, now: Timestamp) -> BackupExport {
    BackupExport {
        account_id: bundle.account_id.map(uuid_to_account),
        username: bundle.username.clone(),
        messages: bundle.messages.iter().map(record_to_message).collect(),
        contacts: bundle.contacts.iter().map(record_to_contact).collect(),
        chats: bundle.chats.iter().map(record_to_chat).collect(),
        attachments: bundle
            .attachments
            .iter()
            .map(record_to_attachment)
            .collect(),
        settings: bundle
            .settings
            .iter()
            .map(|record| (record.key.clone(), record.value))
            .collect(),
        tombstones: bundle
            .tombstones
            .iter()
            .map(|raw| MessageId::from_uuid(uuid::Uuid::from_bytes(*raw)))
            .collect(),
        account_recovery: bundle.account_recovery.as_ref().map(|secret| secret.0),
        contact_pq_hashes: bundle
            .contact_pq_hashes
            .iter()
            .map(|record| (uuid_to_account(record.account_id), record.pq_identity_hash))
            .collect(),
        channels: bundle.channels.as_ref().map(|channels| {
            channels
                .iter()
                .map(|channel| gasapp_storage::channels::ChannelBackupRow {
                    channel_id: channel.channel_id,
                    secret: channel.secret,
                    verify_key: channel.verify_key,
                    signing_key: channel.signing_key,
                    title: channel.title.clone(),
                    muted: channel.muted,
                    sub_token: channel.sub_token,
                    joined_at: Timestamp::from_millis(channel.joined_at_millis),
                    admin_labels: channel.admin_labels.clone(),
                })
                .collect()
        }),
        watermark: now,
    }
}

fn message_to_record(message: &StoredMessage) -> MessageRecord {
    MessageRecord {
        id: *message.id.as_bytes(),
        chat_id: *message.chat_id.as_bytes(),
        sender_id: *message.sender_id.as_bytes(),
        timestamp_millis: message.timestamp.as_millis(),
        content: message.content.as_bytes().to_vec(),
        status: message.status.as_u8(),
        message_type: message.message_type,
        expires_at_millis: message.expires_at.map(|moment| moment.as_millis()),
    }
}

fn record_to_message(record: &MessageRecord) -> StoredMessage {
    StoredMessage {
        id: MessageId::from_uuid(uuid::Uuid::from_bytes(record.id)),
        chat_id: ChatId::from_uuid(uuid::Uuid::from_bytes(record.chat_id)),
        sender_id: uuid_to_account(record.sender_id),
        timestamp: Timestamp::from_millis(record.timestamp_millis),
        content: Ciphertext::new(record.content.clone()),
        status: MessageStatus::from_u8(record.status),
        message_type: record.message_type,
        expires_at: record.expires_at_millis.map(Timestamp::from_millis),
    }
}

fn contact_to_record(contact: &ContactRow) -> ContactRecord {
    ContactRecord {
        account_id: *contact.account_id.as_bytes(),
        identity_key: contact.identity_key.clone(),
        username: contact.username.clone(),
        chat_id: contact.chat_id.as_ref().map(|id| *id.as_bytes()),
        verified: contact.verified,
        added_at_millis: contact.added_at,
    }
}

fn record_to_contact(record: &ContactRecord) -> ContactRow {
    ContactRow {
        account_id: uuid_to_account(record.account_id),
        identity_key: record.identity_key.clone(),
        username: record.username.clone(),
        chat_id: record
            .chat_id
            .map(|raw| ChatId::from_uuid(uuid::Uuid::from_bytes(raw))),
        verified: record.verified,
        added_at: record.added_at_millis,
        // Замена ключа в копию не попадает (формат копии её не несёт):
        // после восстановления неоднозначность имени придётся снять
        // заново — это безопаснее, чем молча считать её снятой.
        replaced: false,
        // Источник ключа в копию не попадает: после восстановления
        // контакт, не сверенный вживую, подтверждается заново.
        confirmed_by_link: false,
        confirmed_by_kt: false,
    }
}

fn chat_to_record(chat: &ChatBackupRow) -> ChatRecord {
    ChatRecord {
        chat_id: *chat.chat_id.as_bytes(),
        last_activity_millis: chat.last_activity_millis,
        disappearing_timer_seconds: chat.disappearing_timer_seconds,
    }
}

fn record_to_chat(record: &ChatRecord) -> ChatBackupRow {
    ChatBackupRow {
        chat_id: ChatId::from_uuid(uuid::Uuid::from_bytes(record.chat_id)),
        last_activity_millis: record.last_activity_millis,
        disappearing_timer_seconds: record.disappearing_timer_seconds,
    }
}

fn attachment_to_record(attachment: &StoredAttachment) -> AttachmentRecord {
    AttachmentRecord {
        message_id: *attachment.message_id.as_bytes(),
        attachment_type: attachment.attachment_type,
        description: attachment.description.clone(),
        size: attachment.size,
        created_at_millis: attachment.created_at.as_millis(),
        descriptor: attachment.descriptor.clone(),
    }
}

fn record_to_attachment(record: &AttachmentRecord) -> StoredAttachment {
    StoredAttachment {
        message_id: MessageId::from_uuid(uuid::Uuid::from_bytes(record.message_id)),
        attachment_type: record.attachment_type,
        description: record.description.clone(),
        size: record.size,
        created_at: Timestamp::from_millis(record.created_at_millis),
        descriptor: record.descriptor.clone(),
    }
}

/// Собирает [`AccountId`] из шестнадцати байт.
fn uuid_to_account(raw: [u8; ID_LEN]) -> AccountId {
    AccountId::from_uuid(uuid::Uuid::from_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gasapp_protocol::keys::SessionState;
    use gasapp_storage::MessageStatus;
    use gasapp_types::Secret;
    use rand_core::OsRng;

    /// Опознавательная строка состояния храповика.
    const SESSION_CANARY: &str = "RATCHET-STATE-MUST-NEVER-LEAVE-THE-DEVICE";

    /// Опознавательная строка приватного identity-ключа.
    const IDENTITY_CANARY: &str = "PRIVATE-IDENTITY-MUST-NEVER-LEAVE-THE-DEVICE";

    /// Опознавательная строка содержимого сообщения.
    const MESSAGE_CANARY: &[u8] = b"ATTACK-AT-DAWN-CIPHERTEXT-CANARY";

    /// Дешёвые параметры растягивания для тестов.
    ///
    /// 256 МиБ × 4 прохода на каждый из полутора десятков тестов
    /// превратили бы прогон в минуты и потребовали бы гигабайтов
    /// памяти при параллельном запуске. Схема при этом проверяется
    /// та же: за то, что боевые параметры именно такие, отвечает
    /// тест `default_params_are_the_planned_ones` в `gasapp-backup`.
    fn cheap() -> KdfParams {
        KdfParams {
            memory_kib: gasapp_backup::kdf::MIN_MEMORY_KIB,
            iterations: gasapp_backup::kdf::MIN_ITERATIONS,
            parallelism: 1,
        }
    }

    /// Служба с дешёвыми параметрами.
    fn cheap_service(storage: &Storage) -> BackupService<'_> {
        BackupService::with_params(storage, cheap())
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_760_000_000_000)
    }

    fn later(offset: i64) -> Timestamp {
        Timestamp::from_millis(now().as_millis().saturating_add(offset))
    }

    /// Открывает пустое хранилище во временном каталоге.
    fn open_storage() -> (Storage, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("каталог");
        let path = directory
            .path()
            .join("gasapp.db")
            .to_string_lossy()
            .into_owned();
        let storage = Storage::new(&path, &[0x5Au8; 32]).expect("база");

        (storage, directory)
    }

    fn message(chat: ChatId, sender: AccountId, at: Timestamp) -> StoredMessage {
        StoredMessage {
            id: MessageId::generate(),
            chat_id: chat,
            sender_id: sender,
            timestamp: at,
            content: Ciphertext::new(MESSAGE_CANARY.to_vec()),
            status: MessageStatus::Sent,
            message_type: 0,
            expires_at: None,
        }
    }

    /// Наполняет хранилище так, как выглядит рабочее устройство.
    fn populate(storage: &Storage) -> (ChatId, AccountId, MessageId) {
        let chat = ChatId::generate();
        let contact = AccountId::generate();
        let stored = message(chat, contact, now());

        storage
            .set_account_id(&AccountId::generate(), now())
            .expect("аккаунт");
        storage
            .save_own_keys(
                IDENTITY_CANARY.as_bytes(),
                &[0x22; 32],
                &[0x33; 64],
                Some("device-1"),
                Some("alice"),
                now(),
            )
            .expect("ключи");
        storage
            .save_session(
                &chat,
                &SessionState::from_serialized(Secret::new(SESSION_CANARY.as_bytes().to_vec())),
                now(),
            )
            .expect("сессия");
        storage.save_message(&stored).expect("сообщение");
        storage
            .save_contact(&contact, &[0x11; 32], Some("bob"), Some(&chat), now())
            .expect("контакт");
        storage
            .set_contact_verified(&contact, true, now())
            .expect("верификация");
        storage
            .set_disappearing_timer(&chat, Some(3600))
            .expect("таймер");

        (chat, contact, stored.id)
    }

    /// 🧪 Задача M6: полный цикл backup → wipe → restore.
    ///
    /// «Чистое устройство» здесь — вторая база в другом каталоге,
    /// открытая другим ключом: у неё нет ни строки от первой.
    #[test]
    fn full_backup_wipe_restore_cycle() {
        let (source, _source_dir) = open_storage();
        let (chat, contact, message_id) = populate(&source);

        let recovery_key = RecoveryKey::generate(&mut OsRng);
        let outcome = cheap_service(&source)
            .create(&recovery_key, Some("Pixel 6a"), now(), &mut OsRng)
            .expect("копия");

        assert!(outcome.is_full, "первая копия обязана быть полным снимком");
        assert_eq!(outcome.generation, 0);

        // --- wipe: устройство утеряно, взято новое ---
        let (fresh, _fresh_dir) = open_storage();

        assert!(
            fresh.load_messages(&chat, 10).expect("чтение").is_empty(),
            "чистое устройство оказалось не чистым"
        );

        let restored = cheap_service(&fresh)
            .restore(&recovery_key, &[outcome.archive], later(60_000))
            .expect("восстановление");

        assert_eq!(restored.links, 1);
        assert!(restored.applied > 0);

        // Переписка вернулась.
        let messages = fresh.load_messages(&chat, 10).expect("чтение");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages.first().map(|row| row.id), Some(message_id));
        assert_eq!(
            messages.first().map(|row| row.content.as_bytes()),
            Some(MESSAGE_CANARY)
        );

        // Контакты и настройки вернулись вместе с верификацией.
        assert_eq!(fresh.list_contacts(10).expect("контакты").len(), 1);
        assert!(fresh.is_contact_verified(&contact).expect("верификация"));
        assert_eq!(
            fresh.get_disappearing_timer(&chat).expect("таймер"),
            Some(3600)
        );

        // 🔐 А ключи и сессии — нет (раздел 12.5).
        assert!(
            fresh.load_own_keys().expect("ключи").is_none(),
            "приватный identity-ключ восстановился — этого быть не должно"
        );
        assert!(
            fresh.load_session(&chat).expect("сессия").is_none(),
            "состояние храповика восстановилось — этого быть не должно"
        );
        assert!(
            restored.identity_changed,
            "восстановление обязано сообщить о смене identity"
        );
    }

    /// 🧪 Задача M6: без recovery key копия не расшифровывается.
    #[test]
    fn backup_does_not_open_without_the_recovery_key() {
        let (source, _source_dir) = open_storage();
        populate(&source);

        let right = RecoveryKey::generate(&mut OsRng);
        let outcome = cheap_service(&source)
            .create(&right, None, now(), &mut OsRng)
            .expect("копия");

        let (fresh, _fresh_dir) = open_storage();
        let wrong = RecoveryKey::generate(&mut OsRng);

        assert!(matches!(
            cheap_service(&fresh).restore(&wrong, &[outcome.archive], later(1_000)),
            Err(GasAppError::Crypto)
        ));
        assert!(
            fresh.list_contacts(10).expect("контакты").is_empty(),
            "неудачное восстановление всё-таки что-то записало"
        );
    }

    /// 🔐 В файле копии нет ни ratchet state, ни identity-ключа,
    /// ни открытого содержимого сообщения.
    #[test]
    fn archive_leaks_nothing_from_the_device() {
        let (source, _source_dir) = open_storage();
        populate(&source);

        let recovery_key = RecoveryKey::generate(&mut OsRng);
        let outcome = cheap_service(&source)
            .create(&recovery_key, Some("Pixel 6a"), now(), &mut OsRng)
            .expect("копия");

        for canary in [
            SESSION_CANARY.as_bytes(),
            IDENTITY_CANARY.as_bytes(),
            MESSAGE_CANARY,
            b"bob".as_slice(),
            b"alice".as_slice(),
            b"Pixel 6a".as_slice(),
        ] {
            assert!(
                !outcome
                    .archive
                    .windows(canary.len())
                    .any(|window| window == canary),
                "в файле копии видно то, чего там быть не должно: {}",
                String::from_utf8_lossy(canary)
            );
        }
    }

    /// Вторая копия — инкремент, и он несёт только новое.
    #[test]
    fn second_backup_is_an_increment() {
        let (storage, _dir) = open_storage();
        let (chat, contact, _) = populate(&storage);

        let recovery_key = RecoveryKey::generate(&mut OsRng);
        let service = cheap_service(&storage);

        let full = service
            .create(&recovery_key, None, now(), &mut OsRng)
            .expect("снимок");
        assert!(full.is_full);

        storage
            .save_message(&message(chat, contact, later(2_000)))
            .expect("новое сообщение");

        let increment = service
            .create(&recovery_key, None, later(3_000), &mut OsRng)
            .expect("инкремент");

        assert!(!increment.is_full, "вторая копия обязана быть инкрементом");
        assert_eq!(increment.generation, 1);

        // Восстановление цепочки даёт оба сообщения.
        let (fresh, _fresh_dir) = open_storage();
        cheap_service(&fresh)
            .restore(
                &recovery_key,
                &[full.archive, increment.archive],
                later(4_000),
            )
            .expect("восстановление");

        assert_eq!(fresh.load_messages(&chat, 10).expect("чтение").len(), 2);
    }

    /// 🔐 Чужой ключ не продолжает цепочку.
    ///
    /// Прежде ключ при продолжении не сверялся: годный по контрольной
    /// сумме, но другой ключ дописывал инкремент, который настоящим
    /// ключом не открывается, — а состояние цепочки сдвигалось, и это
    /// звено из копий пропадало молча.
    #[test]
    fn a_different_key_cannot_continue_the_chain() {
        let (storage, _dir) = open_storage();
        let (chat, contact, _) = populate(&storage);

        let owner = RecoveryKey::generate(&mut OsRng);
        let stranger = RecoveryKey::generate(&mut OsRng);
        let service = cheap_service(&storage);

        let full = service
            .create(&owner, None, now(), &mut OsRng)
            .expect("снимок");

        storage
            .save_message(&message(chat, contact, later(2_000)))
            .expect("новое сообщение");

        assert!(
            matches!(
                service.create(&stranger, None, later(3_000), &mut OsRng),
                Err(GasAppError::Crypto)
            ),
            "чужой ключ продолжил цепочку"
        );

        // Состояние цепочки не сдвинулось: инкремент верным ключом
        // несёт новое сообщение, и цепочка восстанавливается целиком.
        let increment = service
            .create(&owner, None, later(4_000), &mut OsRng)
            .expect("инкремент");
        assert_eq!(increment.generation, 1);

        let (fresh, _fresh_dir) = open_storage();
        cheap_service(&fresh)
            .restore(&owner, &[full.archive, increment.archive], later(5_000))
            .expect("восстановление");
        assert_eq!(fresh.load_messages(&chat, 10).expect("чтение").len(), 2);
    }

    /// Цепочка, заведённая до проверочного значения, начинается заново
    /// полным снимком: сверить ключ не с чем, а снимок под введённым
    /// ключом им же и открывается.
    #[test]
    fn a_chain_without_a_key_check_restarts_with_a_full_snapshot() {
        let (storage, _dir) = open_storage();
        populate(&storage);

        let recovery_key = RecoveryKey::generate(&mut OsRng);
        let service = cheap_service(&storage);

        service
            .create(&recovery_key, None, now(), &mut OsRng)
            .expect("снимок");
        // Как у базы прежней версии: состояния цепочки есть, значения нет.
        storage
            .set_setting_text(KEY_CHECK_SETTING, "")
            .expect("запись");

        let next = service
            .create(&recovery_key, None, later(1_000), &mut OsRng)
            .expect("копия");

        assert!(
            next.is_full,
            "без проверочного значения — только полный снимок"
        );
    }

    /// 🔐 Исчезнувшее сообщение не возвращается из копии.
    ///
    /// Полный цикл: сообщение попало в снимок, истекло по таймеру,
    /// инкремент унёс надгробие — и восстановление его не воскресило.
    #[test]
    fn expired_message_does_not_come_back_from_the_backup() {
        let (storage, _dir) = open_storage();
        let chat = ChatId::generate();
        let sender = AccountId::generate();

        let mut vanishing = message(chat, sender, now());
        vanishing.expires_at = Some(later(1_000));
        let kept = message(chat, sender, now());

        storage.save_message(&vanishing).expect("сообщение");
        storage.save_message(&kept).expect("сообщение");

        let recovery_key = RecoveryKey::generate(&mut OsRng);
        let service = cheap_service(&storage);

        let full = service
            .create(&recovery_key, None, now(), &mut OsRng)
            .expect("снимок");

        // Сообщение истекает и вычищается.
        assert_eq!(storage.purge_expired(later(2_000)).expect("чистка"), 1);

        let increment = service
            .create(&recovery_key, None, later(3_000), &mut OsRng)
            .expect("инкремент");

        let (fresh, _fresh_dir) = open_storage();
        cheap_service(&fresh)
            .restore(
                &recovery_key,
                &[full.archive, increment.archive],
                later(4_000),
            )
            .expect("восстановление");

        let messages = fresh.load_messages(&chat, 10).expect("чтение");

        assert_eq!(
            messages.len(),
            1,
            "исчезнувшее сообщение вернулось из резервной копии"
        );
        assert_eq!(messages.first().map(|row| row.id), Some(kept.id));
    }

    /// 🔐 Разорванная цепочка не восстанавливается наполовину.
    #[test]
    fn broken_chain_restores_nothing() {
        let (storage, _dir) = open_storage();
        let (chat, contact, _) = populate(&storage);

        let recovery_key = RecoveryKey::generate(&mut OsRng);
        let service = cheap_service(&storage);

        let full = service
            .create(&recovery_key, None, now(), &mut OsRng)
            .expect("снимок");

        storage
            .save_message(&message(chat, contact, later(2_000)))
            .expect("сообщение");
        let _lost = service
            .create(&recovery_key, None, later(3_000), &mut OsRng)
            .expect("инкремент");

        storage
            .save_message(&message(chat, contact, later(4_000)))
            .expect("сообщение");
        let third = service
            .create(&recovery_key, None, later(5_000), &mut OsRng)
            .expect("инкремент");

        // Второе звено потеряно.
        let (fresh, _fresh_dir) = open_storage();
        let outcome = cheap_service(&fresh).restore(
            &recovery_key,
            &[full.archive, third.archive],
            later(6_000),
        );

        assert!(matches!(outcome, Err(GasAppError::Malformed)));
        assert!(
            fresh.load_messages(&chat, 10).expect("чтение").is_empty(),
            "разорванная цепочка всё-таки записала часть данных"
        );
    }

    /// Метаданные копии читаются без восстановления.
    #[test]
    fn inspect_reads_meta_without_restoring() {
        let (storage, _dir) = open_storage();
        populate(&storage);

        let recovery_key = RecoveryKey::generate(&mut OsRng);
        let outcome = cheap_service(&storage)
            .create(&recovery_key, Some("Pixel 6a"), now(), &mut OsRng)
            .expect("копия");

        let meta = BackupService::inspect(&recovery_key, &outcome.archive).expect("метаданные");

        assert_eq!(meta.created_at_millis, now().as_millis());
        assert_eq!(meta.message_count, 1);
        assert_eq!(meta.device_label.as_deref(), Some("Pixel 6a"));
    }

    /// Чужой ключ метаданных тоже не открывает.
    #[test]
    fn inspect_refuses_a_foreign_key() {
        let (storage, _dir) = open_storage();
        populate(&storage);

        let outcome = cheap_service(&storage)
            .create(&RecoveryKey::generate(&mut OsRng), None, now(), &mut OsRng)
            .expect("копия");

        assert!(
            BackupService::inspect(&RecoveryKey::generate(&mut OsRng), &outcome.archive).is_err()
        );
    }

    /// Состояние цепочки видно через службу.
    #[test]
    fn service_reports_chain_state() {
        let (storage, _dir) = open_storage();
        populate(&storage);
        let service = cheap_service(&storage);

        assert!(!service.is_configured().expect("состояние"));
        assert!(service.last_backup_at().expect("время").is_none());

        service
            .create(&RecoveryKey::generate(&mut OsRng), None, now(), &mut OsRng)
            .expect("копия");

        assert!(service.is_configured().expect("состояние"));
        assert_eq!(service.last_backup_at().expect("время"), Some(now()));

        service.forget_chain().expect("сброс");

        assert!(!service.is_configured().expect("состояние"));
    }

    /// Смена recovery key начинает цепочку заново.
    #[test]
    fn new_recovery_key_starts_a_fresh_chain() {
        let (storage, _dir) = open_storage();
        populate(&storage);
        let service = cheap_service(&storage);

        service
            .create(&RecoveryKey::generate(&mut OsRng), None, now(), &mut OsRng)
            .expect("копия");
        service.forget_chain().expect("сброс");

        let fresh_key = RecoveryKey::generate(&mut OsRng);
        let outcome = service
            .create(&fresh_key, None, later(1_000), &mut OsRng)
            .expect("копия");

        assert!(outcome.is_full, "после смены ключа нужен полный снимок");
        assert_eq!(outcome.generation, 0);
    }

    /// После восстановления цепочка не продолжает чужую.
    #[test]
    fn restore_clears_the_chain_state() {
        let (source, _source_dir) = open_storage();
        populate(&source);

        let recovery_key = RecoveryKey::generate(&mut OsRng);
        let outcome = cheap_service(&source)
            .create(&recovery_key, None, now(), &mut OsRng)
            .expect("копия");

        let (fresh, _fresh_dir) = open_storage();
        let service = cheap_service(&fresh);
        service
            .restore(&recovery_key, &[outcome.archive], later(1_000))
            .expect("восстановление");

        assert!(
            !service.is_configured().expect("состояние"),
            "восстановленное устройство продолжило бы чужую цепочку"
        );
    }

    /// Восстановление попадает в журнал безопасности.
    #[test]
    fn restore_is_written_to_the_security_log() {
        let (source, _source_dir) = open_storage();
        populate(&source);

        let recovery_key = RecoveryKey::generate(&mut OsRng);
        let outcome = cheap_service(&source)
            .create(&recovery_key, None, now(), &mut OsRng)
            .expect("копия");

        let (fresh, _fresh_dir) = open_storage();
        cheap_service(&fresh)
            .restore(&recovery_key, &[outcome.archive], later(1_000))
            .expect("восстановление");

        let events = fresh.recent_security_events(10).expect("журнал");

        assert!(
            events.iter().any(|event| event.0 == "backup_restored"),
            "восстановление не попало в журнал безопасности"
        );
    }

    /// Обслуживание базы запускается по расписанию.
    #[test]
    fn maintenance_runs_on_schedule() {
        let (storage, _dir) = open_storage();
        let service = cheap_service(&storage);

        assert!(!service.maintain(now()).expect("обслуживание"));
        assert!(!service
            .maintain(later(VACUUM_INTERVAL_MILLIS - 1))
            .expect("обслуживание"));
        assert!(service
            .maintain(later(VACUUM_INTERVAL_MILLIS))
            .expect("обслуживание"));
    }
}
