// SPDX-License-Identifier: Apache-2.0

//! Каналы: создать, вести, читать.
//!
//! Криптография — в `gasapp_protocol::channel`, там же честный список
//! того, чего канал не даёт. Здесь — связка с сервером и базой:
//!
//! * **создать** канал может только аккаунт с премиумом; право
//!   проверяет сервер, а премиум выдаёт оператор вручную;
//! * **читать** может любой, у кого есть ссылка: записи забираются без
//!   подписи запроса, и сервер не знает, кто читает;
//! * **подписка** — строка в локальной базе. На сервере её нет.

use gasapp_net::api::{CreateChannelRequest, PublishPostRequest, UpdateChannelMetaRequest};
use gasapp_net::client::Transport;
use gasapp_protocol::channel::{
    self, ChannelAccess, ChannelAuthor, ChannelId, ChannelMeta, ChannelPost,
};
use gasapp_storage::channels::{StoredChannel, StoredPost};
use gasapp_types::{GasAppError, PrivateKeyBytes, PublicKeyBytes, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::{hex, unhex, Client, DeviceSigner};

/// Сколько записей запрашивается у сервера за один раз.
const PAGE: u32 = 100;

/// Сколько страниц забирается за одну синхронизацию канала.
///
/// Предел нужен, чтобы канал с десятками тысяч записей не превращал
/// открытие экрана в минуты загрузки через Tor: остальное доедет при
/// следующей синхронизации.
const MAX_PAGES_PER_SYNC: u32 = 5;

/// Канал в том виде, в каком его показывает интерфейс.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    /// Идентификатор, UUID.
    pub channel_id: String,
    /// Название.
    pub title: String,
    /// Описание.
    pub description: String,
    /// Свой ли это канал: можно ли в него писать.
    pub owned: bool,
    /// Сколько записей ещё не прочитано.
    pub unread: u64,
    /// Текст последней записи — для списка.
    pub last_post: Option<String>,
    /// Время последней записи по часам автора.
    pub last_post_at: Option<Timestamp>,
}

/// Запись канала для интерфейса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelEntry {
    /// Номер записи.
    pub seq: u64,
    /// Текст.
    pub text: String,
    /// Время публикации по часам автора.
    pub created_at: Timestamp,
}

fn access_of(stored: &StoredChannel) -> ChannelAccess {
    ChannelAccess {
        channel_id: stored.channel_id,
        secret: stored.secret,
        verify_key: PublicKeyBytes::new(stored.verify_key),
    }
}

fn parse_id(channel_id: &str) -> Result<ChannelId> {
    channel::parse_channel_id(channel_id)
}

impl<T: Transport> Client<T> {
    /// Спрашивает сервер, есть ли у аккаунта премиум.
    ///
    /// Ответ нужен интерфейсу, чтобы показать «Создать канал». Права он
    /// не даёт: сервер проверяет премиум при создании сам.
    ///
    /// # Errors
    ///
    /// [`GasAppError::SessionNotFound`] — аккаунт не зарегистрирован;
    /// [`GasAppError::Network`] — сервер недоступен.
    pub fn refresh_premium(&self, now: Timestamp) -> Result<bool> {
        let (device_id, identity) = self.own_device()?;
        let status = self
            .api
            .account_status(&device_id, &DeviceSigner::new(&identity, now))?;

        // Последний известный ответ сохраняется: без сети интерфейс
        // показывает то, что было, а не прячет кнопку.
        self.set_setting_bool(PREMIUM_SETTING, status.premium)?;

        Ok(status.premium)
    }

    /// Последний известный ответ сервера о премиуме — без сети.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn premium_cached(&self) -> Result<bool> {
        self.setting_bool(PREMIUM_SETTING, false)
    }

    /// Создаёт канал. Только для аккаунта с премиумом.
    ///
    /// Ключи канала сохраняются **до** запроса к серверу: канал,
    /// созданный на сервере, но не записанный здесь, остался бы без
    /// автора навсегда — ключ подписи есть только на этом устройстве.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — у аккаунта нет премиума;
    /// * [`GasAppError::Malformed`] — название пустое либо слишком длинное;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn create_channel<R: RngCore + CryptoRng>(
        &self,
        title: &str,
        description: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Channel> {
        let title = title.trim();
        let description = description.trim();
        channel::validate_meta(title, description)?;

        let (device_id, identity) = self.own_device()?;
        let created = channel::create(rng);
        let signing_key = *created.signing_key.expose_secret();

        let meta = ChannelMeta {
            title: title.to_owned(),
            description: description.to_owned(),
            updated_at_millis: now.as_millis(),
        };
        let sealed_meta =
            ChannelAuthor::new(&created.access, created.signing_key)?.seal_meta(&meta, rng)?;

        let stored = StoredChannel {
            channel_id: created.access.channel_id,
            secret: created.access.secret,
            verify_key: *created.access.verify_key.as_bytes(),
            signing_key: Some(signing_key),
            title: meta.title,
            description: meta.description,
            meta_updated_at: meta.updated_at_millis,
            last_seq: 0,
            last_read_seq: 0,
            joined_at: now,
        };
        self.storage.insert_channel(&stored)?;

        let request = CreateChannelRequest {
            channel_id: created.access.channel_uuid(),
            verify_key: hex(created.access.verify_key.as_bytes()),
            meta: hex(&sealed_meta),
        };

        if let Err(error) =
            self.api
                .create_channel(&device_id, &request, &DeviceSigner::new(&identity, now))
        {
            // Сервер канал не принял — локальная заготовка не нужна.
            // При сбое сети она тоже убирается: человек повторит
            // создание, и канал получит новые ключи.
            self.storage.delete_channel(&stored.channel_id)?;

            if matches!(error, GasAppError::Forbidden) {
                self.set_setting_bool(PREMIUM_SETTING, false)?;
            }

            return Err(error);
        }

        self.present(&stored)
    }

    /// Добавляет канал по ссылке-приглашению и забирает его записи.
    ///
    /// 🔐 Ключ подписи автора берётся **из ссылки**, а не с сервера:
    /// сервер, назвавший другой ключ, отвергается. Иначе он подменил бы
    /// автора при первом же открытии канала.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — не ссылка на канал;
    /// * [`GasAppError::SessionNotFound`] — канала нет (удалён);
    /// * [`GasAppError::InvalidSignature`] — сервер отдаёт канал с другим
    ///   ключом автора либо описание подписано не автором;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn join_channel(&self, link: &str, now: Timestamp) -> Result<Channel> {
        let access = ChannelAccess::parse(link)?;

        if let Some(known) = self.storage.channel(&access.channel_id)? {
            // Канал уже есть — та же ссылка открывает его, а не заводит
            // второй раз.
            return self.present(&known);
        }

        let info = self.api.channel_info(&access.channel_uuid())?;

        if unhex(&info.verify_key)? != access.verify_key.as_bytes() {
            return Err(GasAppError::InvalidSignature);
        }

        let meta = access.open_meta(&unhex(&info.meta)?)?;

        let stored = StoredChannel {
            channel_id: access.channel_id,
            secret: access.secret,
            verify_key: *access.verify_key.as_bytes(),
            signing_key: None,
            title: meta.title,
            description: meta.description,
            meta_updated_at: meta.updated_at_millis,
            last_seq: 0,
            last_read_seq: 0,
            joined_at: now,
        };
        self.storage.insert_channel(&stored)?;

        // Записи — сразу, но их сбой подписке не мешает: канал добавлен,
        // остальное доедет при следующей синхронизации.
        let _ = self.sync_channel(&access.channel_uuid());

        self.present(&stored)
    }

    /// Каналы на этом устройстве — без сети.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn channels(&self) -> Result<Vec<Channel>> {
        self.storage
            .channels()?
            .iter()
            .map(|stored| self.present(stored))
            .collect()
    }

    /// Ссылка-приглашение канала — чтобы поделиться им.
    ///
    /// 🔐 Ссылка и есть доступ: кто её получил, читает весь канал.
    ///
    /// # Errors
    ///
    /// [`GasAppError::SessionNotFound`] — канала нет на устройстве.
    pub fn channel_link(&self, channel_id: &str) -> Result<String> {
        Ok(access_of(&self.stored_channel(channel_id)?).to_uri())
    }

    /// Забирает новые записи и описание канала с сервера.
    ///
    /// Возвращает число новых записей. Запись, не прошедшая проверку
    /// (подпись не автора, чужой номер), пропускается и не сохраняется.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет на устройстве
    ///   либо он удалён с сервера;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn sync_channel(&self, channel_id: &str) -> Result<u32> {
        let stored = self.stored_channel(channel_id)?;
        let access = access_of(&stored);
        let uuid = access.channel_uuid();

        let info = self.api.channel_info(&uuid)?;

        // 🔐 Канал с другим ключом автора — не тот канал.
        if unhex(&info.verify_key)? != stored.verify_key {
            return Err(GasAppError::InvalidSignature);
        }

        // Описание: принимается только подписанное автором и не старше
        // известного (второе проверяет хранилище).
        if let Ok(meta) = access.open_meta(&unhex(&info.meta)?) {
            self.storage.update_channel_meta(
                &stored.channel_id,
                &meta.title,
                &meta.description,
                meta.updated_at_millis,
            )?;
        }

        let mut after = stored.last_seq;
        let mut fresh = 0u32;

        for _ in 0..MAX_PAGES_PER_SYNC {
            let page = self.api.channel_posts(&uuid, after, PAGE)?;

            if page.is_empty() {
                break;
            }

            let full = u32::try_from(page.len()).is_ok_and(|len| len >= PAGE);

            for item in page {
                // Номера обязаны расти: сервер, отдающий старое, не
                // должен зациклить синхронизацию.
                if item.seq <= after {
                    return Ok(fresh);
                }
                after = item.seq;

                let opened = unhex(&item.body).and_then(|body| access.open_post(&body, item.seq));

                match opened {
                    Ok(post) => {
                        self.storage.insert_channel_post(
                            &stored.channel_id,
                            &StoredPost {
                                seq: item.seq,
                                text: post.text,
                                created_at: Timestamp::from_millis(post.created_at_millis),
                            },
                        )?;
                        fresh = fresh.saturating_add(1);
                    }
                    // Не от автора или не на своём месте — пропустить,
                    // но не запрашивать снова при каждой синхронизации.
                    Err(_) => self
                        .storage
                        .skip_channel_seq(&stored.channel_id, item.seq)?,
                }
            }

            if !full {
                break;
            }
        }

        // Свой канал прочитан автором по определению.
        if stored.signing_key.is_some() {
            self.storage.mark_channel_read(&stored.channel_id, after)?;
        }

        Ok(fresh)
    }

    /// Синхронизирует все каналы; возвращает число новых записей.
    ///
    /// Сбой одного канала (удалён, сеть оборвалась) остальным не мешает.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn sync_channels(&self) -> Result<u32> {
        let mut fresh = 0u32;

        for stored in self.storage.channels()? {
            let uuid = channel::format_uuid(&stored.channel_id);

            if let Ok(count) = self.sync_channel(&uuid) {
                fresh = fresh.saturating_add(count);
            }
        }

        Ok(fresh)
    }

    /// Последние записи канала — без сети, от старых к новым.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — идентификатор не UUID;
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn channel_posts(&self, channel_id: &str, limit: u32) -> Result<Vec<ChannelEntry>> {
        Ok(self
            .storage
            .channel_posts(&parse_id(channel_id)?, limit)?
            .into_iter()
            .map(|post| ChannelEntry {
                seq: post.seq,
                text: post.text,
                created_at: post.created_at,
            })
            .collect())
    }

    /// Отмечает канал прочитанным до последней сохранённой записи.
    ///
    /// # Errors
    ///
    /// [`GasAppError::SessionNotFound`] — канала нет на устройстве.
    pub fn mark_channel_read(&self, channel_id: &str) -> Result<()> {
        let stored = self.stored_channel(channel_id)?;

        self.storage
            .mark_channel_read(&stored.channel_id, stored.last_seq)
    }

    /// Публикует запись в своём канале.
    ///
    /// Номер записи автор назначает сам — следующий за последним на
    /// сервере — и кладёт внутрь шифротекста: читатели сверяют его
    /// с номером сервера (см. `gasapp_protocol::channel`).
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал чужой: ключа подписи нет;
    /// * [`GasAppError::Malformed`] — текст пустой либо слишком длинный;
    /// * [`GasAppError::InvalidSignature`] — сервер поставил запись под
    ///   другим номером (в канал одновременно писали с другого места);
    ///   читатели такую запись не примут;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn publish_channel_post<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        text: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<ChannelEntry> {
        let stored = self.stored_channel(channel_id)?;
        let signing_key = stored.signing_key.ok_or(GasAppError::Forbidden)?;
        let access = access_of(&stored);
        let uuid = access.channel_uuid();
        let (device_id, identity) = self.own_device()?;

        let text = text.trim();
        let number = self
            .api
            .channel_info(&uuid)?
            .last_seq
            .checked_add(1)
            .ok_or(GasAppError::Malformed)?;

        let sealed = ChannelAuthor::new(&access, PrivateKeyBytes::new(signing_key))?.seal_post(
            &ChannelPost {
                number,
                created_at_millis: now.as_millis(),
                text: text.to_owned(),
            },
            rng,
        )?;

        let published = self.api.publish_channel_post(
            &device_id,
            &uuid,
            &PublishPostRequest { body: hex(&sealed) },
            &DeviceSigner::new(&identity, now),
        )?;

        if published.seq != number {
            return Err(GasAppError::InvalidSignature);
        }

        self.storage.insert_channel_post(
            &stored.channel_id,
            &StoredPost {
                seq: number,
                text: text.to_owned(),
                created_at: now,
            },
        )?;
        self.storage.mark_channel_read(&stored.channel_id, number)?;

        Ok(ChannelEntry {
            seq: number,
            text: text.to_owned(),
            created_at: now,
        })
    }

    /// Меняет название и описание своего канала.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал чужой;
    /// * [`GasAppError::Malformed`] — название пустое либо слишком длинное;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn update_channel<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        title: &str,
        description: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Channel> {
        let stored = self.stored_channel(channel_id)?;
        let signing_key = stored.signing_key.ok_or(GasAppError::Forbidden)?;
        let access = access_of(&stored);
        let (device_id, identity) = self.own_device()?;

        // Время описания обязано расти: читатели не принимают описание
        // старше известного, а часы телефона могли уйти назад.
        let meta = ChannelMeta {
            title: title.trim().to_owned(),
            description: description.trim().to_owned(),
            updated_at_millis: now
                .as_millis()
                .max(stored.meta_updated_at.saturating_add(1)),
        };
        let sealed = ChannelAuthor::new(&access, PrivateKeyBytes::new(signing_key))?
            .seal_meta(&meta, rng)?;

        self.api.update_channel_meta(
            &device_id,
            &access.channel_uuid(),
            &UpdateChannelMetaRequest { meta: hex(&sealed) },
            &DeviceSigner::new(&identity, now),
        )?;

        self.storage.update_channel_meta(
            &stored.channel_id,
            &meta.title,
            &meta.description,
            meta.updated_at_millis,
        )?;

        self.present(&self.stored_channel(channel_id)?)
    }

    /// Убирает канал с устройства; свой — удаляет и с сервера.
    ///
    /// Чужой канал просто перестаёт читаться: сервер о подписке не знал
    /// и об отписке не узнаёт. Свой удаляется с сервера вместе со всеми
    /// записями — у читателей останется то, что они уже загрузили.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — свой канал не удалось удалить
    /// с сервера; на устройстве он при этом остаётся, чтобы не потерять
    /// ключ подписи от канала, который всё ещё существует.
    pub fn leave_channel(&self, channel_id: &str, now: Timestamp) -> Result<()> {
        let stored = self.stored_channel(channel_id)?;

        if stored.signing_key.is_some() {
            let (device_id, identity) = self.own_device()?;
            let removed = self.api.delete_channel(
                &device_id,
                &channel::format_uuid(&stored.channel_id),
                &DeviceSigner::new(&identity, now),
            );

            // «Не найден» — канал уже удалён с сервера: это и есть цель.
            match removed {
                Ok(()) | Err(GasAppError::SessionNotFound) => {}
                Err(error) => return Err(error),
            }
        }

        self.storage.delete_channel(&stored.channel_id)
    }

    fn stored_channel(&self, channel_id: &str) -> Result<StoredChannel> {
        self.storage
            .channel(&parse_id(channel_id)?)?
            .ok_or(GasAppError::SessionNotFound)
    }

    /// Идентификатор своего устройства и ключ для подписи запросов.
    fn own_device(&self) -> Result<(String, gasapp_protocol::keys::IdentityKeyPair)> {
        let device_id = self
            .storage
            .load_own_keys()?
            .and_then(|keys| keys.device_id)
            .ok_or(GasAppError::SessionNotFound)?;
        let (identity, _) = self.load_identity()?;

        Ok((device_id, identity))
    }

    fn present(&self, stored: &StoredChannel) -> Result<Channel> {
        let last = self.storage.channel_posts(&stored.channel_id, 1)?.pop();

        Ok(Channel {
            channel_id: channel::format_uuid(&stored.channel_id),
            title: stored.title.clone(),
            description: stored.description.clone(),
            owned: stored.signing_key.is_some(),
            unread: self
                .storage
                .count_channel_posts_after(&stored.channel_id, stored.last_read_seq)?,
            last_post_at: last.as_ref().map(|post| post.created_at),
            last_post: last.map(|post| post.text),
        })
    }
}

/// Настройка с последним известным ответом сервера о премиуме.
const PREMIUM_SETTING: &str = "account.premium";
