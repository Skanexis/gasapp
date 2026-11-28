// SPDX-License-Identifier: Apache-2.0

//! Связывание и отключение своих устройств (`docs/protocol/MULTI-DEVICE.md`, §3, §5).
//!
//! **Новое устройство** ([`Client::start_device_link`] →
//! [`Client::poll_device_link`] → [`Client::finish_device_link`]):
//! ключи этого устройства, запрос в ящик сервера, QR; затем грант от
//! основного, сверка шести цифр человеком, регистрация устройства и
//! публикация его предключей.
//!
//! **Основное** ([`Client::prepare_device_link`] →
//! [`Client::approve_device_link`]): QR, запрос из ящика с проверкой
//! хеша, новый список устройств с подписью ключа аккаунта, грант; шесть
//! цифр — до отправки, чтобы человек сверил их с новым экраном.
//!
//! 🔐 Закрытый ключ аккаунта не покидает основное устройство; подключать
//! и отключать устройства может только оно.

use std::sync::Mutex;

use gasapp_net::api::{
    LinkCompleteBody, LinkGrantBody, LinkRequestBody, PublishKeysRequest, UnlinkBody,
};
use gasapp_net::client::Transport;
use gasapp_protocol::device_link::{self, LinkCode, LinkGrant, LinkSecrets, OpenedGrant};
use gasapp_protocol::device_list::{
    self, check_succession, DeviceEntry, DeviceList, SignedDeviceList, MAX_DEVICES,
};
use gasapp_protocol::keys::IdentityKeyPair;
use gasapp_protocol::pq_identity::PqIdentityKeyPair;
use gasapp_protocol::prekeys;
use gasapp_storage::devices::{KnownDevice, StoredDeviceList};
use gasapp_types::{
    AccountId, DeviceId, GasAppError, PrivateKeyBytes, PublicKeyBytes, Result, Timestamp,
};
use rand_core::{CryptoRng, RngCore};

use gasapp_protocol::content::ACCESS_KEY_LEN;

use super::{hex, parse_uuid, publish_request, unhex, Account, Client, DeviceSigner};

/// Что подписывает новое устройство, завершая связывание (как сервер).
const COMPLETE_DOMAIN: &[u8] = b"GASAPP_LINK_COMPLETE_v1";

/// Связывание на новом устройстве — между QR и регистрацией.
pub(crate) struct PendingLink {
    secrets: LinkSecrets,
    identity: IdentityKeyPair,
    pq: PqIdentityKeyPair,
    device_id: DeviceId,
    opened: Option<OpenedGrant>,
    /// Сервер уже знает устройство, база — ключи: осталось дослать ключи.
    completed: Option<CompletedLink>,
}

/// Первая фаза входа сделана ([`Client::finish_device_link`]).
pub(crate) struct CompletedLink {
    account: Account,
    request: PublishKeysRequest,
}

/// Грант на основном — между сверкой цифр и отправкой.
pub(crate) struct PreparedLink {
    nonce: String,
    /// Новое устройство — ему после входа уходит история (этап 4б).
    device_id: String,
    /// QR, по которому подготовлен грант: срок проверяется и при
    /// «Подключить» — новое устройство к тому времени могло уйти на
    /// новый QR, и грант в старый ящик никто бы не забрал.
    code: LinkCode,
    body: LinkGrantBody,
}

/// Как часто основное переподписывает свой список (неделя): собеседники
/// не верят списку старше [`super::devices::MAX_LIST_AGE_MILLIS`].
const LIST_RESIGN_MILLIS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Состояние связывания в клиенте — только в памяти.
#[derive(Default)]
pub(crate) struct LinkState {
    pending: Mutex<Option<PendingLink>>,
    prepared: Mutex<Option<PreparedLink>>,
    /// Свои другие устройства и когда узнаны (`client::devices`): в
    /// памяти, чтобы не спрашивать discovery своего имени при отправке.
    pub(crate) own_targets: Mutex<Option<(i64, Vec<super::devices::Target>)>>,
}

/// Грант пришёл: что показать на новом устройстве.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkOffer {
    /// Шесть цифр — должны совпасть с цифрами на основном устройстве.
    pub code: String,
    /// Имя аккаунта, к которому подключаемся.
    pub username: String,
}

/// Своё устройство — для экрана «Устройства».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnDevice {
    /// Идентификатор устройства.
    pub device_id: String,
    /// Это устройство.
    pub this_device: bool,
    /// Основное (его ключ — ключ аккаунта).
    pub primary: bool,
}

fn device_bytes(text: &str) -> Result<[u8; 16]> {
    Ok(*parse_uuid(text)?.as_bytes())
}

/// Сколько бит работы за ящик связывания самое большее — как верх
/// лестницы узла (`pow::link_difficulty`); решатель ищет до 2^28 попыток.
/// Больше узел не потребует, а подменённый — не займёт телефон надолго.
const MAX_LINK_DIFFICULTY: u32 = 27;

impl<T: Transport> Client<T> {
    /// Новое устройство: заводит свои ключи и запрос, открывает ящик и
    /// возвращает ссылку для QR (живёт 60 секунд).
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — устройство уже зарегистрировано;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn start_device_link<R: RngCore + CryptoRng>(
        &self,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<String> {
        if self.storage.load_own_keys()?.is_some() {
            return Err(GasAppError::Malformed);
        }
        let identity = prekeys::generate_identity(rng)?;
        let pq = PqIdentityKeyPair::generate(rng);
        let device_id = DeviceId::generate();
        let secrets = device_link::new_request(
            *device_id.as_uuid().as_bytes(),
            &identity,
            &pq,
            now.as_millis(),
            rng,
        );
        let nonce = uuid::Uuid::from_bytes(secrets.request().nonce).to_string();
        let request = secrets.request().encode();
        // Работа за ящик: открыть его можно без входа (см. `pow::LINK_DIFFICULTY`).
        // Цена растёт, когда ящики забивают (аудит 2026-11-28): узел
        // называет текущую. Не ответил — базовая; больше 28 бит не
        // считаем — иначе узел мог бы занять телефон работой надолго.
        let difficulty = self
            .api
            .link_challenge()
            .map_or(gasapp_net::pow::LINK_DIFFICULTY, |challenge| {
                challenge.difficulty
            })
            .clamp(gasapp_net::pow::LINK_DIFFICULTY, MAX_LINK_DIFFICULTY);
        let pow_nonce =
            gasapp_net::pow::solve(&gasapp_net::pow::link_challenge(&request), difficulty)
                .ok_or(GasAppError::Crypto)?;

        self.api.link_open(
            &nonce,
            &LinkRequestBody {
                request: hex(&request),
                pow_nonce,
            },
        )?;
        let uri = secrets.request().code().to_uri();
        *self
            .linking
            .pending
            .lock()
            .map_err(|_| GasAppError::Storage)? = Some(PendingLink {
            secrets,
            identity,
            pq,
            device_id,
            opened: None,
            completed: None,
        });
        Ok(uri)
    }

    /// Новое устройство: пришёл ли грант. `None` — ещё нет (спрашивать
    /// снова через пару секунд, пока QR не истёк).
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Uninitialized`] — связывание не начато;
    /// * [`GasAppError::Crypto`], [`GasAppError::InvalidSignature`] —
    ///   грант не для этого запроса или список устройств не сходится.
    pub fn poll_device_link(&self) -> Result<Option<LinkOffer>> {
        let mut guard = self
            .linking
            .pending
            .lock()
            .map_err(|_| GasAppError::Storage)?;
        let pending = guard.as_mut().ok_or(GasAppError::Uninitialized)?;
        if let Some(opened) = &pending.opened {
            return Ok(Some(LinkOffer {
                code: opened.code.clone(),
                username: opened.grant.username.clone(),
            }));
        }
        let nonce = uuid::Uuid::from_bytes(pending.secrets.request().nonce).to_string();
        let grant = match self.api.link_take_grant(&nonce) {
            Ok(grant) => grant,
            Err(GasAppError::SessionNotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        let opened = device_link::open_grant(&pending.secrets, &unhex(&grant.grant)?)?;
        let offer = LinkOffer {
            code: opened.code.clone(),
            username: opened.grant.username.clone(),
        };
        pending.opened = Some(opened);
        Ok(Some(offer))
    }

    /// Новое устройство: человек сверил цифры — устройство регистрируется
    /// в аккаунте и публикует свои предключи.
    ///
    /// Повторяемо: сбой сети после регистрации на сервере не обрывает
    /// вход — повторный вызов досылает ключи, а не начинает заново (новый
    /// QR был бы невозможен: устройство уже с ключами).
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Uninitialized`] — гранта ещё нет;
    /// * [`GasAppError::Network`] — сервер недоступен или отказал (можно
    ///   повторить).
    pub fn finish_device_link<R: RngCore + CryptoRng>(
        &self,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Account> {
        let mut guard = self
            .linking
            .pending
            .lock()
            .map_err(|_| GasAppError::Storage)?;
        let pending = guard.as_mut().ok_or(GasAppError::Uninitialized)?;
        if pending.completed.is_none() {
            let done = self.register_linked(pending, now, rng)?;
            pending.completed = Some(done);
        }
        let account = self.publish_linked(pending, now, rng)?;
        *guard = None;
        Ok(account)
    }

    /// Первая фаза входа — один раз: сервер узнаёт устройство, база —
    /// ключи и аккаунт. Возвращает то, что досылается второй фазой.
    fn register_linked<R: RngCore + CryptoRng>(
        &self,
        pending: &PendingLink,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<CompletedLink> {
        let opened = pending.opened.as_ref().ok_or(GasAppError::Uninitialized)?;
        let access_key: [u8; ACCESS_KEY_LEN] = opened
            .grant
            .extra
            .as_slice()
            .try_into()
            .map_err(|_| GasAppError::Malformed)?;
        let nonce = pending.secrets.request().nonce;
        let private = PrivateKeyBytes::new(*pending.identity.private().expose_secret());

        let mut message = COMPLETE_DOMAIN.to_vec();
        message.extend_from_slice(&nonce);
        let signature = gasapp_protocol::xeddsa::montgomery::sign(&private, &message)?;
        // 🔐 Членство: этот ключ — устройство именно этого аккаунта. Без
        // подписи собеседники устройство из списка не примут.
        let membership = device_list::sign_membership(
            &private,
            &opened.grant.account_identity,
            pending.device_id.as_uuid().as_bytes(),
        )?;
        let response = self.api.link_complete(
            &uuid::Uuid::from_bytes(nonce).to_string(),
            &LinkCompleteBody {
                signature: hex(&signature),
                membership: hex(&membership),
            },
        )?;
        let device_id = parse_uuid(&response.device_id).map(DeviceId::from_uuid)?;
        let account_id = parse_uuid(&response.account_id).map(AccountId::from_uuid)?;
        if device_id != pending.device_id
            || account_id.as_uuid().as_bytes() != &opened.grant.account_id
        {
            return Err(GasAppError::Malformed);
        }

        let identity = &pending.identity;
        let (bundle, secrets) = prekeys::generate(identity, &pending.pq, device_id, now, rng)?;
        let username = opened.grant.username.clone();
        self.storage.save_own_keys(
            identity.private().expose_secret(),
            identity.public().public().as_bytes(),
            &secrets.to_bytes()?,
            Some(&device_id.to_string()),
            Some(&username),
            now,
        )?;
        self.storage.set_account_id(&account_id, now)?;
        self.storage.init_own_pq_identity(pending.pq.seed())?;
        // 🔐 Половина этого устройства — не половина аккаунта: публиковать
        // её как ключ аккаунта нельзя никогда.
        self.storage.mark_own_pq_identity_published(now)?;
        self.storage
            .set_own_account_identity(&opened.grant.account_identity, &opened.grant.account_pq)?;
        self.save_list(&opened.grant.account_identity, &opened.device_list, now)?;
        // Ключ доступа аккаунта — тот же, что у основного.
        self.storage.init_own_access_key(&access_key)?;

        let mut request = publish_request(&bundle);
        // Своя половина и её привязка — как у устройства, не у аккаунта:
        // сервер хранит их при устройстве (собеседники проверяют связку
        // по подписанному списку и привязке).
        request.pq_identity_key = Some(hex(&pending.pq.public()));
        request.identity_binding = Some(hex(&gasapp_protocol::pq_identity::bind(
            identity,
            &pending.pq,
        )?));
        let (kem_public, kem_signature) = self.sealed_kem_publication(identity, rng)?;
        request.sealed_kem_public = Some(kem_public);
        request.sealed_kem_signature = Some(kem_signature);

        Ok(CompletedLink {
            account: Account {
                account_id,
                device_id,
                username,
            },
            request,
        })
    }

    /// Вторая фаза входа — повторяемая: ключи на сервер, ключ доступа,
    /// отметки.
    fn publish_linked<R: RngCore + CryptoRng>(
        &self,
        pending: &PendingLink,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Account> {
        let completed = pending
            .completed
            .as_ref()
            .ok_or(GasAppError::Uninitialized)?;
        let identity = &pending.identity;
        self.api.publish_keys(
            &completed.account.device_id.to_string(),
            &completed.request,
            &DeviceSigner::new(identity, now),
        )?;
        self.storage.mark_own_sealed_kem_published(now)?;
        self.ensure_access_key(identity, now, rng)?;
        self.set_setting_bool(super::devices::MULTI_DEVICE_SETTING, true)?;
        // С этого момента полчаса принимается история от основного.
        self.storage
            .set_setting_int(super::history::LINKED_AT_SETTING, now.as_millis())?;
        self.forget_own_targets();
        self.storage
            .log_security_event("device_linked_to_account", None, now)?;
        Ok(completed.account.clone())
    }

    /// Основное устройство: QR нового — проверенный запрос, новый список
    /// устройств, запечатанный грант. Возвращает шесть цифр: показать
    /// человеку и отправить ([`Client::approve_device_link`]) только
    /// после «Подключить».
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — не ссылка связывания или срок вышел;
    /// * [`GasAppError::InvalidSignature`] — запрос в ящике подменён;
    /// * [`GasAppError::Forbidden`] — это не основное устройство или
    ///   устройств уже предел.
    pub fn prepare_device_link<R: RngCore + CryptoRng>(
        &self,
        uri: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<String> {
        let code = LinkCode::parse(uri)?;
        code.check_fresh(now.as_millis())?;
        let nonce = uuid::Uuid::from_bytes(code.nonce).to_string();
        let request = device_link::check_request(
            &code,
            &unhex(&self.api.link_request(&nonce)?.request)?,
            now.as_millis(),
        )?;

        let (identity, pq) = self.primary_keys()?;
        let current = self.own_device_list(&identity, &pq, now)?;
        if current.devices.len() >= MAX_DEVICES {
            return Err(GasAppError::Forbidden);
        }
        let mut devices = current.devices;
        devices.push(DeviceEntry {
            device_id: request.device_id,
            identity: request.identity,
            pq_identity: request.pq_identity.clone(),
        });
        let list = DeviceList {
            account_identity: *identity.public().public(),
            version: current
                .version
                .checked_add(1)
                .ok_or(GasAppError::Malformed)?,
            issued_at_millis: now.as_millis(),
            devices,
        }
        .sign(&identity, &pq)?;

        let account_id = self
            .storage
            .get_account_id()?
            .ok_or(GasAppError::Uninitialized)?;
        // 🔐 Ключ доступа sealed sender — общий для всех устройств аккаунта:
        // собеседник хранит один ключ на аккаунт, и запечатанное сообщение
        // любому устройству проходит с ним.
        let access_key = self.ensure_access_key(&identity, now, rng)?;
        let grant = LinkGrant {
            account_id: *account_id.as_uuid().as_bytes(),
            username: self.own_username()?.ok_or(GasAppError::Uninitialized)?,
            account_identity: *identity.public().public(),
            account_pq: pq.public(),
            device_list: list.to_bytes(),
            extra: access_key.to_vec(),
        };
        let seal = device_link::seal_grant(&request, &grant, rng)?;
        *self
            .linking
            .prepared
            .lock()
            .map_err(|_| GasAppError::Storage)? = Some(PreparedLink {
            nonce,
            device_id: uuid::Uuid::from_bytes(request.device_id).to_string(),
            code,
            body: LinkGrantBody {
                grant: hex(&seal.sealed),
                device_list: hex(&list.to_bytes()),
            },
        });
        Ok(seal.code)
    }

    /// Основное устройство: человек нажал «Подключить» — грант уходит
    /// новому устройству.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Uninitialized`] — подготовленного гранта нет;
    /// * [`GasAppError::Forbidden`] — сервер не принял список;
    /// * [`GasAppError::Malformed`] — срок QR вышел, пока человек сверял
    ///   цифры;
    /// * [`GasAppError::SessionNotFound`] — ящика на сервере уже нет.
    pub fn approve_device_link(&self, now: Timestamp) -> Result<()> {
        let prepared = self
            .linking
            .prepared
            .lock()
            .map_err(|_| GasAppError::Storage)?
            .take()
            .ok_or(GasAppError::Uninitialized)?;
        prepared.code.check_fresh(now.as_millis())?;
        let (identity, _) = self.load_identity()?;
        let own = self.own_device_id()?.ok_or(GasAppError::Uninitialized)?;
        self.api.link_grant(
            &own,
            &prepared.nonce,
            &prepared.body,
            &DeviceSigner::new(&identity, now),
        )?;
        self.set_setting_bool(super::devices::MULTI_DEVICE_SETTING, true)?;
        self.schedule_history(&prepared.device_id, now)?;
        self.forget_own_targets();
        self.storage
            .log_security_event("device_link_approved", None, now)?;
        Ok(())
    }

    /// Свои устройства.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сервер недоступен.
    pub fn own_devices(&self, now: Timestamp) -> Result<Vec<OwnDevice>> {
        let (identity, _) = self.load_identity()?;
        let account = self.own_account(&identity)?;
        let own = self.own_device_id()?.unwrap_or_default();
        let devices = if self.storage.own_account_identity()?.is_some() {
            // Подключённое устройство: список — запомненный, обновлённый
            // по серверу, если тот отдаёт новее.
            let pq = self
                .storage
                .own_account_identity()?
                .map(|(_, pq)| pq)
                .unwrap_or_default();
            let _ = self.refresh_own_list(&account, &pq, now);
            self.storage.known_devices(&account)?
        } else {
            let (identity, pq) = self.primary_keys()?;
            self.own_device_list(&identity, &pq, now)?
                .devices
                .into_iter()
                .map(|entry| KnownDevice {
                    device_id: entry.device_id,
                    identity: entry.identity,
                    pq_identity: entry.pq_identity,
                })
                .collect()
        };
        Ok(devices
            .into_iter()
            .map(|device| {
                let device_id = uuid::Uuid::from_bytes(device.device_id).to_string();
                OwnDevice {
                    this_device: device_id == own,
                    primary: device.identity == account,
                    device_id,
                }
            })
            .collect())
    }

    /// Основное устройство отключает другое: новый список без него.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — это не основное устройство, или
    ///   отключить пытаются основное;
    /// * [`GasAppError::SessionNotFound`] — такого устройства нет.
    pub fn unlink_device(&self, device_id: &str, now: Timestamp) -> Result<()> {
        let target = device_bytes(device_id)?;
        let (identity, pq) = self.primary_keys()?;
        let current = self.own_device_list(&identity, &pq, now)?;
        let entry = current
            .devices
            .iter()
            .find(|entry| entry.device_id == target)
            .ok_or(GasAppError::SessionNotFound)?;
        if entry.identity == *identity.public().public() {
            return Err(GasAppError::Forbidden);
        }
        let list = DeviceList {
            account_identity: *identity.public().public(),
            version: current
                .version
                .checked_add(1)
                .ok_or(GasAppError::Malformed)?,
            issued_at_millis: now.as_millis(),
            devices: current
                .devices
                .into_iter()
                .filter(|entry| entry.device_id != target)
                .collect(),
        }
        .sign(&identity, &pq)?;
        let own = self.own_device_id()?.ok_or(GasAppError::Uninitialized)?;
        self.api.unlink_device(
            &own,
            device_id,
            &UnlinkBody {
                device_list: hex(&list.to_bytes()),
            },
            &DeviceSigner::new(&identity, now),
        )?;
        self.save_list(identity.public().public(), &list, now)?;
        self.forget_own_targets();
        self.storage
            .log_security_event("device_unlinked", None, now)?;
        Ok(())
    }

    /// Основное ли это устройство: его ключ — ключ аккаунта. Подключать
    /// и отключать устройства можно только с него.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn is_primary_device(&self) -> Result<bool> {
        Ok(self.storage.own_account_identity()?.is_none())
    }

    /// Ключи основного устройства (они же — ключи аккаунта).
    fn primary_keys(&self) -> Result<(IdentityKeyPair, PqIdentityKeyPair)> {
        if self.storage.own_account_identity()?.is_some() {
            return Err(GasAppError::Forbidden);
        }
        let (identity, _) = self.load_identity()?;
        Ok((identity, self.own_pq_identity()?))
    }

    /// Действующий список своих устройств — с сервера, проверенный ключом
    /// аккаунта и правилом версий. Списка ещё нет — одно, это устройство
    /// (версия 0: первая подписанная будет 1).
    fn own_device_list(
        &self,
        identity: &IdentityKeyPair,
        pq: &PqIdentityKeyPair,
        now: Timestamp,
    ) -> Result<DeviceList> {
        let account = *identity.public().public();
        if let Some(list) = self.refresh_own_list(&account, &pq.public(), now)? {
            return Ok(list.list);
        }
        if self.storage.device_list(&account)?.is_some() {
            // Список был, а сервер его не отдаёт — откат: не строить новый
            // поверх пустоты (он вернул бы отключённые устройства).
            return Err(GasAppError::InvalidSignature);
        }
        let own = self.own_device_id()?.ok_or(GasAppError::Uninitialized)?;
        Ok(DeviceList {
            account_identity: account,
            version: 0,
            issued_at_millis: now.as_millis(),
            devices: vec![DeviceEntry {
                device_id: device_bytes(&own)?,
                identity: account,
                pq_identity: pq.public(),
            }],
        })
    }

    /// Основное устройство: переподписывает свой список, если он старше
    /// недели (тот же состав, новая версия и время). Зовётся с приёмом.
    ///
    /// 🔐 Собеседники не верят списку старше 30 дней — тогда пишут только
    /// основному устройству. Иначе сервер мог бы годами отдавать старую
    /// версию с давно отключённым (украденным) телефоном.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сервер недоступен; повтор в следующий раз.
    pub(crate) fn resign_own_list_if_old(&self, now: Timestamp) -> Result<()> {
        let Ok((identity, pq)) = self.primary_keys() else {
            return Ok(());
        };
        let account = *identity.public().public();
        // Своего списка в базе может не быть (после «Подключить» он только
        // на сервере) — тогда с сервера; у аккаунта без списка — нечего.
        let signed = match self.storage.device_list(&account)? {
            Some(stored) => SignedDeviceList::verify(&stored.signed, &account, &pq.public())?,
            None => match self.refresh_own_list(&account, &pq.public(), now)? {
                Some(signed) => signed,
                None => return Ok(()),
            },
        };
        if now.as_millis().saturating_sub(signed.list.issued_at_millis) < LIST_RESIGN_MILLIS {
            return Ok(());
        }
        let current = self.own_device_list(&identity, &pq, now)?;
        let list = DeviceList {
            account_identity: account,
            version: current
                .version
                .checked_add(1)
                .ok_or(GasAppError::Malformed)?,
            issued_at_millis: now.as_millis(),
            devices: current.devices,
        }
        .sign(&identity, &pq)?;
        let own = self.own_device_id()?.ok_or(GasAppError::Uninitialized)?;
        self.api.refresh_device_list(
            &own,
            &UnlinkBody {
                device_list: hex(&list.to_bytes()),
            },
            &DeviceSigner::new(&identity, now),
        )?;
        self.save_list(&account, &list, now)
    }

    /// Свой список с сервера — проверенный и запомненный. `None` — у
    /// аккаунта списка нет.
    fn refresh_own_list(
        &self,
        account: &PublicKeyBytes,
        account_pq: &[u8],
        now: Timestamp,
    ) -> Result<Option<SignedDeviceList>> {
        let account_id = self
            .storage
            .get_account_id()?
            .ok_or(GasAppError::Uninitialized)?;
        let response = match self.api.device_list_of(&account_id.as_uuid().to_string()) {
            Ok(response) => response,
            Err(GasAppError::SessionNotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        let signed = SignedDeviceList::verify(&unhex(&response.device_list)?, account, account_pq)?;
        let stored = self.storage.device_list(account)?;
        check_succession(
            stored.as_ref().map(|list| (list.version, list.digest)),
            &signed,
        )?;
        self.save_list(account, &signed, now)?;
        Ok(Some(signed))
    }

    /// Запоминает проверенный список устройств аккаунта.
    pub(crate) fn save_list(
        &self,
        account: &PublicKeyBytes,
        signed: &SignedDeviceList,
        now: Timestamp,
    ) -> Result<()> {
        self.save_list_with(account, signed, &signed.list.devices, now)
    }

    /// Запоминает список и устройства, которым верить: для своего аккаунта
    /// — все (список подписан своим ключом), для собеседника — только с
    /// подписью членства ([`device_list::proven_devices`]).
    pub(crate) fn save_list_with(
        &self,
        account: &PublicKeyBytes,
        signed: &SignedDeviceList,
        trusted: &[DeviceEntry],
        now: Timestamp,
    ) -> Result<()> {
        let devices: Vec<KnownDevice> = trusted
            .iter()
            .map(|entry| KnownDevice {
                device_id: entry.device_id,
                identity: entry.identity,
                pq_identity: entry.pq_identity.clone(),
            })
            .collect();
        self.storage.save_device_list(
            account,
            &StoredDeviceList {
                version: signed.list.version,
                digest: signed.digest(),
                signed: signed.to_bytes(),
            },
            &devices,
            now,
        )
    }

    /// Свой список устройств для собеседников — только на подключённом
    /// устройстве (основное собеседники знают по ключу аккаунта).
    pub(crate) fn own_device_list_for_peers(&self) -> Result<Option<Vec<u8>>> {
        let Some((account, _)) = self.storage.own_account_identity()? else {
            return Ok(None);
        };
        let Some(list) = self.storage.device_list(&account)? else {
            return Ok(None);
        };
        // С подписью членства этого устройства: без неё получатель не
        // примет его в списке.
        let (identity, _) = self.load_identity()?;
        let own = self.own_device_id()?.ok_or(GasAppError::Uninitialized)?;
        let device_id = device_bytes(&own)?;
        let membership = device_list::sign_membership(
            &PrivateKeyBytes::new(*identity.private().expose_secret()),
            &account,
            &device_id,
        )?;
        device_list::encode_shared(&list.signed, &[(device_id, membership)]).map(Some)
    }

    /// 🔐 Список устройств из первого сообщения сессии с незнакомого
    /// устройства: чьё оно. Ключ аккаунта списка сверяется с известным
    /// контактом (классический ключ — он и есть ключ аккаунта; хеш
    /// пост-квантовой половины основного устройства); незнакомый аккаунт —
    /// доверие при первой встрече, как к ключу в конверте инициации.
    /// Подпись, наличие устройства в списке и правило версий — всегда.
    /// Не сошлось — устройство остаётся незнакомым.
    pub(crate) fn learn_device_list(&self, device: &PublicKeyBytes, shared: &[u8], now: Timestamp) {
        let Ok((bytes, proofs)) = device_list::decode_shared(shared) else {
            return;
        };
        let bytes = bytes.as_slice();
        let Some(split) = bytes
            .len()
            .checked_sub(gasapp_protocol::pq_identity::HYBRID_SIGNATURE_LEN)
        else {
            return;
        };
        let Some(Ok(list)) = bytes.get(..split).map(DeviceList::decode) else {
            return;
        };
        let Some(primary) = list
            .devices
            .iter()
            .find(|entry| entry.identity == list.account_identity)
        else {
            return;
        };
        // 🔐 Устройство отправителя — в списке и с подписью членства.
        let proven = device_list::proven_devices(&list, &proofs);
        if !proven.iter().any(|entry| entry.identity == *device) {
            return;
        }
        let account = list.account_identity;
        let known_hash = self
            .storage
            .contact_pq_hash(&super::peer_account(&account))
            .ok()
            .flatten();
        if known_hash.is_some_and(|hash| {
            hash != gasapp_protocol::pq_identity::pq_identity_hash(&primary.pq_identity)
        }) {
            let _ = self
                .storage
                .log_security_event("device_list_pq_mismatch", None, now);
            return;
        }
        let Ok(signed) = SignedDeviceList::verify(bytes, &account, &primary.pq_identity) else {
            return;
        };
        let stored = self.storage.device_list(&account).ok().flatten();
        if check_succession(
            stored.as_ref().map(|list| (list.version, list.digest)),
            &signed,
        )
        .is_ok()
        {
            let _ = self.save_list_with(&account, &signed, &proven, now);
        }
    }
}
