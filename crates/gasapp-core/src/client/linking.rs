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

use gasapp_net::api::{LinkCompleteBody, LinkGrantBody, LinkRequestBody, UnlinkBody};
use gasapp_net::client::Transport;
use gasapp_protocol::device_link::{self, LinkCode, LinkGrant, LinkSecrets, OpenedGrant};
use gasapp_protocol::device_list::{
    check_succession, DeviceEntry, DeviceList, SignedDeviceList, MAX_DEVICES,
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

/// Состояние связывания в клиенте — только в памяти.
#[derive(Default)]
pub(crate) struct LinkState {
    pending: Mutex<Option<PendingLink>>,
    prepared: Mutex<Option<PreparedLink>>,
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

        self.api.link_open(
            &nonce,
            &LinkRequestBody {
                request: hex(&secrets.request().encode()),
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
    /// # Errors
    ///
    /// * [`GasAppError::Uninitialized`] — гранта ещё нет;
    /// * [`GasAppError::Network`] — сервер недоступен или отказал.
    pub fn finish_device_link<R: RngCore + CryptoRng>(
        &self,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Account> {
        let pending = self
            .linking
            .pending
            .lock()
            .map_err(|_| GasAppError::Storage)?
            .take()
            .ok_or(GasAppError::Uninitialized)?;
        let Some(opened) = pending.opened else {
            return Err(GasAppError::Uninitialized);
        };
        let nonce = pending.secrets.request().nonce;

        let mut message = COMPLETE_DOMAIN.to_vec();
        message.extend_from_slice(&nonce);
        let signature = gasapp_protocol::xeddsa::montgomery::sign(
            &PrivateKeyBytes::new(*pending.identity.private().expose_secret()),
            &message,
        )?;
        let response = self.api.link_complete(
            &uuid::Uuid::from_bytes(nonce).to_string(),
            &LinkCompleteBody {
                signature: hex(&signature),
            },
        )?;
        let device_id = parse_uuid(&response.device_id).map(DeviceId::from_uuid)?;
        if device_id != pending.device_id {
            return Err(GasAppError::Malformed);
        }
        let account_id = parse_uuid(&response.account_id).map(AccountId::from_uuid)?;
        if account_id.as_uuid().as_bytes() != &opened.grant.account_id {
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
        self.api.publish_keys(
            &device_id.to_string(),
            &request,
            &DeviceSigner::new(identity, now),
        )?;
        self.storage.mark_own_sealed_kem_published(now)?;

        // Ключ доступа аккаунта — тот же, что у основного: выкладывается и
        // для этого устройства.
        let access_key: [u8; ACCESS_KEY_LEN] = opened
            .grant
            .extra
            .as_slice()
            .try_into()
            .map_err(|_| GasAppError::Malformed)?;
        self.storage.init_own_access_key(&access_key)?;
        self.ensure_access_key(identity, now, rng)?;
        self.set_setting_bool(super::devices::MULTI_DEVICE_SETTING, true)?;
        // С этого момента полчаса принимается история от основного.
        self.storage
            .set_setting_int(super::history::LINKED_AT_SETTING, now.as_millis())?;
        self.storage
            .log_security_event("device_linked_to_account", None, now)?;

        Ok(Account {
            account_id,
            device_id,
            username,
        })
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
        let devices: Vec<KnownDevice> = signed
            .list
            .devices
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
        Ok(self.storage.device_list(&account)?.map(|list| list.signed))
    }

    /// 🔐 Список устройств из первого сообщения сессии с незнакомого
    /// устройства: чьё оно. Ключ аккаунта списка сверяется с известным
    /// контактом (классический ключ — он и есть ключ аккаунта; хеш
    /// пост-квантовой половины основного устройства); незнакомый аккаунт —
    /// доверие при первой встрече, как к ключу в конверте инициации.
    /// Подпись, наличие устройства в списке и правило версий — всегда.
    /// Не сошлось — устройство остаётся незнакомым.
    pub(crate) fn learn_device_list(&self, device: &PublicKeyBytes, bytes: &[u8], now: Timestamp) {
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
        if !list.devices.iter().any(|entry| entry.identity == *device) {
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
            let _ = self.save_list(&account, &signed, now);
        }
    }
}
