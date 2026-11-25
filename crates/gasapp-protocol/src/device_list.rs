// SPDX-License-Identifier: Apache-2.0

//! Подписанный список устройств аккаунта (SDL, `docs/protocol/MULTI-DEVICE.md`, §2).
//!
//! У каждого устройства свои ключи (`IK_d`, `PQ_d`): предключи, сессии,
//! sealed sender. Связывает их с аккаунтом этот список, подписанный
//! гибридно ключом аккаунта (`IK_A` + `PQ_A`) — тем, что собеседник уже
//! сверил кодом безопасности и что подтверждает журнал ключей.
//!
//! 🔐 Что это даёт:
//!
//! * сервер не может **добавить** устройство — подписать список нечем;
//! * сервер не может **вернуть** отключённое — версия только растёт
//!   ([`check_succession`]), а та же версия с другим содержимым — подделка;
//! * закрытый ключ аккаунта остаётся на основном устройстве.
//!
//! ⚠️ Чего это не даёт: сервер может придержать новую версию — отдавать
//! старый список. Защита — срок списка ([`DeviceList::issued_at_millis`]),
//! её применяет ядро.
//!
//! # Формат
//!
//! ```text
//! "GDL1" ‖ IK_A(32) ‖ версия(u64 BE) ‖ время(i64 BE, мс) ‖ n(u8)
//!        ‖ n × (device_id(16) ‖ IK_d(32) ‖ PQ_d(1952))
//! подпись = XEdDSA(IK_A) ‖ ML-DSA-65(PQ_A, домен GASAPP_DEVICE_LIST_v1)
//! ```

use gasapp_types::{GasAppError, PrivateKeyBytes, PublicKeyBytes, Result};
use sha2::{Digest, Sha256};

use crate::keys::IdentityKeyPair;
use crate::pq_identity::{self, PqIdentityKeyPair, HYBRID_SIGNATURE_LEN, PQ_PUBLIC_LEN};

/// Начало закодированного списка.
pub const MAGIC: &[u8; 4] = b"GDL1";

/// Домен гибридной подписи списка.
pub const DOMAIN: &[u8] = b"GASAPP_DEVICE_LIST_v1";

/// Сколько устройств может быть у аккаунта (план, 13.1).
pub const MAX_DEVICES: usize = 5;

/// Длина идентификатора устройства (UUID).
pub const DEVICE_ID_LEN: usize = 16;

/// Длина заголовка: магия, ключ аккаунта, версия, время, число устройств.
const HEADER_LEN: usize = 4 + 32 + 8 + 8 + 1;

/// Длина записи устройства.
const ENTRY_LEN: usize = DEVICE_ID_LEN + 32 + PQ_PUBLIC_LEN;

/// Устройство аккаунта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEntry {
    /// Идентификатор устройства (UUID), как его знает сервер.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Identity-ключ устройства (X25519).
    pub identity: PublicKeyBytes,
    /// Пост-квантовая половина identity устройства (ML-DSA-65).
    pub pq_identity: Vec<u8>,
}

/// Список устройств аккаунта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceList {
    /// Identity-ключ аккаунта — тот, чей это список.
    pub account_identity: PublicKeyBytes,
    /// Версия: только растёт.
    pub version: u64,
    /// Когда подписан, миллисекунды Unix.
    pub issued_at_millis: i64,
    /// Устройства; основное (`identity == account_identity`) — всегда есть.
    pub devices: Vec<DeviceEntry>,
}

impl DeviceList {
    /// Устройство по идентификатору.
    #[must_use]
    pub fn device(&self, device_id: &[u8; DEVICE_ID_LEN]) -> Option<&DeviceEntry> {
        self.devices
            .iter()
            .find(|entry| &entry.device_id == device_id)
    }

    /// Проверяет правила списка.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — устройств нет или больше
    /// [`MAX_DEVICES`]; повтор идентификатора или ключа; нулевой
    /// идентификатор; ключ PQ не той длины; нет основного устройства.
    pub fn validate(&self) -> Result<()> {
        if self.devices.is_empty() || self.devices.len() > MAX_DEVICES {
            return Err(GasAppError::Malformed);
        }
        let mut has_primary = false;
        for (index, entry) in self.devices.iter().enumerate() {
            if entry.device_id == [0; DEVICE_ID_LEN] || entry.pq_identity.len() != PQ_PUBLIC_LEN {
                return Err(GasAppError::Malformed);
            }
            let repeated = self
                .devices
                .iter()
                .skip(index.saturating_add(1))
                .any(|other| {
                    other.device_id == entry.device_id
                        || other.identity == entry.identity
                        || other.pq_identity == entry.pq_identity
                });
            if repeated {
                return Err(GasAppError::Malformed);
            }
            has_primary |= entry.identity == self.account_identity;
        }
        if has_primary {
            Ok(())
        } else {
            Err(GasAppError::Malformed)
        }
    }

    /// Кодирует список (с проверкой правил).
    ///
    /// # Errors
    ///
    /// Как [`DeviceList::validate`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let count = u8::try_from(self.devices.len()).map_err(|_| GasAppError::Malformed)?;
        let mut out = Vec::with_capacity(
            HEADER_LEN.saturating_add(ENTRY_LEN.saturating_mul(self.devices.len())),
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(self.account_identity.as_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.issued_at_millis.to_be_bytes());
        out.push(count);
        for entry in &self.devices {
            out.extend_from_slice(&entry.device_id);
            out.extend_from_slice(entry.identity.as_bytes());
            out.extend_from_slice(&entry.pq_identity);
        }
        Ok(out)
    }

    /// Разбирает закодированный список (с проверкой правил).
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — не тот формат, лишние байты или
    /// нарушены правила списка.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader(bytes);
        if &reader.array::<4>()? != MAGIC {
            return Err(GasAppError::Malformed);
        }
        let account_identity = PublicKeyBytes::new(reader.array()?);
        let version = u64::from_be_bytes(reader.array()?);
        let issued_at_millis = i64::from_be_bytes(reader.array()?);
        let [count] = reader.array::<1>()?;
        let count = usize::from(count);
        if count > MAX_DEVICES {
            return Err(GasAppError::Malformed);
        }
        let mut devices = Vec::with_capacity(count);
        for _ in 0..count {
            devices.push(DeviceEntry {
                device_id: reader.array()?,
                identity: PublicKeyBytes::new(reader.array()?),
                pq_identity: reader.take(PQ_PUBLIC_LEN)?.to_vec(),
            });
        }
        if !reader.0.is_empty() {
            return Err(GasAppError::Malformed);
        }
        let list = Self {
            account_identity,
            version,
            issued_at_millis,
            devices,
        };
        list.validate()?;
        Ok(list)
    }

    /// Подписывает список ключом аккаунта — только основное устройство.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — ключ не тот, чей это список, или
    ///   нарушены правила списка;
    /// * [`GasAppError::Crypto`] — сбой подписи.
    pub fn sign(
        &self,
        identity: &IdentityKeyPair,
        pq: &PqIdentityKeyPair,
    ) -> Result<SignedDeviceList> {
        if identity.public().public() != &self.account_identity {
            return Err(GasAppError::Malformed);
        }
        let encoded = self.encode()?;
        let signature = pq_identity::hybrid_sign(identity, pq, DOMAIN, &encoded)?;
        Ok(SignedDeviceList {
            list: self.clone(),
            encoded,
            signature,
        })
    }
}

/// Список с подписью ключа аккаунта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDeviceList {
    /// Разобранный список.
    pub list: DeviceList,
    /// Подписанные байты.
    pub encoded: Vec<u8>,
    /// Гибридная подпись.
    pub signature: Vec<u8>,
}

impl SignedDeviceList {
    /// Байты для передачи: список ‖ подпись.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded.len().saturating_add(self.signature.len()));
        out.extend_from_slice(&self.encoded);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Отпечаток списка — для правила версий ([`check_succession`]).
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.encoded).into()
    }

    /// Разбирает и проверяет список ключом аккаунта, который уже
    /// известен проверяющему (сверен кодом безопасности, подтверждён KT).
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — формат или правила списка;
    /// * [`GasAppError::InvalidSignature`] — подпись не сошлась либо
    ///   список чужого аккаунта.
    pub fn verify(
        bytes: &[u8],
        account_identity: &PublicKeyBytes,
        account_pq: &[u8],
    ) -> Result<Self> {
        let split = bytes
            .len()
            .checked_sub(HYBRID_SIGNATURE_LEN)
            .ok_or(GasAppError::Malformed)?;
        let (encoded, signature) = bytes.split_at(split);
        let list = DeviceList::decode(encoded)?;
        if &list.account_identity != account_identity {
            return Err(GasAppError::InvalidSignature);
        }
        pq_identity::hybrid_verify(account_identity, account_pq, DOMAIN, encoded, signature)?;
        Ok(Self {
            list,
            encoded: encoded.to_vec(),
            signature: signature.to_vec(),
        })
    }
}

/// Правило версий: принять ли `next` после списка, запомненного раньше
/// (`previous` — его версия и [`SignedDeviceList::digest`]).
///
/// # Errors
///
/// * [`GasAppError::InvalidSignature`] — версия меньше запомненной: сервер
///   отдаёт старый список (например, с отключённым устройством);
/// * [`GasAppError::IdentityChanged`] — та же версия, другое содержимое:
///   два разных списка под одной версией — подделка.
pub fn check_succession(previous: Option<(u64, [u8; 32])>, next: &SignedDeviceList) -> Result<()> {
    match previous {
        None => Ok(()),
        Some((version, _)) if next.list.version > version => Ok(()),
        Some((version, digest)) if next.list.version == version => {
            if next.digest() == digest {
                Ok(())
            } else {
                Err(GasAppError::IdentityChanged)
            }
        }
        Some(_) => Err(GasAppError::InvalidSignature),
    }
}

/// Читатель байтов без индексации.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.0.len() < count {
            return Err(GasAppError::Malformed);
        }
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| GasAppError::Malformed)
    }
}

/// Домен подписи членства: устройство подтверждает, что оно — устройство
/// этого аккаунта.
pub const MEMBERSHIP_DOMAIN: &[u8] = b"GASAPP_DEVICE_MEMBERSHIP_v1";

/// Длина подписи членства (XEdDSA).
pub const MEMBERSHIP_SIGNATURE_LEN: usize = 64;

/// Доказательство членства: устройство и его подпись.
pub type Membership = ([u8; DEVICE_ID_LEN], [u8; MEMBERSHIP_SIGNATURE_LEN]);

/// Сообщение, которое подписывает устройство: домен ‖ ключ аккаунта ‖
/// идентификатор устройства.
#[must_use]
pub fn membership_message(account: &PublicKeyBytes, device_id: &[u8; DEVICE_ID_LEN]) -> Vec<u8> {
    let mut message = MEMBERSHIP_DOMAIN.to_vec();
    message.extend_from_slice(account.as_bytes());
    message.extend_from_slice(device_id);
    message
}

/// Устройство подписывает своё членство в аккаунте.
///
/// 🔐 Без этой подписи список, подписанный аккаунтом, мог бы назвать
/// «своим» чужой ключ — ключ устройства другого человека: получатель
/// приписал бы его сообщения не тому собеседнику. Подпись делает только
/// само устройство и только для аккаунта, к которому подключилось.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — ключ не годится для подписи.
pub fn sign_membership(
    device: &PrivateKeyBytes,
    account: &PublicKeyBytes,
    device_id: &[u8; DEVICE_ID_LEN],
) -> Result<[u8; MEMBERSHIP_SIGNATURE_LEN]> {
    crate::xeddsa::montgomery::sign(device, &membership_message(account, device_id))
}

/// Проверяет подпись членства устройства `device` в аккаунте `account`.
///
/// # Errors
///
/// [`GasAppError::InvalidSignature`] — подпись не этого устройства или не
/// для этого аккаунта.
pub fn verify_membership(
    device: &PublicKeyBytes,
    account: &PublicKeyBytes,
    device_id: &[u8; DEVICE_ID_LEN],
    signature: &[u8],
) -> Result<()> {
    crate::xeddsa::montgomery::verify(device, &membership_message(account, device_id), signature)
        .map_err(|_| GasAppError::InvalidSignature)
}

/// Устройства списка, которым можно верить: основное (его ключ — ключ
/// аккаунта) и подключённые с действительной подписью членства.
#[must_use]
pub fn proven_devices(list: &DeviceList, proofs: &[Membership]) -> Vec<DeviceEntry> {
    list.devices
        .iter()
        .filter(|entry| {
            entry.identity == list.account_identity
                || proofs.iter().any(|(device_id, signature)| {
                    *device_id == entry.device_id
                        && verify_membership(
                            &entry.identity,
                            &list.account_identity,
                            device_id,
                            signature,
                        )
                        .is_ok()
                })
        })
        .cloned()
        .collect()
}

/// Список с доказательствами членства — одним блоком (хвост ключа
/// доступа): длина списка (u32 BE) ‖ список ‖ n (u8) ‖ n × (id ‖ подпись).
///
/// # Errors
///
/// [`GasAppError::Malformed`] — доказательств больше, чем устройств.
pub fn encode_shared(list: &[u8], proofs: &[Membership]) -> Result<Vec<u8>> {
    if proofs.len() > MAX_DEVICES {
        return Err(GasAppError::Malformed);
    }
    let length = u32::try_from(list.len()).map_err(|_| GasAppError::Malformed)?;
    let mut out = Vec::with_capacity(
        list.len().saturating_add(5).saturating_add(
            proofs
                .len()
                .saturating_mul(DEVICE_ID_LEN + MEMBERSHIP_SIGNATURE_LEN),
        ),
    );
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(list);
    out.push(u8::try_from(proofs.len()).map_err(|_| GasAppError::Malformed)?);
    for (device_id, signature) in proofs {
        out.extend_from_slice(device_id);
        out.extend_from_slice(signature);
    }
    Ok(out)
}

/// Разбирает [`encode_shared`].
///
/// # Errors
///
/// [`GasAppError::Malformed`] — обрыв, хвост или доказательств больше,
/// чем устройств.
pub fn decode_shared(bytes: &[u8]) -> Result<(Vec<u8>, Vec<Membership>)> {
    let (length, rest) = bytes
        .split_first_chunk::<4>()
        .ok_or(GasAppError::Malformed)?;
    let length =
        usize::try_from(u32::from_be_bytes(*length)).map_err(|_| GasAppError::Malformed)?;
    let list = rest.get(..length).ok_or(GasAppError::Malformed)?;
    let rest = rest.get(length..).ok_or(GasAppError::Malformed)?;
    let (count, mut rest) = rest.split_first().ok_or(GasAppError::Malformed)?;
    let count = usize::from(*count);
    if count > MAX_DEVICES {
        return Err(GasAppError::Malformed);
    }
    let mut proofs = Vec::with_capacity(count);
    for _ in 0..count {
        let (device_id, tail) = rest
            .split_first_chunk::<DEVICE_ID_LEN>()
            .ok_or(GasAppError::Malformed)?;
        let (signature, tail) = tail
            .split_first_chunk::<MEMBERSHIP_SIGNATURE_LEN>()
            .ok_or(GasAppError::Malformed)?;
        proofs.push((*device_id, *signature));
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(GasAppError::Malformed);
    }
    Ok((list.to_vec(), proofs))
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::prekeys::generate_identity;
    use rand_core::OsRng;

    struct Device {
        identity: IdentityKeyPair,
        pq: PqIdentityKeyPair,
        id: [u8; DEVICE_ID_LEN],
    }

    fn device(id: u8) -> Device {
        Device {
            identity: generate_identity(&mut OsRng).unwrap(),
            pq: PqIdentityKeyPair::generate(&mut OsRng),
            id: [id; DEVICE_ID_LEN],
        }
    }

    fn entry(device: &Device) -> DeviceEntry {
        DeviceEntry {
            device_id: device.id,
            identity: *device.identity.public().public(),
            pq_identity: device.pq.public(),
        }
    }

    fn list(primary: &Device, others: &[&Device], version: u64) -> DeviceList {
        let mut devices = vec![entry(primary)];
        devices.extend(others.iter().map(|other| entry(other)));
        DeviceList {
            account_identity: *primary.identity.public().public(),
            version,
            issued_at_millis: 1_764_000_000_000,
            devices,
        }
    }

    #[test]
    fn a_signed_list_round_trips_and_verifies() {
        let primary = device(1);
        let phone = device(2);
        let signed = list(&primary, &[&phone], 2)
            .sign(&primary.identity, &primary.pq)
            .unwrap();
        let bytes = signed.to_bytes();

        let checked = SignedDeviceList::verify(
            &bytes,
            primary.identity.public().public(),
            &primary.pq.public(),
        )
        .unwrap();
        assert_eq!(checked, signed);
        assert!(checked.list.device(&phone.id).is_some());
    }

    /// 🔐 Сервер не может добавить устройство: список, подписанный не
    /// ключом аккаунта, и подменённый байт отвергаются.
    #[test]
    fn a_forged_or_tampered_list_is_refused() {
        let primary = device(1);
        let intruder = device(9);
        let account = *primary.identity.public().public();
        let account_pq = primary.pq.public();

        // Список «от имени» аккаунта, подписанный чужим ключом.
        let mut forged = list(&primary, &[&intruder], 3);
        forged.account_identity = *intruder.identity.public().public();
        forged.devices[0] = entry(&intruder);
        forged.devices[1] = entry(&primary);
        let forged = forged.sign(&intruder.identity, &intruder.pq).unwrap();
        assert!(SignedDeviceList::verify(&forged.to_bytes(), &account, &account_pq).is_err());

        // Подменён байт ключа устройства.
        let mut bytes = list(&primary, &[&intruder], 3)
            .sign(&primary.identity, &primary.pq)
            .unwrap()
            .to_bytes();
        bytes[HEADER_LEN + ENTRY_LEN + DEVICE_ID_LEN] ^= 1;
        assert!(SignedDeviceList::verify(&bytes, &account, &account_pq).is_err());

        // Подписать чужой список нельзя вовсе.
        assert!(list(&primary, &[], 1)
            .sign(&intruder.identity, &intruder.pq)
            .is_err());
    }

    /// 🔐 Откат версии и два разных списка под одной версией.
    #[test]
    fn versions_only_grow() {
        let primary = device(1);
        let phone = device(2);
        let v2 = list(&primary, &[&phone], 2)
            .sign(&primary.identity, &primary.pq)
            .unwrap();
        let v3 = list(&primary, &[], 3)
            .sign(&primary.identity, &primary.pq)
            .unwrap();
        let other_v3 = list(&primary, &[&phone], 3)
            .sign(&primary.identity, &primary.pq)
            .unwrap();

        assert!(check_succession(None, &v2).is_ok());
        assert!(check_succession(Some((2, v2.digest())), &v3).is_ok());
        assert!(check_succession(Some((3, v3.digest())), &v3).is_ok());
        assert!(matches!(
            check_succession(Some((3, v3.digest())), &v2),
            Err(GasAppError::InvalidSignature)
        ));
        assert!(matches!(
            check_succession(Some((3, v3.digest())), &other_v3),
            Err(GasAppError::IdentityChanged)
        ));
    }

    #[test]
    fn list_rules_are_enforced() {
        let primary = device(1);
        let phones: Vec<Device> = (2..=6).map(device).collect();
        let refs: Vec<&Device> = phones.iter().collect();

        // Шесть устройств — больше предела.
        assert!(list(&primary, &refs, 1).encode().is_err());
        // Пять — можно.
        assert!(list(&primary, &refs[..4], 1).encode().is_ok());
        // Повтор устройства.
        assert!(list(&primary, &[refs[0], refs[0]], 1).encode().is_err());
        // Без основного устройства.
        let mut orphan = list(&primary, &[refs[0]], 1);
        orphan.devices.remove(0);
        assert!(orphan.encode().is_err());
        // Лишние байты.
        let mut bytes = list(&primary, &[], 1).encode().unwrap();
        bytes.push(0);
        assert!(DeviceList::decode(&bytes).is_err());
    }
    /// Подключённое устройство в списке — только с подписью членства для
    /// этого аккаунта; чужой ключ без неё отбрасывается.
    #[test]
    fn only_proven_devices_are_trusted() {
        let mut rng = rand_core::OsRng;
        let account = generate_identity(&mut rng).expect("аккаунт");
        let linked = generate_identity(&mut rng).expect("устройство");
        let stranger = generate_identity(&mut rng).expect("чужой");
        let account_key = *account.public().public();
        let entry = |id: u8, key: &IdentityKeyPair| DeviceEntry {
            device_id: [id; DEVICE_ID_LEN],
            identity: *key.public().public(),
            pq_identity: vec![0; PQ_PUBLIC_LEN],
        };
        let list = DeviceList {
            account_identity: account_key,
            version: 2,
            issued_at_millis: 1,
            devices: vec![entry(1, &account), entry(2, &linked), entry(3, &stranger)],
        };
        let private = |key: &IdentityKeyPair| PrivateKeyBytes::new(*key.private().expose_secret());
        let good =
            sign_membership(&private(&linked), &account_key, &[2; DEVICE_ID_LEN]).expect("подпись");
        // Чужой ключ подписал членство в другом аккаунте — не годится.
        let other = sign_membership(
            &private(&stranger),
            stranger.public().public(),
            &[3; DEVICE_ID_LEN],
        )
        .expect("подпись");
        let proven = proven_devices(
            &list,
            &[([2; DEVICE_ID_LEN], good), ([3; DEVICE_ID_LEN], other)],
        );
        let ids: Vec<u8> = proven.iter().map(|entry| entry.device_id[0]).collect();
        assert_eq!(ids, vec![1, 2]);

        let shared = encode_shared(b"list", &[([2; DEVICE_ID_LEN], good)]).expect("кодируется");
        assert_eq!(
            decode_shared(&shared).expect("читается"),
            (b"list".to_vec(), vec![([2; DEVICE_ID_LEN], good)])
        );
        let mut tail = shared.clone();
        tail.push(0);
        assert!(decode_shared(&tail).is_err());
        assert!(decode_shared(shared.get(..shared.len() - 1).expect("срез")).is_err());
    }
}
