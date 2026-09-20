// SPDX-License-Identifier: Apache-2.0

//! Sender Keys для групповых чатов (ADR-023).
//!
//! # Зачем они нужны
//!
//! В группе из ста человек pairwise-шифрование требует ста
//! шифротекстов на каждое сообщение. Sender Keys дают один: каждый
//! участник заводит собственную симметричную цепочку, раздаёт её
//! всем один раз по уже установленным pairwise-сессиям, а дальше
//! шифрует сообщения ключами из этой цепочки.
//!
//! # Что теряется
//!
//! ⚠️ Post-compromise security внутри цепочки. Симметричная цепочка
//! не «лечится» сама: атакующий, получивший её состояние, читает всё
//! последующее до ротации. Double Ratchet восстанавливается после
//! компрометации сам, Sender Keys — нет.
//!
//! Поэтому ADR-023 предписывает гибрид: группы до восьми участников
//! используют pairwise Double Ratchet (сорок шифротекстов — приемлемо),
//! и только с девяти переходят на Sender Keys.
//!
//! И поэтому же ротация обязательна при каждом изменении состава:
//! ушедший участник иначе продолжит читать переписку, в которой
//! больше не состоит.
//!
//! # Почему подпись обязательна
//!
//! 🔐 Ключ цепочки знают **все** участники группы. Без подписи любой
//! из них мог бы отправить сообщение от чужого имени, и получатели
//! не отличили бы подделку: тег AEAD подтверждает только знание
//! ключа, а его знают все.
//!
//! Подпись Ed25519 привязывает сообщение к конкретному отправителю.
//! Приватная часть подписывающей пары не раздаётся — в отличие
//! от цепочки.

use aegis_types::{AegisError, PublicKeyBytes, Result, Secret};
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aead::MessageKey;
use crate::x25519::X25519PrivateKey;
use crate::xeddsa;

/// Длина ключа цепочки.
pub const CHAIN_KEY_LEN: usize = 32;

/// Метка шага цепочки.
///
/// Отличается от меток Double Ratchet: одинаковые метки при
/// одинаковом входе дали бы одинаковые ключи в двух разных
/// подсистемах, и компрометация одной раскрыла бы другую.
const CHAIN_STEP: &[u8] = b"AEGIS_SENDER_CHAIN_v1";

/// Метка вывода ключа сообщения.
const MESSAGE_STEP: &[u8] = b"AEGIS_SENDER_MESSAGE_v1";

/// Предел сообщений на один ключ до обязательной ротации.
///
/// 🔐 ADR-023: тысяча сообщений либо семь дней, что наступит раньше.
/// Значение усилено относительно исходного плана (2000/30 дней),
/// потому что без post-compromise security каждое сообщение сверх
/// предела — это ещё одно, которое прочитает тот, кто однажды получил
/// состояние цепочки.
pub const MAX_MESSAGES_PER_KEY: u32 = 1_000;

/// Предел возраста ключа в миллисекундах: семь дней.
pub const MAX_KEY_AGE_MILLIS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// Порог перехода с pairwise на Sender Keys.
///
/// До этого числа участников включительно группа шифрует pairwise:
/// восемь участников — это сорок шифротекстов на сообщение,
/// что приемлемо ради post-compromise security. Дальше цена растёт
/// быстрее пользы.
pub const PAIRWISE_THRESHOLD: usize = 8;

/// Состояние отправителя: цепочка и подписывающая пара.
pub struct SenderKeyState {
    /// Текущий ключ цепочки.
    chain_key: Secret<[u8; CHAIN_KEY_LEN]>,

    /// Номер следующего сообщения.
    counter: u32,

    /// Приватная часть подписывающей пары.
    ///
    /// 🔐 Не раздаётся участникам — в отличие от цепочки. Именно она
    /// не даёт другому участнику отправить сообщение от нашего имени.
    signing_key: X25519PrivateKey,

    /// Когда ключ создан: для ротации по времени.
    created_at_millis: i64,
}

/// То, что раздаётся участникам группы.
///
/// 🔐 Уходит по уже установленным pairwise-сессиям, то есть под
/// сквозным шифрованием. Сервер видит только шифротекст.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderKeyDistribution {
    /// Ключ цепочки на момент раздачи.
    pub chain_key: [u8; CHAIN_KEY_LEN],

    /// Номер сообщения, с которого действует этот ключ.
    ///
    /// Нужен, чтобы участник, добавленный в середине разговора,
    /// не пытался расшифровать более ранние сообщения — он и не
    /// должен их видеть.
    pub counter: u32,

    /// Публичная часть подписывающей пары.
    pub signing_public: PublicKeyBytes,
}

/// Состояние получателя для одного отправителя.
pub struct SenderKeyReceiver {
    chain_key: Secret<[u8; CHAIN_KEY_LEN]>,
    counter: u32,
    signing_public: PublicKeyBytes,
}

/// Зашифрованное групповое сообщение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMessage {
    /// Номер сообщения в цепочке отправителя.
    pub counter: u32,

    /// Шифротекст.
    pub ciphertext: Vec<u8>,

    /// Подпись шифротекста.
    ///
    /// 🔐 Подписывается шифротекст вместе с номером: без номера
    /// участник переставил бы сообщения местами, сохранив подписи
    /// подлинными.
    pub signature: Vec<u8>,
}

impl SenderKeyState {
    /// Создаёт новое состояние отправителя.
    pub fn generate<R: RngCore + CryptoRng>(now_millis: i64, rng: &mut R) -> Self {
        let mut chain = [0u8; CHAIN_KEY_LEN];
        rng.fill_bytes(&mut chain);

        Self {
            chain_key: Secret::new(chain),
            counter: 0,
            signing_key: X25519PrivateKey::generate(rng),
            created_at_millis: now_millis,
        }
    }

    /// Собирает то, что раздаётся участникам.
    #[must_use]
    pub fn distribution(&self) -> SenderKeyDistribution {
        SenderKeyDistribution {
            chain_key: *self.chain_key.expose_secret(),
            counter: self.counter,
            signing_public: self.signing_key.public_key().as_bytes(),
        }
    }

    /// Требуется ли ротация.
    ///
    /// 🔐 Проверяется перед каждой отправкой. Два из шести триггеров
    /// ADR-023 — по числу сообщений и по времени — живут здесь;
    /// остальные четыре (добавление, удаление, смена identity,
    /// ревокация устройства) известны вызывающей стороне, а не протоколу.
    #[must_use]
    pub const fn needs_rotation(&self, now_millis: i64) -> bool {
        if self.counter >= MAX_MESSAGES_PER_KEY {
            return true;
        }

        let age = now_millis.saturating_sub(self.created_at_millis);

        age >= MAX_KEY_AGE_MILLIS
    }

    /// Шифрует сообщение в группу.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — счётчик исчерпан;
    /// [`AegisError::Crypto`] — сбой шифрования или подписи.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<GroupMessage> {
        let counter = self.counter;

        let (next_chain, message_key) = step(self.chain_key.expose_secret())?;

        // Номер входит в аутентифицируемые данные: без этого
        // получатель не заметил бы подмену номера, а по нему он
        // выбирает ключ.
        let ciphertext = MessageKey::new(*message_key).seal(plaintext, &counter.to_be_bytes())?;

        let signature = xeddsa::montgomery::sign(
            &aegis_types::PrivateKeyBytes::new(*self.signing_key.expose_secret().expose_secret()),
            &signed_payload(counter, &ciphertext),
        )?;

        self.chain_key = Secret::new(next_chain);
        self.counter = self.counter.checked_add(1).ok_or(AegisError::Malformed)?;

        Ok(GroupMessage {
            counter,
            ciphertext,
            signature: signature.to_vec(),
        })
    }
}

impl SenderKeyReceiver {
    /// Принимает раздачу ключа от участника.
    #[must_use]
    pub fn from_distribution(distribution: &SenderKeyDistribution) -> Self {
        Self {
            chain_key: Secret::new(distribution.chain_key),
            counter: distribution.counter,
            signing_public: distribution.signing_public,
        }
    }

    /// Расшифровывает групповое сообщение.
    ///
    /// # Про пропущенные сообщения
    ///
    /// Цепочка прокручивается вперёд до нужного номера. Назад она
    /// не отматывается: сообщение с номером меньше текущего означает
    /// либо повтор, либо попытку заставить нас переиспользовать
    /// уже израсходованный ключ.
    ///
    /// # Errors
    ///
    /// [`AegisError::InvalidSignature`] — подпись не сходится:
    /// сообщение отправлено не тем, за кого себя выдают;
    /// [`AegisError::Malformed`] — номер в прошлом или слишком далеко
    /// в будущем;
    /// [`AegisError::Crypto`] — расшифровка не удалась.
    pub fn decrypt(&mut self, message: &GroupMessage) -> Result<Vec<u8>> {
        // 🔐 Подпись проверяется до расшифровки: ключ цепочки знают
        // все участники, поэтому успешная расшифровка сама по себе
        // не доказывает авторства.
        xeddsa::montgomery::verify(
            &self.signing_public,
            &signed_payload(message.counter, &message.ciphertext),
            &message.signature,
        )
        .map_err(|_| AegisError::InvalidSignature)?;

        if message.counter < self.counter {
            return Err(AegisError::Malformed);
        }

        let skip = message.counter.saturating_sub(self.counter);

        // Предел прокрутки: сообщение с номером в миллиард заставило
        // бы считать миллиард шагов HMAC — отказ в обслуживании
        // одним пакетом.
        if skip > MAX_SKIP {
            return Err(AegisError::Malformed);
        }

        let mut chain = *self.chain_key.expose_secret();
        let mut message_key = Zeroizing::new([0u8; CHAIN_KEY_LEN]);

        for _ in 0..=skip {
            let (next, key) = step(&chain)?;
            chain = next;
            message_key = key;
        }

        let plaintext = MessageKey::new(*message_key)
            .open(&message.ciphertext, &message.counter.to_be_bytes())?;

        self.chain_key = Secret::new(chain);
        self.counter = message
            .counter
            .checked_add(1)
            .ok_or(AegisError::Malformed)?;

        Ok(plaintext)
    }
}

/// Предел прокрутки цепочки за одно сообщение.
///
/// Тысяча — столько же, сколько предел сообщений на ключ: дальше
/// отправитель обязан был провести ротацию.
const MAX_SKIP: u32 = MAX_MESSAGES_PER_KEY;

/// Собирает то, что подписывается.
///
/// Номер входит в подпись: без него участник переставил бы сообщения
/// местами, и подписи остались бы подлинными.
fn signed_payload(counter: u32, ciphertext: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(ciphertext.len().saturating_add(4));
    payload.extend_from_slice(&counter.to_be_bytes());
    payload.extend_from_slice(ciphertext);

    payload
}

/// Шаг цепочки: следующий ключ цепочки и ключ сообщения.
fn step(chain_key: &[u8; CHAIN_KEY_LEN]) -> Result<([u8; CHAIN_KEY_LEN], Zeroizing<[u8; 32]>)> {
    let next = hmac_step(chain_key, CHAIN_STEP)?;
    let message = hmac_step(chain_key, MESSAGE_STEP)?;

    Ok((*next, message))
}

/// Один шаг HMAC с меткой.
fn hmac_step(key: &[u8; CHAIN_KEY_LEN], label: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| AegisError::Crypto)?;
    mac.update(label);

    let output = mac.finalize().into_bytes();
    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(&output);

    Ok(result)
}

/// Нужно ли использовать Sender Keys для группы такого размера.
///
/// 🔐 До порога включительно группа шифрует pairwise ради
/// post-compromise security: Sender Keys её не дают, а в маленькой
/// группе цена pairwise приемлема (ADR-023).
#[must_use]
pub const fn use_sender_keys(member_count: usize) -> bool {
    member_count > PAIRWISE_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn now() -> i64 {
        1_700_000_000_000
    }

    #[test]
    fn message_round_trips() {
        let mut sender = SenderKeyState::generate(now(), &mut OsRng);
        let mut receiver = SenderKeyReceiver::from_distribution(&sender.distribution());

        let message = sender.encrypt(b"group message").expect("шифрование");

        assert_eq!(
            receiver.decrypt(&message).expect("расшифровка"),
            b"group message"
        );
    }

    #[test]
    fn multiple_messages_round_trip() {
        let mut sender = SenderKeyState::generate(now(), &mut OsRng);
        let mut receiver = SenderKeyReceiver::from_distribution(&sender.distribution());

        for index in 0..5u8 {
            let payload = [index; 8];
            let message = sender.encrypt(&payload).expect("шифрование");

            assert_eq!(receiver.decrypt(&message).expect("расшифровка"), payload);
        }
    }

    /// 🔐 Сообщение от чужого имени отвергается.
    ///
    /// Главная проверка: ключ цепочки знают все участники, и без
    /// подписи любой из них отправил бы сообщение от чужого имени,
    /// а тег AEAD подтвердил бы только знание ключа.
    #[test]
    fn message_signed_by_another_member_is_rejected() {
        let mut sender = SenderKeyState::generate(now(), &mut OsRng);
        let distribution = sender.distribution();

        // Другой участник знает цепочку — она роздана всем.
        let mut impostor = SenderKeyState::generate(now(), &mut OsRng);
        impostor.chain_key = Secret::new(distribution.chain_key);

        let forged = impostor.encrypt(b"forged").expect("шифрование");

        let mut receiver = SenderKeyReceiver::from_distribution(&distribution);

        assert!(matches!(
            receiver.decrypt(&forged),
            Err(AegisError::InvalidSignature)
        ));

        // Настоящий отправитель по-прежнему проходит.
        let genuine = sender.encrypt(b"genuine").expect("шифрование");
        assert!(receiver.decrypt(&genuine).is_ok());
    }

    /// 🔐 Ушедший участник не читает после ротации.
    ///
    /// Требование ADR-023: `test_removed_member_cannot_decrypt_after_rotation`.
    #[test]
    fn removed_member_cannot_decrypt_after_rotation() {
        let mut sender = SenderKeyState::generate(now(), &mut OsRng);

        // Участник получил ключ, пока состоял в группе.
        let mut removed = SenderKeyReceiver::from_distribution(&sender.distribution());

        let before = sender.encrypt(b"before removal").expect("шифрование");
        assert!(removed.decrypt(&before).is_ok());

        // Состав изменился — ротация.
        let mut rotated = SenderKeyState::generate(now(), &mut OsRng);
        let after = rotated.encrypt(b"after removal").expect("шифрование");

        assert!(
            removed.decrypt(&after).is_err(),
            "ушедший участник прочитал сообщение после ротации"
        );
    }

    /// Пропущенные сообщения не мешают расшифровать более поздние.
    #[test]
    fn skipped_messages_are_tolerated() {
        let mut sender = SenderKeyState::generate(now(), &mut OsRng);
        let mut receiver = SenderKeyReceiver::from_distribution(&sender.distribution());

        let _lost = sender.encrypt(b"lost").expect("шифрование");
        let delivered = sender.encrypt(b"delivered").expect("шифрование");

        assert_eq!(
            receiver.decrypt(&delivered).expect("расшифровка"),
            b"delivered"
        );
    }

    /// 🔐 Повтор сообщения отвергается.
    ///
    /// Иначе перехваченное сообщение можно было бы проиграть заново,
    /// и участники увидели бы его дважды.
    #[test]
    fn replayed_message_is_rejected() {
        let mut sender = SenderKeyState::generate(now(), &mut OsRng);
        let mut receiver = SenderKeyReceiver::from_distribution(&sender.distribution());

        let message = sender.encrypt(b"once").expect("шифрование");

        assert!(receiver.decrypt(&message).is_ok());
        assert!(receiver.decrypt(&message).is_err(), "повтор прошёл");
    }

    /// Огромный номер отвергается без прокрутки цепочки.
    ///
    /// Иначе одно сообщение заставило бы считать миллиард шагов HMAC.
    #[test]
    fn absurd_counter_is_rejected() {
        let mut sender = SenderKeyState::generate(now(), &mut OsRng);
        let mut receiver = SenderKeyReceiver::from_distribution(&sender.distribution());

        let mut message = sender.encrypt(b"payload").expect("шифрование");
        message.counter = u32::MAX;

        assert!(receiver.decrypt(&message).is_err());
    }

    /// Подмена номера отвергается.
    #[test]
    fn counter_tampering_is_detected() {
        let mut sender = SenderKeyState::generate(now(), &mut OsRng);
        let mut receiver = SenderKeyReceiver::from_distribution(&sender.distribution());

        let mut message = sender.encrypt(b"payload").expect("шифрование");
        message.counter = 5;

        assert!(receiver.decrypt(&message).is_err());
    }

    /// Ротация требуется после предела сообщений.
    #[test]
    fn rotation_required_after_message_limit() {
        let mut sender = SenderKeyState::generate(now(), &mut OsRng);

        assert!(!sender.needs_rotation(now()));

        sender.counter = MAX_MESSAGES_PER_KEY;

        assert!(sender.needs_rotation(now()));
    }

    /// Ротация требуется после предела возраста.
    #[test]
    fn rotation_required_after_age_limit() {
        let sender = SenderKeyState::generate(now(), &mut OsRng);

        assert!(!sender.needs_rotation(now() + MAX_KEY_AGE_MILLIS - 1));
        assert!(sender.needs_rotation(now() + MAX_KEY_AGE_MILLIS));
    }

    /// Порог перехода на Sender Keys соответствует ADR-023.
    #[test]
    fn pairwise_threshold_matches_adr() {
        assert!(!use_sender_keys(2));
        assert!(!use_sender_keys(PAIRWISE_THRESHOLD));
        assert!(use_sender_keys(PAIRWISE_THRESHOLD + 1));
    }

    /// Метки цепочки отличаются от меток Double Ratchet.
    ///
    /// Одинаковые метки при одинаковом входе дали бы одинаковые ключи
    /// в двух подсистемах, и компрометация одной раскрыла бы другую.
    #[test]
    fn labels_are_distinct_from_ratchet() {
        assert_ne!(CHAIN_STEP, b"AEGIS_RATCHET_CHAIN_v1");
        assert_ne!(CHAIN_STEP, MESSAGE_STEP);
    }
}
