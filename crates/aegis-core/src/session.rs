// SPDX-License-Identifier: Apache-2.0

//! Оркестрация сессий: от prekey bundle до расшифрованного сообщения.
//!
//! # Что делает этот модуль
//!
//! Соединяет готовые части в последовательность, которую невозможно
//! выполнить по частям правильно:
//!
//! ```text
//! отправка:  bundle -> PQXDH::initiate -> Ratchet::initiate
//!                   -> encrypt -> Envelope::Initial -> сеть
//! приём:     сеть -> Envelope -> PQXDH::respond -> Ratchet::accept
//!                 -> decrypt -> хранилище
//! ```
//!
//! # Почему оркестрация отдельно от протокола
//!
//! `aegis-protocol` не ходит ни в сеть, ни на диск — это условие его
//! тестируемости и фаззинга. Но кто-то обязан знать, что после
//! `initiate` нужно сохранить сессию, вычеркнуть израсходованный
//! предключ и только потом отправлять. Этот «кто-то» и есть здесь.
//!
//! # Про порядок сохранения
//!
//! Сессия сохраняется **до** отправки в сеть. Обратный порядок терял
//! бы состояние храповика при обрыве связи после успешной отправки:
//! получатель продвинул бы цепочку, а отправитель — нет, и переписка
//! встала бы навсегда.

use aegis_protocol::double_ratchet::RatchetState;
use aegis_protocol::envelope::Envelope;
use aegis_protocol::keys::{IdentityKeyPair, PreKeyBundle, PreKeyId};
use aegis_protocol::pqxdh::{self, KemPreKeyChoice, ResponderKeys};
use aegis_protocol::prekeys::PreKeySecrets;
use aegis_protocol::x25519::{X25519PrivateKey, X25519PublicKey};
use aegis_types::{AegisError, ChatId, Plaintext, PublicKeyBytes, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

/// Результат подготовки исходящего сообщения.
#[derive(Debug)]
pub struct OutgoingMessage {
    /// Байты конверта для отправки на сервер.
    pub envelope: Vec<u8>,
    /// Состояние сессии после шифрования — подлежит сохранению.
    pub session: aegis_protocol::keys::SessionState,
    /// Была ли ослаблена forward secrecy из-за исчерпания предключей.
    ///
    /// Показывается в Security Center: систематическое исчерпание
    /// может означать, что кто-то намеренно вычерпывает предключи
    /// собеседника, чтобы ослабить первое сообщение.
    pub degraded: bool,
}

/// Результат разбора входящего сообщения.
#[derive(Debug)]
pub struct IncomingMessage {
    /// Расшифрованный текст.
    pub plaintext: Plaintext,
    /// Состояние сессии после расшифровки — подлежит сохранению.
    pub session: aegis_protocol::keys::SessionState,
    /// Identity-ключ отправителя, если сессия только что установлена.
    ///
    /// Нужен вызывающей стороне, чтобы сверить его с известным ключом
    /// контакта и поднять тревогу при смене (см. `identity_change_alert`).
    pub sender_identity: Option<PublicKeyBytes>,
    /// Израсходованный одноразовый предключ: его следует вычеркнуть.
    pub consumed_one_time: Option<PreKeyId>,
    /// Израсходованный одноразовый пост-квантовый предключ.
    pub consumed_one_time_kem: Option<PreKeyId>,
}

/// Начинает новую сессию и шифрует первое сообщение.
///
/// # Errors
///
/// [`AegisError::InvalidSignature`] — подписи в bundle не сходятся
/// с identity-ключом владельца. Это либо подмена на сервере, либо
/// повреждение: мягкого режима нет.
///
/// Прочие ошибки протокола пробрасываются как есть.
pub fn start_session<R: RngCore + CryptoRng>(
    our_identity: &IdentityKeyPair,
    their_bundle: &PreKeyBundle,
    plaintext: &Plaintext,
    rng: &mut R,
) -> Result<OutgoingMessage> {
    // PQXDH проверяет подписи bundle внутри себя — до всякого
    // использования ключей.
    let output = pqxdh::initiate(our_identity, their_bundle, rng)?;

    // Храповик стартует от подписанного предключа получателя: это
    // единственный его публичный ключ, который мы знаем на этот момент.
    let their_ratchet = X25519PublicKey::from_bytes(their_bundle.signed_pre_key.public)?;
    let mut ratchet =
        RatchetState::initiate(output.shared_secret.expose_secret(), &their_ratchet, rng)?;

    let ciphertext = ratchet.encrypt(plaintext)?;

    let (kem_pre_key_id, kem_one_time) = match output.kem_choice {
        KemPreKeyChoice::OneTime(id) => (id, true),
        KemPreKeyChoice::Signed(id) => (id, false),
    };

    let envelope = Envelope::Initial {
        identity_key: *our_identity.public().public(),
        ephemeral_key: output.ephemeral_public,
        kem_ciphertext: output.kem_ciphertext,
        one_time_pre_key_id: output.one_time_pre_key_id,
        kem_pre_key_id,
        kem_one_time,
        payload: ciphertext.into_bytes(),
    };

    Ok(OutgoingMessage {
        envelope: envelope.to_bytes()?,
        session: ratchet.serialize(),
        degraded: output.degraded,
    })
}

/// Шифрует сообщение в уже установленной сессии.
///
/// # Errors
///
/// Ошибки восстановления состояния сессии или шифрования.
pub fn continue_session(
    session: &aegis_protocol::keys::SessionState,
    plaintext: &Plaintext,
) -> Result<OutgoingMessage> {
    let mut ratchet = RatchetState::deserialize(session)?;
    let ciphertext = ratchet.encrypt(plaintext)?;

    let envelope = Envelope::Message {
        payload: ciphertext.into_bytes(),
    };

    Ok(OutgoingMessage {
        envelope: envelope.to_bytes()?,
        session: ratchet.serialize(),
        // Ослабление касается только первого сообщения: дальше
        // forward secrecy обеспечивает сам храповик.
        degraded: false,
    })
}

/// Разбирает входящий конверт.
///
/// `session` — состояние существующей сессии, если она есть. Для
/// конверта инициации оно не нужно и игнорируется: отправитель мог
/// начать сессию заново, потеряв своё состояние.
///
/// # Errors
///
/// [`AegisError::SessionNotFound`] — пришло сообщение в сессии,
/// которой у нас нет. Ошибка отдельная, потому что реакция на неё
/// особая: сессию нужно переустановить, а не показывать сбой.
///
/// [`AegisError::Malformed`] — конверт не разбирается.
///
/// [`AegisError::Crypto`] — расшифровка не удалась. Это может быть
/// как повреждение, так и подделка, и различать их для пользователя
/// смысла нет.
pub fn receive(
    our_identity: &IdentityKeyPair,
    secrets: &PreKeySecrets,
    session: Option<&aegis_protocol::keys::SessionState>,
    raw_envelope: &[u8],
    now: Timestamp,
) -> Result<IncomingMessage> {
    match Envelope::from_bytes(raw_envelope)? {
        Envelope::Initial {
            identity_key,
            ephemeral_key,
            kem_ciphertext,
            one_time_pre_key_id,
            kem_pre_key_id,
            kem_one_time,
            payload,
        } => accept_initial(
            our_identity,
            secrets,
            &identity_key,
            &ephemeral_key,
            &kem_ciphertext,
            one_time_pre_key_id,
            kem_pre_key_id,
            kem_one_time,
            &payload,
            now,
        ),
        Envelope::Message { payload } => {
            let state = session.ok_or(AegisError::SessionNotFound)?;
            let mut ratchet = RatchetState::deserialize(state)?;
            let plaintext = ratchet.decrypt(&aegis_types::Ciphertext::new(payload), now)?;

            Ok(IncomingMessage {
                plaintext,
                session: ratchet.serialize(),
                sender_identity: None,
                consumed_one_time: None,
                consumed_one_time_kem: None,
            })
        }
    }
}

/// Принимает первое сообщение и устанавливает сессию.
#[allow(clippy::too_many_arguments)]
fn accept_initial(
    our_identity: &IdentityKeyPair,
    secrets: &PreKeySecrets,
    sender_identity: &PublicKeyBytes,
    ephemeral_key: &PublicKeyBytes,
    kem_ciphertext: &[u8],
    one_time_pre_key_id: Option<PreKeyId>,
    kem_pre_key_id: PreKeyId,
    kem_one_time: bool,
    payload: &[u8],
    now: Timestamp,
) -> Result<IncomingMessage> {
    // Приватная часть одноразового предключа ищется по идентификатору,
    // который прислал отправитель. Отсутствие — не ошибка формата,
    // а признак повтора: этот предключ уже израсходован.
    let one_time = match one_time_pre_key_id {
        Some(id) => Some(find_one_time(secrets, id)?),
        None => None,
    };

    let one_time_kem = if kem_one_time {
        Some(find_one_time_kem(secrets, kem_pre_key_id)?)
    } else {
        None
    };

    // 🔐 Подписанный предключ перебирается: текущий, затем выведенные.
    //
    // Отправитель мог забрать bundle до ротации, а сообщение прочитано
    // после неё. Прежде ротация затирала ключ на месте, и такое
    // начальное сообщение не расшифровывалось никогда — вместе со всей
    // перепиской, которая за ним шла. Идентификатора подписанного
    // ключа в конверте нет, поэтому выбор — пробой: неверная пара
    // честно не проходит проверку AEAD первого сообщения.
    let candidates = core::iter::once((&secrets.signed_pre_key, &secrets.signed_kem)).chain(
        secrets
            .retired_signed
            .iter()
            .map(|retired| (&retired.signed_pre_key, &retired.signed_kem)),
    );

    let mut first_failure = None;

    for (signed_pre_key, signed_kem) in candidates {
        match try_accept(
            our_identity,
            signed_pre_key,
            one_time,
            one_time_kem.unwrap_or(signed_kem),
            sender_identity,
            ephemeral_key,
            kem_ciphertext,
            payload,
            now,
        ) {
            Ok((plaintext, ratchet)) => {
                return Ok(IncomingMessage {
                    plaintext,
                    session: ratchet.serialize(),
                    sender_identity: Some(*sender_identity),
                    consumed_one_time: one_time_pre_key_id,
                    consumed_one_time_kem: kem_one_time.then_some(kem_pre_key_id),
                });
            }
            Err(error) => {
                first_failure.get_or_insert(error);
            }
        }
    }

    Err(first_failure.unwrap_or(AegisError::Crypto))
}

/// Одна попытка принять начальное сообщение с данной парой ключей.
#[allow(clippy::too_many_arguments)]
fn try_accept(
    our_identity: &IdentityKeyPair,
    signed_pre_key: &X25519PrivateKey,
    one_time: Option<&X25519PrivateKey>,
    kem_pre_key: &aegis_protocol::mlkem::MlKem1024PrivateKey,
    sender_identity: &PublicKeyBytes,
    ephemeral_key: &PublicKeyBytes,
    kem_ciphertext: &[u8],
    payload: &[u8],
    now: Timestamp,
) -> Result<(aegis_types::Plaintext, RatchetState)> {
    let shared = pqxdh::respond(
        &ResponderKeys {
            identity: our_identity,
            signed_pre_key,
            one_time_pre_key: one_time,
            kem_pre_key,
        },
        sender_identity,
        ephemeral_key,
        kem_ciphertext,
    )?;

    // Наша сторона храповика стартует от подписанного предключа:
    // именно его отправитель использовал как их публичный ключ.
    let our_ratchet = X25519PrivateKey::from_bytes(signed_pre_key.expose_secret())?;
    let mut ratchet = RatchetState::accept(shared.expose_secret(), our_ratchet);

    let plaintext = ratchet.decrypt(&aegis_types::Ciphertext::new(payload.to_vec()), now)?;

    Ok((plaintext, ratchet))
}

/// Находит приватную часть одноразового предключа.
fn find_one_time(secrets: &PreKeySecrets, id: PreKeyId) -> Result<&X25519PrivateKey> {
    secrets
        .one_time
        .iter()
        .find(|(key_id, _)| *key_id == id)
        .map(|(_, key)| key)
        // Предключ уже израсходован: либо это повтор старого конверта,
        // либо отправитель использовал ключ дважды. В обоих случаях
        // принимать сообщение нельзя — одноразовый предключ на то и
        // одноразовый.
        .ok_or(AegisError::SessionNotFound)
}

/// Находит приватную часть одноразового пост-квантового предключа.
fn find_one_time_kem(
    secrets: &PreKeySecrets,
    id: PreKeyId,
) -> Result<&aegis_protocol::mlkem::MlKem1024PrivateKey> {
    secrets
        .one_time_kem
        .iter()
        .find(|(key_id, _)| *key_id == id)
        .map(|(_, key)| key)
        .ok_or(AegisError::SessionNotFound)
}

/// Выводит идентификатор чата из идентификаторов собеседников.
///
/// Детерминированный и симметричный: обе стороны обязаны получить
/// один и тот же идентификатор, иначе сообщения разойдутся по разным
/// чатам. Сортировка байтов и даёт эту симметрию.
#[must_use]
pub fn derive_chat_id(a: &PublicKeyBytes, b: &PublicKeyBytes) -> ChatId {
    use sha2::{Digest, Sha256};

    let (first, second) = if a.as_bytes() <= b.as_bytes() {
        (a, b)
    } else {
        (b, a)
    };

    let mut hasher = Sha256::new();
    hasher.update(b"AEGIS_CHAT_ID_v1");
    hasher.update(first.as_bytes());
    hasher.update(second.as_bytes());
    let digest = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(digest.get(..16).unwrap_or(&[0u8; 16]));

    ChatId::from_uuid(uuid::Uuid::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_protocol::prekeys;
    use aegis_types::DeviceId;
    use rand_core::OsRng;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    /// Полный цикл: Алиса начинает сессию, Боб читает сообщение.
    #[test]
    fn alice_and_bob_exchange_first_message() {
        let alice = prekeys::generate_identity(&mut OsRng).expect("identity");
        let bob = prekeys::generate_identity(&mut OsRng).expect("identity");

        let (bundle, secrets) =
            prekeys::generate(&bob, DeviceId::generate(), now(), &mut OsRng).expect("предключи");

        let text = Plaintext::new(b"attack at dawn".to_vec());
        let outgoing = start_session(&alice, &bundle, &text, &mut OsRng).expect("сессия начата");

        let incoming =
            receive(&bob, &secrets, None, &outgoing.envelope, now()).expect("сообщение принято");

        assert_eq!(incoming.plaintext.expose(), text.expose());
        assert_eq!(
            incoming.sender_identity.expect("identity отправителя"),
            *alice.public().public()
        );
    }

    /// Переписка продолжается в обе стороны.
    ///
    /// Односторонняя проверка пропустила бы дефект в приёмной цепочке
    /// храповика: она задействуется только когда отвечает вторая сторона.
    #[test]
    fn conversation_continues_in_both_directions() {
        let alice = prekeys::generate_identity(&mut OsRng).expect("identity");
        let bob = prekeys::generate_identity(&mut OsRng).expect("identity");

        let (bundle, secrets) =
            prekeys::generate(&bob, DeviceId::generate(), now(), &mut OsRng).expect("предключи");

        let first = Plaintext::new(b"first".to_vec());
        let outgoing = start_session(&alice, &bundle, &first, &mut OsRng).expect("сессия");
        let mut alice_session = outgoing.session;

        let received = receive(&bob, &secrets, None, &outgoing.envelope, now()).expect("приём");
        assert_eq!(received.plaintext.expose(), first.expose());
        let mut bob_session = received.session;

        // Боб отвечает.
        let reply = Plaintext::new(b"reply".to_vec());
        let bob_out = continue_session(&bob_session, &reply).expect("ответ зашифрован");
        bob_session = bob_out.session;

        let alice_in = receive(
            &alice,
            &secrets,
            Some(&alice_session),
            &bob_out.envelope,
            now(),
        )
        .expect("Алиса читает ответ");
        assert_eq!(alice_in.plaintext.expose(), reply.expose());
        alice_session = alice_in.session;

        // И ещё один круг: храповик должен продолжать проворачиваться.
        let second = Plaintext::new(b"second".to_vec());
        let alice_out = continue_session(&alice_session, &second).expect("второе сообщение");

        let bob_in = receive(
            &bob,
            &secrets,
            Some(&bob_session),
            &alice_out.envelope,
            now(),
        )
        .expect("Боб читает второе");
        assert_eq!(bob_in.plaintext.expose(), second.expose());
    }

    /// 🔐 Открытый текст не появляется в конверте.
    ///
    /// Самая дешёвая и самая тяжёлая ошибка: конверт уходит на сервер,
    /// и текст в нём означал бы, что шифрования нет вовсе.
    #[test]
    fn envelope_carries_no_plaintext() {
        let alice = prekeys::generate_identity(&mut OsRng).expect("identity");
        let bob = prekeys::generate_identity(&mut OsRng).expect("identity");

        let (bundle, _) =
            prekeys::generate(&bob, DeviceId::generate(), now(), &mut OsRng).expect("предключи");

        let canary = b"ATTACK-AT-DAWN-CANARY";
        let outgoing = start_session(
            &alice,
            &bundle,
            &Plaintext::new(canary.to_vec()),
            &mut OsRng,
        )
        .expect("сессия");

        assert!(
            !outgoing
                .envelope
                .windows(canary.len())
                .any(|window| window == canary),
            "открытый текст найден в конверте"
        );
    }

    /// Повторное использование одноразового предключа отвергается.
    ///
    /// Иначе перехваченный конверт можно было бы проиграть заново,
    /// а forward secrecy первого сообщения исчезла бы.
    #[test]
    fn replayed_one_time_prekey_is_rejected() {
        let alice = prekeys::generate_identity(&mut OsRng).expect("identity");
        let bob = prekeys::generate_identity(&mut OsRng).expect("identity");

        let (bundle, secrets) =
            prekeys::generate(&bob, DeviceId::generate(), now(), &mut OsRng).expect("предключи");

        let outgoing = start_session(
            &alice,
            &bundle,
            &Plaintext::new(b"once".to_vec()),
            &mut OsRng,
        )
        .expect("сессия");

        let first = receive(&bob, &secrets, None, &outgoing.envelope, now());
        assert!(first.is_ok(), "первый приём должен пройти");

        // Вычёркиваем израсходованный предключ, как это делает
        // вызывающая сторона, и повторяем тот же конверт.
        let consumed = first
            .expect("первый приём")
            .consumed_one_time
            .expect("одноразовый предключ был использован");

        let mut depleted =
            PreKeySecrets::from_bytes(&secrets.to_bytes().expect("сериализация")).expect("разбор");
        depleted.one_time.retain(|(id, _)| *id != consumed);

        assert!(
            receive(&bob, &depleted, None, &outgoing.envelope, now()).is_err(),
            "повтор конверта прошёл после расходования предключа"
        );
    }

    /// Идентификатор чата одинаков с обеих сторон.
    #[test]
    fn chat_id_is_symmetric() {
        let a = PublicKeyBytes::new([0x11; 32]);
        let b = PublicKeyBytes::new([0x22; 32]);

        assert_eq!(derive_chat_id(&a, &b), derive_chat_id(&b, &a));
        assert_ne!(derive_chat_id(&a, &b), derive_chat_id(&a, &a));
    }

    /// Сообщение без сессии даёт отдельную ошибку.
    ///
    /// Отличать «сессии нет» от «расшифровать не удалось» важно:
    /// в первом случае сессию нужно переустановить, во втором —
    /// поднимать тревогу.
    #[test]
    fn message_without_session_is_reported_as_missing_session() {
        let bob = prekeys::generate_identity(&mut OsRng).expect("identity");
        let (_, secrets) =
            prekeys::generate(&bob, DeviceId::generate(), now(), &mut OsRng).expect("предключи");

        let envelope = Envelope::Message {
            payload: vec![0u8; 64],
        }
        .to_bytes()
        .expect("конверт");

        assert!(matches!(
            receive(&bob, &secrets, None, &envelope, now()),
            Err(AegisError::SessionNotFound)
        ));
    }
}
