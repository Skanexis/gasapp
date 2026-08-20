// SPDX-License-Identifier: Apache-2.0

//! Единственная реализация [`ProtocolEngine`] — сборка трёх храповиков.
//!
//! # Почему движок один
//!
//! PQXDH, Double Ratchet и SPQR — не три взаимозаменяемых движка, а три
//! **этапа одного протокола**: начальный обмен, продвижение ключей и
//! пост-квантовая составляющая. В первой редакции каждый из них реализовывал
//! `ProtocolEngine` отдельно и с несовпадающими сигнатурами, из-за чего трейт
//! переставал описывать протокол целиком (дефект #4 раздела 23.0.1).
//!
//! Здесь они собраны в один тип. Трейт остаётся точкой переключения
//! реализаций из ADR-005: вторая реализация — обёртка над libsignal —
//! появится, только если аудит собственной не будет профинансирован.
//!
//! # Что движок не делает
//!
//! Не ходит в хранилище и не берёт время из системных часов. Приватные
//! предключи получателя и отметка времени передаются снаружи: движок
//! обязан быть чистым, иначе его поведение невоспроизводимо в тестах
//! (раздел 9.2 плана).

use aegis_types::{AegisError, Ciphertext, Plaintext, Result, Timestamp};
use rand_core::CryptoRngCore;

use crate::{
    double_ratchet::RatchetState,
    engine::{InitialMessage, InitiatedSession, ProtocolEngine},
    keys::{IdentityKey, IdentityKeyPair, PreKeyBundle, SessionState},
    pqxdh::{self, ResponderKeys},
    spqr,
    x25519::X25519PublicKey,
    Fingerprint, ProtocolVersion,
};

/// Криптографический движок AEGIS.
///
/// Тип без состояния: всё состояние сессии живёт в [`SessionState`],
/// который передаётся аргументом. Благодаря этому один экземпляр движка
/// обслуживает произвольное число сессий и безопасно используется
/// из нескольких потоков.
#[derive(Clone, Copy, Debug, Default)]
pub struct AegisEngine;

impl AegisEngine {
    /// Создаёт движок.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Устанавливает сессию как получатель, имея свои приватные предключи.
    ///
    /// Отдельный метод, а не часть [`ProtocolEngine`]: трейт не передаёт
    /// приватных предключей, потому что они лежат в хранилище, а движок
    /// в хранилище не ходит. Вызывающая сторона (`aegis-core`) достаёт их
    /// по идентификаторам из входящего сообщения и передаёт сюда.
    ///
    /// # Errors
    ///
    /// * [`AegisError::UnsupportedProtocolVersion`] — попытка понижения версии.
    /// * [`AegisError::Malformed`] — сообщение короче ожидаемого.
    /// * [`AegisError::Crypto`] — сбой декапсуляции или вывода ключей.
    pub fn accept_session_with_keys(
        &self,
        keys: &ResponderKeys<'_>,
        message: &InitialMessage,
        initiator_identity: &IdentityKey,
    ) -> Result<SessionState> {
        spqr::ensure_post_quantum(message.version)?;

        let payload = message.payload.as_bytes();
        let ephemeral = payload
            .get(..32)
            .and_then(|slice| <[u8; 32]>::try_from(slice).ok())
            .ok_or(AegisError::Malformed)?;
        let kem_ciphertext = payload.get(32..).ok_or(AegisError::Malformed)?;

        let shared = pqxdh::respond(
            keys,
            initiator_identity.public(),
            &aegis_types::PublicKeyBytes::new(ephemeral),
            kem_ciphertext,
        )?;

        // Получатель ведёт храповик на своём подписанном предключе: именно
        // его публичную часть инициатор взял из bundle.
        let our_ratchet =
            crate::x25519::X25519PrivateKey::from_bytes(keys.signed_pre_key.expose_secret())?;
        let state = RatchetState::accept(shared.expose_secret(), our_ratchet);

        Ok(state.serialize())
    }

    /// Расшифровывает сообщение с явной отметкой времени.
    ///
    /// Отдельный метод по той же причине, что и выше: [`ProtocolEngine`]
    /// не передаёт время, а TTL пропущенных ключей без него не проверить.
    ///
    /// # Errors
    ///
    /// Те же, что у [`ProtocolEngine::decrypt`].
    pub fn decrypt_at(
        &self,
        session: &mut SessionState,
        ciphertext: &Ciphertext,
        now: Timestamp,
    ) -> Result<Plaintext> {
        let mut state = RatchetState::deserialize(session)?;
        let plaintext = state.decrypt(ciphertext, now)?;
        *session = state.serialize();

        Ok(plaintext)
    }
}

impl ProtocolEngine for AegisEngine {
    fn initiate_session(
        &self,
        our_identity: &IdentityKeyPair,
        their_bundle: &PreKeyBundle,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<InitiatedSession> {
        // `pqxdh::initiate` требует обобщённый `R: RngCore + CryptoRng`,
        // объектом трейта его не удовлетворить — отсюда обёртка.
        let mut rng = DynRng(rng);

        let output = pqxdh::initiate(our_identity, their_bundle, &mut rng)?;

        // Храповик стартует на подписанном предключе получателя — том же,
        // что участвовал в PQXDH.
        let their_ratchet = X25519PublicKey::from_bytes(their_bundle.signed_pre_key.public)?;
        let state = RatchetState::initiate(
            output.shared_secret.expose_secret(),
            &their_ratchet,
            &mut rng,
        )?;

        // Полезная нагрузка PREKEY-сообщения: эфемерный ключ инициатора
        // и инкапсуляция ML-KEM. Получатель разбирает её в
        // `accept_session_with_keys`.
        let mut payload = Vec::with_capacity(32usize.saturating_add(output.kem_ciphertext.len()));
        payload.extend_from_slice(output.ephemeral_public.as_bytes());
        payload.extend_from_slice(&output.kem_ciphertext);

        Ok(InitiatedSession {
            session: state.serialize(),
            message: InitialMessage {
                version: ProtocolVersion::CURRENT,
                payload: Ciphertext::new(payload),
            },
            degraded: output.degraded,
        })
    }

    fn accept_session(
        &self,
        _our_identity: &IdentityKeyPair,
        message: &InitialMessage,
    ) -> Result<(SessionState, Plaintext)> {
        // Проверка версии выполняется даже здесь, где дальше следует отказ:
        // downgrade должен отвергаться раньше всего остального.
        spqr::ensure_post_quantum(message.version)?;

        // Без приватных предключей получателя обмен невозможен, а трейт их
        // не передаёт. Возвращается `Uninitialized`, а не `Crypto`: это
        // ошибка порядка вызовов, а не сбой криптографии.
        //
        // Рабочий путь — `AegisEngine::accept_session_with_keys`.
        Err(AegisError::Uninitialized)
    }

    fn encrypt(&self, session: &mut SessionState, plaintext: &Plaintext) -> Result<Ciphertext> {
        let mut state = RatchetState::deserialize(session)?;
        let ciphertext = state.encrypt(plaintext)?;
        *session = state.serialize();

        Ok(ciphertext)
    }

    fn decrypt(&self, session: &mut SessionState, ciphertext: &Ciphertext) -> Result<Plaintext> {
        // Время не передаётся трейтом, поэтому TTL пропущенных ключей здесь
        // не истекает: используется нулевая отметка, при которой ни один
        // ключ не считается просроченным. Путь с реальным временем —
        // `AegisEngine::decrypt_at`.
        self.decrypt_at(session, ciphertext, Timestamp::from_millis(0))
    }

    fn fingerprint(&self, identity: &IdentityKey, identifier: &[u8]) -> Result<Fingerprint> {
        Ok(Fingerprint::compute(identity.public(), identifier))
    }
}

/// Придаёт `&mut dyn CryptoRngCore` конкретный тип.
///
/// Функции протокола требуют `R: RngCore + CryptoRng` — обобщённый параметр,
/// который объектом трейта не удовлетворить напрямую. Обёртка переносит
/// вызовы на тот же источник, ничего не добавляя и не подменяя.
struct DynRng<'a>(&'a mut dyn CryptoRngCore);

impl rand_core::RngCore for DynRng<'_> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

// Источник заявлен криптографическим на уровне типа `CryptoRngCore`,
// обёртка это свойство сохраняет.
impl rand_core::CryptoRng for DynRng<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keys::{KemPublicKey, PreKeyId, SignedKemPreKey, SignedPreKey},
        mlkem::MlKem1024PrivateKey,
        x25519::X25519PrivateKey,
        xeddsa,
    };
    use aegis_types::{DeviceId, PrivateKeyBytes, Secret};
    use rand_core::OsRng;

    /// Комплект ключей получателя: публичный bundle и приватные части.
    struct Responder {
        identity: IdentityKeyPair,
        signed_pre_key: X25519PrivateKey,
        signed_kem: MlKem1024PrivateKey,
    }

    fn generate_identity() -> IdentityKeyPair {
        let private = X25519PrivateKey::generate(&mut OsRng);
        let private_bytes = private.expose_secret();
        let public = xeddsa::montgomery::public_key(&private_bytes).unwrap();

        IdentityKeyPair::new(
            IdentityKey::new(public),
            Secret::new(*private_bytes.expose_secret()),
        )
    }

    impl Responder {
        fn generate() -> Self {
            Self {
                identity: generate_identity(),
                signed_pre_key: X25519PrivateKey::generate(&mut OsRng),
                signed_kem: MlKem1024PrivateKey::generate(&mut OsRng),
            }
        }

        fn sign(&self, message: &[u8]) -> Vec<u8> {
            let private = PrivateKeyBytes::new(*self.identity.private().expose_secret());

            xeddsa::montgomery::sign(&private, message)
                .unwrap()
                .to_vec()
        }

        fn bundle(&self) -> PreKeyBundle {
            let spk_public = self.signed_pre_key.public_key().as_bytes();
            let kem_public = self.signed_kem.public_key().as_bytes();

            PreKeyBundle {
                device_id: DeviceId::generate(),
                identity_key: *self.identity.public(),
                signed_pre_key: SignedPreKey {
                    id: PreKeyId::new(1),
                    public: spk_public,
                    signature: self.sign(spk_public.as_bytes()),
                },
                // Одноразовые предключи опущены: PQXDH это допускает,
                // помечая bundle как degraded.
                one_time_pre_key: None,
                signed_kem_pre_key: SignedKemPreKey {
                    id: PreKeyId::new(2),
                    public: KemPublicKey::new(kem_public.clone()),
                    signature: self.sign(&kem_public),
                },
                one_time_kem_pre_key: None,
            }
        }
    }

    /// 🔐 Полный путь через трейт: установление сессии и обмен сообщением.
    ///
    /// Это проверка того, что три храповика действительно собраны в один
    /// работающий движок, а не просто лежат рядом в крейте.
    #[test]
    fn full_session_through_the_trait() {
        let engine = AegisEngine::new();
        let initiator = generate_identity();
        let responder = Responder::generate();
        let bundle = responder.bundle();

        // Инициатор устанавливает сессию.
        let mut initiated = engine
            .initiate_session(&initiator, &bundle, &mut OsRng)
            .unwrap();

        assert!(initiated.degraded, "bundle без одноразовых предключей");

        // Получатель принимает её, имея свои приватные предключи.
        let keys = ResponderKeys {
            identity: &responder.identity,
            signed_pre_key: &responder.signed_pre_key,
            one_time_pre_key: None,
            kem_pre_key: &responder.signed_kem,
        };
        let mut accepted = engine
            .accept_session_with_keys(&keys, &initiated.message, initiator.public())
            .unwrap();

        // Инициатор шифрует, получатель расшифровывает.
        let plaintext = Plaintext::new(b"hello over the trait".to_vec());
        let ciphertext = engine.encrypt(&mut initiated.session, &plaintext).unwrap();

        let decrypted = engine
            .decrypt_at(&mut accepted, &ciphertext, Timestamp::from_millis(1))
            .unwrap();

        assert_eq!(decrypted.expose(), b"hello over the trait");
    }

    /// Сессия продолжается: несколько сообщений подряд.
    #[test]
    fn multiple_messages_through_the_trait() {
        let engine = AegisEngine::new();
        let initiator = generate_identity();
        let responder = Responder::generate();

        let mut initiated = engine
            .initiate_session(&initiator, &responder.bundle(), &mut OsRng)
            .unwrap();

        let keys = ResponderKeys {
            identity: &responder.identity,
            signed_pre_key: &responder.signed_pre_key,
            one_time_pre_key: None,
            kem_pre_key: &responder.signed_kem,
        };
        let mut accepted = engine
            .accept_session_with_keys(&keys, &initiated.message, initiator.public())
            .unwrap();

        for round in 0..5u8 {
            let payload = vec![round; 32];
            let ciphertext = engine
                .encrypt(&mut initiated.session, &Plaintext::new(payload.clone()))
                .unwrap();
            let decrypted = engine
                .decrypt_at(&mut accepted, &ciphertext, Timestamp::from_millis(1))
                .unwrap();

            assert_eq!(decrypted.expose(), payload.as_slice());
        }
    }

    /// 🔐 Подменённый bundle отвергается движком.
    ///
    /// Аутентификация предключей работает и через трейт, а не только
    /// при прямом вызове `pqxdh::initiate`.
    #[test]
    fn tampered_bundle_is_rejected_through_the_trait() {
        let engine = AegisEngine::new();
        let initiator = generate_identity();
        let responder = Responder::generate();

        let mut bundle = responder.bundle();
        bundle.signed_pre_key.public = X25519PrivateKey::generate(&mut OsRng)
            .public_key()
            .as_bytes();

        assert!(matches!(
            engine.initiate_session(&initiator, &bundle, &mut OsRng),
            Err(AegisError::InvalidSignature)
        ));
    }

    /// 🔐 Downgrade отвергается при приёме сессии.
    #[test]
    fn downgrade_is_rejected_on_accept() {
        let engine = AegisEngine::new();
        let responder = Responder::generate();

        // Версия 0 не разбирается в принципе, поэтому downgrade
        // невозможно даже выразить корректным `ProtocolVersion`.
        assert!(ProtocolVersion::parse(0).is_err());

        let keys = ResponderKeys {
            identity: &responder.identity,
            signed_pre_key: &responder.signed_pre_key,
            one_time_pre_key: None,
            kem_pre_key: &responder.signed_kem,
        };

        // Пустая нагрузка отвергается как повреждённая, а не паникует.
        let malformed = InitialMessage {
            version: ProtocolVersion::CURRENT,
            payload: Ciphertext::new(Vec::new()),
        };

        assert!(matches!(
            engine.accept_session_with_keys(&keys, &malformed, responder.identity.public()),
            Err(AegisError::Malformed)
        ));
    }

    /// `accept_session` из трейта сообщает, что нужен путь с ключами.
    ///
    /// Ошибка `Uninitialized` отличает «не хватает входных данных»
    /// от криптографического сбоя.
    #[test]
    fn trait_accept_session_requires_prekeys() {
        let engine = AegisEngine::new();
        let identity = generate_identity();

        let message = InitialMessage {
            version: ProtocolVersion::CURRENT,
            payload: Ciphertext::new(vec![0u8; 64]),
        };

        assert!(matches!(
            engine.accept_session(&identity, &message),
            Err(AegisError::Uninitialized)
        ));
    }

    /// Отпечаток через трейт совпадает с прямым вычислением.
    #[test]
    fn fingerprint_matches_direct_computation() {
        let engine = AegisEngine::new();
        let identity = generate_identity();

        let via_trait = engine.fingerprint(identity.public(), b"alice").unwrap();
        let direct = Fingerprint::compute(identity.public().public(), b"alice");

        assert_eq!(via_trait, direct);
    }

    /// Движок пригоден как объект трейта.
    ///
    /// `aegis-core` хранит его как `Box<dyn ProtocolEngine>`, чтобы
    /// реализацию можно было подменить без параметризации всего приложения.
    #[test]
    fn engine_works_as_trait_object() {
        let engine: Box<dyn ProtocolEngine> = Box::new(AegisEngine::new());

        assert_eq!(engine.version(), ProtocolVersion::CURRENT);
    }
}
