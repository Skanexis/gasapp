// SPDX-License-Identifier: Apache-2.0

//! PQXDH — установление общего секрета между двумя устройствами.
//!
//! Гибридный обмен: классический X25519 в четырёх экземплярах плюс
//! инкапсуляция ML-KEM-1024. Общий секрет выводится из **всех** составляющих
//! сразу, поэтому взлом любой одной из них не раскрывает сессию — ни
//! появление квантового компьютера (защищает ML-KEM), ни обнаружение
//! слабости в ML-KEM (защищает X25519). Это требование ADR-021.
//!
//! # Что именно здесь аутентифицируется
//!
//! Предключи приходят с сервера, и сервер физически может подменить любой
//! из них. Единственное, что связывает предключ с владельцем, — подпись
//! XEdDSA его identity-ключом. Поэтому [`verify_bundle`] проверяет подписи
//! **ключом отправителя** (`bundle.identity_key`), а не каким-либо нашим
//! ключом, и делает это до единой криптографической операции над bundle.
//!
//! Сам `identity_key` эта проверка не аутентифицирует — его подтверждает
//! пользователь, сверяя safety number (см. `crate::fingerprint`).
//! Здесь проверяется ровно одно: предключи выпущены владельцем того
//! identity-ключа, который лежит в bundle.
//!
//! # Порядок вычислений
//!
//! ```text
//! DH1 = DH(IK_A, SPK_B)     аутентифицирует инициатора
//! DH2 = DH(EK_A, IK_B)      аутентифицирует получателя
//! DH3 = DH(EK_A, SPK_B)     forward secrecy
//! DH4 = DH(EK_A, OPK_B)     forward secrecy первого сообщения, опционально
//! SS  = ML-KEM.Encaps(PQ)   пост-квантовая составляющая
//!
//! SK = HKDF(F ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4 ‖ SS)
//! ```
//!
//! Асимметрия DH1 и DH2 существенна: если поменять их местами, обмен
//! перестанет различать стороны, и сообщение инициатора станет
//! неотличимым от сообщения получателя.

use aegis_types::{AegisError, PublicKeyBytes, Result, Secret};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    keys::{IdentityKeyPair, PreKeyBundle, PreKeyId},
    mlkem::{MlKem1024PrivateKey, MlKem1024PublicKey},
    x25519::{X25519PrivateKey, X25519PublicKey},
    xeddsa,
};

/// Длина общего секрета PQXDH в байтах.
pub const SHARED_SECRET_LEN: usize = 32;

/// Префикс `F` из спецификации X3DH/PQXDH.
///
/// 32 байта `0xFF` дописываются в начало входа KDF. Назначение —
/// доменное разделение: значение выбрано так, чтобы не совпадать ни с одной
/// корректной точкой Curve25519, и вход KDF нельзя было спутать с выходом
/// какого-либо другого протокола, работающего на тех же ключах.
const KDF_PREFIX_F: [u8; 32] = [0xFF; 32];

/// Метка протокола для HKDF.
///
/// Содержит версию и обе схемы: смена любой из них меняет метку, поэтому
/// секреты разных версий протокола невозможно перепутать.
///
/// v2 — с привязкой к транскрипту (см. [`transcript_hash`]).
const KDF_INFO: &[u8] = b"AEGIS_PQXDH_v2_X25519_MLKEM1024_TRANSCRIPT";

/// Домен-разделитель хеша транскрипта.
const TRANSCRIPT_DOMAIN: &[u8] = b"AEGIS_PQXDH_v2_TRANSCRIPT";

/// 🔐 Хеш открытой части обмена — соль HKDF.
///
/// # Что здесь чинится
///
/// Спецификации X3DH/PQXDH требуют, чтобы стороны согласовали
/// identity-ключи друг друга: `AD = IK_A ‖ IK_B` в AEAD первого
/// сообщения. Прежде AD не было вовсе — аутентифицировался только
/// заголовок храповика — и соль HKDF была нулевой. Эксплуатируемой
/// дыры это не давало: оба identity-ключа входят в общий секрет через
/// DH1 и DH2, и подмена любого из них даёт другой ключ. Но стороны не
/// подтверждали явно, что видят **один и тот же** обмен — эфемерный
/// ключ, предключ, шифротекст KEM, — а третья ревизия PQXDH (2024)
/// прямо рекомендует привязывать шифротекст KEM к ключу сессии.
///
/// # Как
///
/// Весь открытый транскрипт хешируется в соль: identity-ключи обеих
/// сторон, эфемерный ключ инициатора, подписанный предключ получателя
/// и шифротекст ML-KEM. Это сильнее, чем AD одного первого сообщения:
/// все ключи сессии выводятся из корня, и расхождение сторон в любом
/// элементе транскрипта даёт другой корень — первое же сообщение
/// не расшифруется. Открытый ключ KEM отдельно не нужен: общий
/// секрет ML-KEM выводится с `H(ek)` и уже привязан к нему.
///
/// Каждое поле — фиксированной длины, кроме шифротекста, и тот идёт
/// с длиной впереди: разные транскрипты не склеиваются в один.
fn transcript_hash(
    initiator_identity: &PublicKeyBytes,
    responder_identity: &PublicKeyBytes,
    initiator_ephemeral: &PublicKeyBytes,
    responder_signed_pre_key: &PublicKeyBytes,
    kem_ciphertext: &[u8],
) -> [u8; 32] {
    use sha2::Digest;

    let mut hasher = Sha256::new();
    hasher.update(TRANSCRIPT_DOMAIN);
    hasher.update(initiator_identity.as_bytes());
    hasher.update(responder_identity.as_bytes());
    hasher.update(initiator_ephemeral.as_bytes());
    hasher.update(responder_signed_pre_key.as_bytes());
    hasher.update(
        u64::try_from(kem_ciphertext.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(kem_ciphertext);
    hasher.finalize().into()
}

/// Общий секрет PQXDH.
///
/// Отдельный тип, а не голый массив: секрет обнуляется при уничтожении и
/// не печатается в отладочном выводе.
pub struct SharedSecret(Secret<[u8; SHARED_SECRET_LEN]>);

impl SharedSecret {
    /// Возвращает байты секрета.
    ///
    /// # Безопасность
    ///
    /// Раскрывает ключевой материал. Единственный допустимый потребитель —
    /// инициализация корневого ключа ratchet.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; SHARED_SECRET_LEN] {
        self.0.expose_secret()
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret<redacted>")
    }
}

/// Какой пост-квантовый предключ был использован при инкапсуляции.
///
/// Получателю необходимо знать это, чтобы выбрать правильный приватный ключ
/// для декапсуляции: одноразовый расходуется, подписанный — нет.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KemPreKeyChoice {
    /// Использован одноразовый пост-квантовый предключ.
    OneTime(PreKeyId),
    /// Одноразовые исчерпаны, использован подписанный.
    Signed(PreKeyId),
}

/// Результат обмена со стороны инициатора.
#[derive(Debug)]
pub struct InitiatorOutput {
    /// Общий секрет.
    pub shared_secret: SharedSecret,
    /// Эфемерный публичный ключ инициатора — уходит получателю.
    pub ephemeral_public: PublicKeyBytes,
    /// Шифротекст ML-KEM — уходит получателю.
    pub kem_ciphertext: Vec<u8>,
    /// Какой пост-квантовый предключ был использован.
    pub kem_choice: KemPreKeyChoice,
    /// Идентификатор израсходованного одноразового предключа X25519.
    pub one_time_pre_key_id: Option<PreKeyId>,
    /// Была ли ослаблена forward secrecy из-за исчерпания пулов.
    pub degraded: bool,
}

/// Приватные ключи получателя, необходимые для воспроизведения обмена.
///
/// Собираются вызывающей стороной из хранилища по идентификаторам, которые
/// прислал инициатор. Сам протокол в хранилище не ходит: доступ к диску
/// вынесен за пределы крейта (раздел 9.2 плана).
pub struct ResponderKeys<'a> {
    /// Долгоживущая пара identity-ключей получателя.
    pub identity: &'a IdentityKeyPair,
    /// Приватная часть подписанного предключа.
    pub signed_pre_key: &'a X25519PrivateKey,
    /// Приватная часть одноразового предключа, если инициатор его израсходовал.
    pub one_time_pre_key: Option<&'a X25519PrivateKey>,
    /// Приватная часть пост-квантового предключа, выбранного инициатором.
    pub kem_pre_key: &'a MlKem1024PrivateKey,
}

/// Проверяет подписи предключей в bundle.
///
/// # Чей ключ проверяет подписи
///
/// `bundle.identity_key` — ключ **владельца** bundle. Проверка своим ключом
/// не имеет смысла: она прошла бы только для наших собственных предключей,
/// а для чужих не прошла бы никогда, из-за чего проверку пришлось бы
/// «смягчить» — и аутентификация исчезла бы совсем. Ровно этот дефект был
/// в первой редакции движка (раздел 23.0.1 мастер-плана).
///
/// # Errors
///
/// [`AegisError::InvalidSignature`] — подпись не сходится с identity-ключом
/// владельца. Мягкого режима нет: неверная подпись означает либо подмену
/// на сервере, либо повреждение данных, и оба случая неприемлемы.
///
/// [`AegisError::Crypto`] — identity-ключ не разбирается как точка кривой.
pub fn verify_bundle(bundle: &PreKeyBundle) -> Result<()> {
    // Ключ владельца bundle — единственный, чья подпись здесь что-то значит.
    let owner = bundle.identity_key.public();

    xeddsa::montgomery::verify(
        owner,
        bundle.signed_pre_key.public.as_bytes(),
        &bundle.signed_pre_key.signature,
    )?;

    xeddsa::montgomery::verify(
        owner,
        bundle.signed_kem_pre_key.public.as_bytes(),
        &bundle.signed_kem_pre_key.signature,
    )?;

    // 🔐 Одноразовый пост-квантовый предключ — тоже.
    //
    // Его подмена даёт атакующему всю пост-квантовую половину общего
    // секрета: инициатор инкапсулирует в подставленный ключ, и тот,
    // кто его подставил, эту половину знает. Классическая половина
    // при этом остаётся целой — но в том и смысл гибрида, что ломать
    // надо обе.
    //
    // ⚠️ Подменить его может сервер: публикация требует подписи
    // устройства, но хранит и отдаёт bundle сервер. Ровно от этого
    // подпись и защищает, и ровно она не проверялась.
    if let Some(one_time_kem) = &bundle.one_time_kem_pre_key {
        xeddsa::montgomery::verify(
            owner,
            one_time_kem.public.as_bytes(),
            &one_time_kem.signature,
        )?;
    }

    Ok(())
}

/// Выполняет PQXDH со стороны инициатора.
///
/// Подписи предключей проверяются первым делом: до проверки над недоверенными
/// данными не выполняется ни одной криптографической операции.
///
/// # Errors
///
/// * [`AegisError::InvalidSignature`] — подпись предключа не сошлась.
/// * [`AegisError::Crypto`] — ключ в bundle не разбирается, либо сбой HKDF.
pub fn initiate<R: RngCore + CryptoRng>(
    our_identity: &IdentityKeyPair,
    their_bundle: &PreKeyBundle,
    rng: &mut R,
) -> Result<InitiatorOutput> {
    // Аутентификация bundle — до всего остального.
    verify_bundle(their_bundle)?;

    let our_identity_private = X25519PrivateKey::from_bytes(aegis_types::PrivateKeyBytes::new(
        *our_identity.private().expose_secret(),
    ))?;
    let their_identity = X25519PublicKey::from_bytes(*their_bundle.identity_key.public())?;
    let their_signed_pre_key = X25519PublicKey::from_bytes(their_bundle.signed_pre_key.public)?;

    // Эфемерная пара живёт ровно один обмен.
    let ephemeral = X25519PrivateKey::generate(rng);
    let ephemeral_public = ephemeral.public_key().as_bytes();

    // DH1 = DH(IK_A, SPK_B) — аутентифицирует инициатора.
    let dh1 = Zeroizing::new(our_identity_private.diffie_hellman(&their_signed_pre_key)?);
    // DH2 = DH(EK_A, IK_B) — аутентифицирует получателя.
    let dh2 = Zeroizing::new(ephemeral.diffie_hellman(&their_identity)?);
    // DH3 = DH(EK_A, SPK_B) — forward secrecy.
    let dh3 = Zeroizing::new(ephemeral.diffie_hellman(&their_signed_pre_key)?);

    // DH4 = DH(EK_A, OPK_B) — есть только пока пул одноразовых не исчерпан.
    let one_time = their_bundle
        .one_time_pre_key
        .as_ref()
        .map(|(id, public)| -> Result<_> {
            let peer = X25519PublicKey::from_bytes(*public)?;
            Ok((*id, Zeroizing::new(ephemeral.diffie_hellman(&peer)?)))
        })
        .transpose()?;

    // Пост-квантовая составляющая: одноразовый предключ предпочтительнее,
    // подписанный — запасной вариант, он не расходуется.
    let (kem_public_bytes, kem_choice) = match &their_bundle.one_time_kem_pre_key {
        Some(one_time_kem) => (
            one_time_kem.public.as_bytes(),
            KemPreKeyChoice::OneTime(one_time_kem.id),
        ),
        None => (
            their_bundle.signed_kem_pre_key.public.as_bytes(),
            KemPreKeyChoice::Signed(their_bundle.signed_kem_pre_key.id),
        ),
    };
    let kem_public = MlKem1024PublicKey::from_bytes(kem_public_bytes)?;
    let (kem_shared, kem_ciphertext) = kem_public.encapsulate(rng);
    let kem_shared = Zeroizing::new(kem_shared);

    let transcript = transcript_hash(
        our_identity.public().public(),
        their_bundle.identity_key.public(),
        &ephemeral_public,
        &their_bundle.signed_pre_key.public,
        &kem_ciphertext,
    );

    let one_time_dh = one_time.as_ref().map(|(_, dh)| dh.as_slice());
    let shared_secret =
        derive_shared_secret(&dh1, &dh2, &dh3, one_time_dh, &kem_shared, &transcript)?;

    Ok(InitiatorOutput {
        shared_secret,
        ephemeral_public,
        kem_ciphertext,
        kem_choice,
        one_time_pre_key_id: one_time.map(|(id, _)| id),
        degraded: their_bundle.is_degraded(),
    })
}

/// Выполняет PQXDH со стороны получателя.
///
/// Воспроизводит те же четыре DH и декапсуляцию, но со своими приватными
/// ключами. Результат обязан совпасть с секретом инициатора.
///
/// # Про отсутствие проверки подписи здесь
///
/// Получателю нечего проверять: его собственные предключи подписаны им же,
/// а identity-ключ инициатора подтверждается не подписью, а safety number.
/// Попытка подмены проявится иначе — как несовпадение общего секрета и,
/// как следствие, провал аутентификации AEAD на первом же сообщении.
///
/// # Errors
///
/// [`AegisError::Crypto`] — ключ инициатора не разбирается, шифротекст
/// ML-KEM некорректной длины, либо сбой HKDF.
pub fn respond(
    keys: &ResponderKeys<'_>,
    initiator_identity: &PublicKeyBytes,
    initiator_ephemeral: &PublicKeyBytes,
    kem_ciphertext: &[u8],
) -> Result<SharedSecret> {
    let our_identity_private = X25519PrivateKey::from_bytes(aegis_types::PrivateKeyBytes::new(
        *keys.identity.private().expose_secret(),
    ))?;
    let their_identity = X25519PublicKey::from_bytes(*initiator_identity)?;
    let their_ephemeral = X25519PublicKey::from_bytes(*initiator_ephemeral)?;

    // Зеркало инициатора: в DH1 участвует наш подписанный предключ и их
    // identity-ключ, в DH2 — наш identity-ключ и их эфемерный.
    let dh1 = Zeroizing::new(keys.signed_pre_key.diffie_hellman(&their_identity)?);
    let dh2 = Zeroizing::new(our_identity_private.diffie_hellman(&their_ephemeral)?);
    let dh3 = Zeroizing::new(keys.signed_pre_key.diffie_hellman(&their_ephemeral)?);

    let dh4 = keys
        .one_time_pre_key
        .map(|private| -> Result<_> {
            Ok(Zeroizing::new(private.diffie_hellman(&their_ephemeral)?))
        })
        .transpose()?;

    let kem_shared = Zeroizing::new(keys.kem_pre_key.decapsulate(kem_ciphertext)?);

    let transcript = transcript_hash(
        initiator_identity,
        keys.identity.public().public(),
        initiator_ephemeral,
        &keys.signed_pre_key.public_key().as_bytes(),
        kem_ciphertext,
    );

    derive_shared_secret(
        &dh1,
        &dh2,
        &dh3,
        dh4.as_ref().map(|dh| dh.as_slice()),
        &kem_shared,
        &transcript,
    )
}

/// Сводит составляющие обмена в общий секрет через HKDF-SHA-256.
///
/// # Почему пропущенный DH4 не заменяется нулями
///
/// Отсутствующая составляющая просто не дописывается во вход. Подстановка
/// нулевого блока сделала бы вход неотличимым от обмена, в котором DH4
/// вычислился и дал нули, — а нулевой результат X25519 означает точку малого
/// порядка, то есть попытку атаки. Разные ситуации не должны давать
/// одинаковый ключ.
fn derive_shared_secret(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: Option<&[u8]>,
    kem_shared: &[u8; 32],
    transcript: &[u8; 32],
) -> Result<SharedSecret> {
    // Вход KDF — секретный материал: обнуляется при выходе из области видимости.
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 6));

    ikm.extend_from_slice(&KDF_PREFIX_F);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    if let Some(dh4) = dh4 {
        ikm.extend_from_slice(dh4);
    }
    ikm.extend_from_slice(kem_shared);

    let hkdf = Hkdf::<Sha256>::new(Some(transcript), &ikm);
    let mut output = [0u8; SHARED_SECRET_LEN];
    hkdf.expand(KDF_INFO, &mut output)
        .map_err(|_| AegisError::Crypto)?;

    let secret = SharedSecret(Secret::new(output));
    output.zeroize();

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{IdentityKey, KemPublicKey, SignedKemPreKey, SignedPreKey};
    use aegis_types::{DeviceId, PrivateKeyBytes};
    use rand_core::OsRng;

    /// Создаёт пару identity-ключей.
    ///
    /// `IK` — ключ X25519: им выполняется DH и им же, по схеме XEdDSA,
    /// проверяются подписи предключей.
    fn generate_identity() -> IdentityKeyPair {
        let private = X25519PrivateKey::generate(&mut OsRng);
        let private_bytes = private.expose_secret();
        let public = xeddsa::montgomery::public_key(&private_bytes).unwrap();

        IdentityKeyPair::new(
            IdentityKey::new(public),
            Secret::new(*private_bytes.expose_secret()),
        )
    }

    /// Полный комплект ключей получателя: публичный bundle и приватные части.
    struct Responder {
        identity: IdentityKeyPair,
        signed_pre_key: X25519PrivateKey,
        one_time_pre_key: X25519PrivateKey,
        signed_kem: MlKem1024PrivateKey,
        one_time_kem: MlKem1024PrivateKey,
    }

    impl Responder {
        fn generate() -> Self {
            Self {
                identity: generate_identity(),
                signed_pre_key: X25519PrivateKey::generate(&mut OsRng),
                one_time_pre_key: X25519PrivateKey::generate(&mut OsRng),
                signed_kem: MlKem1024PrivateKey::generate(&mut OsRng),
                one_time_kem: MlKem1024PrivateKey::generate(&mut OsRng),
            }
        }

        /// Подписывает данные identity-ключом получателя.
        fn sign(&self, message: &[u8]) -> Vec<u8> {
            let private = PrivateKeyBytes::new(*self.identity.private().expose_secret());

            xeddsa::montgomery::sign(&private, message)
                .unwrap()
                .to_vec()
        }

        fn bundle(&self, with_one_time: bool, with_one_time_kem: bool) -> PreKeyBundle {
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
                one_time_pre_key: with_one_time.then(|| {
                    (
                        PreKeyId::new(2),
                        self.one_time_pre_key.public_key().as_bytes(),
                    )
                }),
                signed_kem_pre_key: SignedKemPreKey {
                    id: PreKeyId::new(3),
                    public: KemPublicKey::new(kem_public.clone()),
                    signature: self.sign(&kem_public),
                },
                one_time_kem_pre_key: with_one_time_kem.then(|| {
                    let public = self.one_time_kem.public_key().as_bytes();
                    let signature = self.sign(&public);

                    SignedKemPreKey {
                        id: PreKeyId::new(4),
                        public: KemPublicKey::new(public),
                        signature,
                    }
                }),
            }
        }
    }

    /// Воспроизводит обмен на стороне получателя по выходу инициатора.
    fn respond_to(
        responder: &Responder,
        initiator: &IdentityKeyPair,
        output: &InitiatorOutput,
    ) -> Result<SharedSecret> {
        let kem_pre_key = match output.kem_choice {
            KemPreKeyChoice::OneTime(_) => &responder.one_time_kem,
            KemPreKeyChoice::Signed(_) => &responder.signed_kem,
        };

        respond(
            &ResponderKeys {
                identity: &responder.identity,
                signed_pre_key: &responder.signed_pre_key,
                one_time_pre_key: output
                    .one_time_pre_key_id
                    .map(|_| &responder.one_time_pre_key),
                kem_pre_key,
            },
            initiator.public().public(),
            &output.ephemeral_public,
            &output.kem_ciphertext,
        )
    }

    /// Обе стороны приходят к одному секрету — основное свойство обмена.
    #[test]
    fn both_sides_derive_the_same_secret() {
        let initiator = generate_identity();
        let responder = Responder::generate();
        let bundle = responder.bundle(true, true);

        let output = initiate(&initiator, &bundle, &mut OsRng).unwrap();
        let theirs = respond_to(&responder, &initiator, &output).unwrap();

        assert_eq!(output.shared_secret.expose_secret(), theirs.expose_secret());
    }

    /// Обмен работает и при исчерпанных пулах одноразовых предключей —
    /// но помечается как ослабленный.
    #[test]
    fn exhausted_one_time_pools_still_establish_session() {
        let initiator = generate_identity();
        let responder = Responder::generate();
        let bundle = responder.bundle(false, false);

        let output = initiate(&initiator, &bundle, &mut OsRng).unwrap();

        assert!(output.degraded, "исчерпание пулов должно быть заметно");
        assert!(output.one_time_pre_key_id.is_none());
        assert!(matches!(output.kem_choice, KemPreKeyChoice::Signed(_)));

        let theirs = respond_to(&responder, &initiator, &output).unwrap();
        assert_eq!(output.shared_secret.expose_secret(), theirs.expose_secret());
    }

    /// Исчерпание любого одного из двух пулов тоже помечается.
    #[test]
    fn partially_exhausted_pools_are_marked_degraded() {
        let initiator = generate_identity();
        let responder = Responder::generate();

        for (otp, kem_otp) in [(false, true), (true, false)] {
            let bundle = responder.bundle(otp, kem_otp);
            let output = initiate(&initiator, &bundle, &mut OsRng).unwrap();

            assert!(output.degraded);

            let theirs = respond_to(&responder, &initiator, &output).unwrap();
            assert_eq!(output.shared_secret.expose_secret(), theirs.expose_secret());
        }
    }

    /// 🔐 Подменённый подписанный предключ отвергается.
    ///
    /// Это и есть проверка того, что подписи сверяются ключом владельца
    /// bundle. Сервер, подставивший свой предключ, не может подделать
    /// подпись, не имея приватного identity-ключа получателя.
    #[test]
    fn tampered_signed_pre_key_is_rejected() {
        let initiator = generate_identity();
        let responder = Responder::generate();
        let attacker = X25519PrivateKey::generate(&mut OsRng);

        let mut bundle = responder.bundle(true, true);
        bundle.signed_pre_key.public = attacker.public_key().as_bytes();

        assert!(matches!(
            initiate(&initiator, &bundle, &mut OsRng),
            Err(AegisError::InvalidSignature)
        ));
    }

    /// 🔐 Подменённый пост-квантовый предключ отвергается.
    #[test]
    fn tampered_kem_pre_key_is_rejected() {
        let initiator = generate_identity();
        let responder = Responder::generate();
        let attacker = MlKem1024PrivateKey::generate(&mut OsRng);

        let mut bundle = responder.bundle(true, true);
        bundle.signed_kem_pre_key.public = KemPublicKey::new(attacker.public_key().as_bytes());

        assert!(matches!(
            initiate(&initiator, &bundle, &mut OsRng),
            Err(AegisError::InvalidSignature)
        ));
    }

    /// 🔐 Подменённый **одноразовый** пост-квантовый предключ отвергается.
    ///
    /// # Почему это отдельный тест
    ///
    /// Подпись подписанного ПК-предключа проверялась и раньше
    /// (`tampered_kem_pre_key_is_rejected`), а одноразового — нет.
    /// Сервер её присылал, сетевой слой разбирал, а `parse_bundle`
    /// отбрасывал третьим элементом кортежа: `|(id, key, _)|`.
    ///
    /// # Чем это грозило
    ///
    /// Инициатор предпочитает одноразовый ПК-предключ подписанному —
    /// он и расходуется ради forward secrecy. Значит подменять надо
    /// было именно его, и именно он не проверялся: инициатор
    /// инкапсулировал бы в ключ атакующего, и тот знал бы всю
    /// пост-квантовую половину общего секрета. Классическая половина
    /// осталась бы цела — но гибрид на то и гибрид, что ломать надо
    /// обе.
    ///
    /// ⚠️ Подменить мог сервер: публикация требует подписи
    /// устройства, но хранит и отдаёт bundle он.
    #[test]
    fn tampered_one_time_kem_pre_key_is_rejected() {
        let initiator = generate_identity();
        let responder = Responder::generate();
        let attacker = MlKem1024PrivateKey::generate(&mut OsRng);

        let mut bundle = responder.bundle(true, true);

        let one_time_kem = bundle
            .one_time_kem_pre_key
            .as_mut()
            .expect("в bundle должен быть одноразовый ПК-предключ");

        one_time_kem.public = KemPublicKey::new(attacker.public_key().as_bytes());

        assert!(
            matches!(
                initiate(&initiator, &bundle, &mut OsRng),
                Err(AegisError::InvalidSignature)
            ),
            "подменённый одноразовый ПК-предключ принят",
        );
    }

    /// 🔐 Пустая подпись одноразового ПК-предключа отвергается.
    ///
    /// Так выглядел ключ, опубликованный прежней версией клиента:
    /// `publish_request` слал `String::new()` вместо подписи.
    /// Принять такой ключ значило бы сохранить дыру ради
    /// совместимости.
    #[test]
    fn one_time_kem_pre_key_without_signature_is_rejected() {
        let initiator = generate_identity();
        let responder = Responder::generate();

        let mut bundle = responder.bundle(true, true);

        bundle
            .one_time_kem_pre_key
            .as_mut()
            .expect("одноразовый ПК-предключ")
            .signature = Vec::new();

        assert!(
            initiate(&initiator, &bundle, &mut OsRng).is_err(),
            "ключ без подписи принят",
        );
    }

    /// 🔐 Целый bundle, подписанный чужим ключом, отвергается.
    ///
    /// Регрессионный тест на дефект первой редакции: там подписи
    /// проверялись нашим собственным identity-ключом, из-за чего чужой
    /// bundle не проходил проверку никогда, а подменённый — определялся
    /// не подписью, а случайностью.
    #[test]
    fn bundle_signed_by_another_identity_is_rejected() {
        let initiator = generate_identity();
        let responder = Responder::generate();
        let impostor = Responder::generate();

        // Предключи получателя, но подписи — самозванца.
        let mut bundle = responder.bundle(true, true);
        let impostor_bundle = impostor.bundle(true, true);
        bundle.signed_pre_key.signature = impostor_bundle.signed_pre_key.signature.clone();
        bundle.signed_kem_pre_key.signature = impostor_bundle.signed_kem_pre_key.signature;

        assert!(matches!(
            initiate(&initiator, &bundle, &mut OsRng),
            Err(AegisError::InvalidSignature)
        ));
    }

    /// 🔐 Испорченная подпись отвергается, а не игнорируется.
    #[test]
    fn corrupted_signature_is_rejected() {
        let initiator = generate_identity();
        let responder = Responder::generate();

        let mut bundle = responder.bundle(true, true);
        // Портим один бит — этого достаточно.
        let signature = &mut bundle.signed_pre_key.signature;
        let last = signature.len() - 1;
        signature[last] ^= 0x01;

        assert!(matches!(
            initiate(&initiator, &bundle, &mut OsRng),
            Err(AegisError::InvalidSignature)
        ));
    }

    /// Подмена эфемерного ключа инициатора ломает совпадение секретов.
    ///
    /// Активный посредник не может подставить свой эфемерный ключ:
    /// стороны получат разные секреты, и первое же сообщение не пройдёт
    /// проверку аутентичности AEAD.
    #[test]
    fn tampered_ephemeral_key_breaks_agreement() {
        let initiator = generate_identity();
        let responder = Responder::generate();
        let bundle = responder.bundle(true, true);

        let mut output = initiate(&initiator, &bundle, &mut OsRng).unwrap();
        output.ephemeral_public = X25519PrivateKey::generate(&mut OsRng)
            .public_key()
            .as_bytes();

        let theirs = respond_to(&responder, &initiator, &output).unwrap();

        assert_ne!(output.shared_secret.expose_secret(), theirs.expose_secret());
    }

    /// Подменённый шифротекст ML-KEM не даёт совпадения секретов.
    ///
    /// ML-KEM по построению не сообщает об ошибке (implicit rejection,
    /// FIPS 203): декапсуляция вернёт псевдослучайный секрет, а расхождение
    /// обнаружится при проверке тега AEAD.
    #[test]
    fn tampered_kem_ciphertext_breaks_agreement() {
        let initiator = generate_identity();
        let responder = Responder::generate();
        let bundle = responder.bundle(true, true);

        let mut output = initiate(&initiator, &bundle, &mut OsRng).unwrap();
        output.kem_ciphertext[0] ^= 0xFF;

        let theirs = respond_to(&responder, &initiator, &output).unwrap();

        assert_ne!(output.shared_secret.expose_secret(), theirs.expose_secret());
    }

    /// Шифротекст ML-KEM неверной длины отвергается, а не паникует.
    #[test]
    fn malformed_kem_ciphertext_is_rejected() {
        let initiator = generate_identity();
        let responder = Responder::generate();
        let bundle = responder.bundle(true, true);

        let output = initiate(&initiator, &bundle, &mut OsRng).unwrap();

        let result = respond(
            &ResponderKeys {
                identity: &responder.identity,
                signed_pre_key: &responder.signed_pre_key,
                one_time_pre_key: Some(&responder.one_time_pre_key),
                kem_pre_key: &responder.one_time_kem,
            },
            initiator.public().public(),
            &output.ephemeral_public,
            b"too short",
        );

        assert!(matches!(result, Err(AegisError::Crypto)));
    }

    /// Два обмена с одним и тем же bundle дают разные секреты.
    ///
    /// Эфемерный ключ и инкапсуляция ML-KEM свежие в каждом обмене, поэтому
    /// повторное использование bundle не приводит к повторению ключа.
    #[test]
    fn repeated_exchanges_produce_distinct_secrets() {
        let initiator = generate_identity();
        let responder = Responder::generate();
        let bundle = responder.bundle(true, true);

        let first = initiate(&initiator, &bundle, &mut OsRng).unwrap();
        let second = initiate(&initiator, &bundle, &mut OsRng).unwrap();

        assert_ne!(
            first.shared_secret.expose_secret(),
            second.shared_secret.expose_secret()
        );
    }

    /// Пропуск DH4 не эквивалентен нулевому DH4.
    ///
    /// Проверяется, что отсутствующая составляющая не дописывается нулями:
    /// иначе исчерпание пула давало бы тот же ключ, что и обмен с
    /// вырожденным DH4.
    #[test]
    fn absent_dh4_differs_from_zero_dh4() {
        let dh = [7u8; 32];
        let kem = [9u8; 32];

        let absent = derive_shared_secret(&dh, &dh, &dh, None, &kem, &[7u8; 32]).unwrap();
        let zeroed =
            derive_shared_secret(&dh, &dh, &dh, Some(&[0u8; 32]), &kem, &[7u8; 32]).unwrap();

        assert_ne!(absent.expose_secret(), zeroed.expose_secret());
    }

    /// Порядок DH-составляющих влияет на результат.
    ///
    /// DH1 и DH2 несут разный смысл (аутентификация инициатора против
    /// аутентификации получателя), поэтому их перестановка обязана менять
    /// ключ — иначе стороны обмена перестают различаться.
    #[test]
    fn dh_order_affects_the_secret() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let kem = [4u8; 32];

        let straight = derive_shared_secret(&a, &b, &c, None, &kem, &[7u8; 32]).unwrap();
        let swapped = derive_shared_secret(&b, &a, &c, None, &kem, &[7u8; 32]).unwrap();

        assert_ne!(straight.expose_secret(), swapped.expose_secret());
    }

    /// Общий секрет не печатается в отладочном выводе.
    #[test]
    fn shared_secret_debug_is_redacted() {
        let secret = SharedSecret(Secret::new([0xAB; SHARED_SECRET_LEN]));

        assert_eq!(format!("{secret:?}"), "SharedSecret<redacted>");
    }

    /// 🔐 Любое поле транскрипта меняет соль, а значит и ключ сессии.
    ///
    /// Стороны, увидевшие разные identity-ключи, разный эфемерный ключ,
    /// предключ или шифротекст KEM, не получат общий корень.
    #[test]
    fn every_transcript_field_is_bound() {
        let key = |byte: u8| PublicKeyBytes::new([byte; 32]);
        let base = transcript_hash(&key(1), &key(2), &key(3), &key(4), &[5u8; 16]);

        let variants = [
            transcript_hash(&key(9), &key(2), &key(3), &key(4), &[5u8; 16]),
            transcript_hash(&key(1), &key(9), &key(3), &key(4), &[5u8; 16]),
            transcript_hash(&key(1), &key(2), &key(9), &key(4), &[5u8; 16]),
            transcript_hash(&key(1), &key(2), &key(3), &key(9), &[5u8; 16]),
            transcript_hash(&key(1), &key(2), &key(3), &key(4), &[9u8; 16]),
            // Роли не взаимозаменяемы: A→B и B→A — разные обмены.
            transcript_hash(&key(2), &key(1), &key(3), &key(4), &[5u8; 16]),
        ];

        for variant in variants {
            assert_ne!(variant, base, "поле транскрипта не привязано");
        }

        let dh = [3u8; 32];
        let kem = [4u8; 32];
        let one = derive_shared_secret(&dh, &dh, &dh, None, &kem, &base).expect("ключ");
        let other = derive_shared_secret(&dh, &dh, &dh, None, &kem, &variants[0]).expect("ключ");
        assert_ne!(
            one.expose_secret(),
            other.expose_secret(),
            "соль не влияет на ключ"
        );
    }
}
