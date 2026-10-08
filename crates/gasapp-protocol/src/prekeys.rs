// SPDX-License-Identifier: Apache-2.0

//! Генерация и ротация предключей.
//!
//! Владелец публикует на сервере набор ключей, по которому с ним можно
//! установить сессию, не будучи онлайн. Состав набора задан разделом 6.2:
//!
//! | Ключ | Тип | Обновление | Подписан |
//! |---|---|---|---|
//! | `IK` | X25519, долгоживущий | никогда | — |
//! | `SPK` | X25519 | раз в 7 дней | да |
//! | `OPK` | X25519, пул из 100 | по расходу | нет |
//! | `PQSPK` | ML-KEM-1024 | раз в 7 дней | да |
//! | `PQOPK` | ML-KEM-1024, пул из 100 | по расходу | да |
//!
//! # Почему одноразовые X25519 не подписываются, а пост-квантовые — да
//!
//! `OPK` не подписан, потому что его подмена не даёт атакующему ничего:
//! общий секрет всё равно включает `SPK`, подписанный identity-ключом,
//! и подменённый `OPK` приведёт лишь к несовпадению секретов. Для `PQOPK`
//! это не так — пост-квантовая составляющая единственная, и её подмена
//! обнулила бы защиту от квантового противника, поэтому она подписывается.
//!
//! # Про хранение
//!
//! Модуль возвращает и публичную часть (для отправки на сервер), и
//! приватную (для записи в зашифрованное хранилище). Сам он никуда не
//! пишет: доступ к диску вынесен за пределы крейта (раздел 9.2).

use gasapp_types::{GasAppError, PrivateKeyBytes, Result, Secret, Timestamp};
use rand_core::{CryptoRng, RngCore};

use crate::{
    keys::{
        IdentityKey, IdentityKeyPair, KemPublicKey, PreKeyBundle, PreKeyId, SignedKemPreKey,
        SignedPreKey,
    },
    mlkem::MlKem1024PrivateKey,
    pq_identity::{
        bind, hybrid_sign, PqIdentityKeyPair, KEM_PRE_KEY_DOMAIN, ONE_TIME_KEM_DOMAIN,
        SIGNED_PRE_KEY_DOMAIN,
    },
    x25519::X25519PrivateKey,
    xeddsa, ONE_TIME_PRE_KEY_POOL_SIZE, ONE_TIME_PRE_KEY_REFILL_THRESHOLD,
    SIGNED_PRE_KEY_ROTATION_DAYS,
};

/// Миллисекунд в сутках.
const DAY_MILLIS: i64 = 24 * 60 * 60 * 1000;

/// Приватная часть набора предключей — то, что владелец хранит у себя.
///
/// Публичная часть ([`PreKeyBundle`]) уходит на сервер, приватная
/// не покидает устройство и записывается только в зашифрованное хранилище.
pub struct PreKeySecrets {
    /// Приватная часть подписанного предключа.
    pub signed_pre_key: X25519PrivateKey,
    /// Когда подписанный предключ был создан — для ротации.
    pub signed_pre_key_created: Timestamp,
    /// Одноразовые предключи X25519, по идентификаторам.
    pub one_time: Vec<(PreKeyId, X25519PrivateKey)>,
    /// Приватная часть подписанного пост-квантового предключа.
    pub signed_kem: MlKem1024PrivateKey,
    /// Одноразовые пост-квантовые предключи.
    pub one_time_kem: Vec<(PreKeyId, MlKem1024PrivateKey)>,
    /// Подписанные предключи, выведенные из обращения ротацией.
    ///
    /// 🔐 Хранятся [`RETIRED_SIGNED_KEEP_DAYS`] суток — столько же живёт
    /// недоставленный конверт. Начальное сообщение, зашифрованное на
    /// прежний ключ до ротации, иначе не расшифровалось бы никогда
    /// (см. [`rotate_signed`]). Новые впереди.
    pub retired_signed: Vec<RetiredSigned>,
}

/// Подписанная пара предключей, выведенная из обращения ротацией.
pub struct RetiredSigned {
    /// Прежний подписанный предключ X25519.
    pub signed_pre_key: X25519PrivateKey,
    /// Прежний подписанный пост-квантовый предключ.
    pub signed_kem: MlKem1024PrivateKey,
    /// Когда выведен из обращения.
    pub retired_at: Timestamp,
}

/// Сколько суток хранится выведенный подписанный предключ.
///
/// Совпадает со сроком жизни недоставленного конверта на сервере:
/// позже начальное сообщение на этот ключ прийти уже не может.
pub const RETIRED_SIGNED_KEEP_DAYS: i64 = 30;

/// Предел числа выведенных ключей.
///
/// Ротация раз в семь суток даёт за тридцать суток пять ключей;
/// предел с запасом, чтобы испорченные часы не раздули список.
pub const MAX_RETIRED_SIGNED: usize = 8;

// Неполнота `Debug` — требование правила 4: приватные предключи
// не печатаются ни при каких условиях, в выводе только их количество.
#[allow(clippy::missing_fields_in_debug)]
impl core::fmt::Debug for PreKeySecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Ни одного байта ключевого материала: вывод попадает в логи.
        f.debug_struct("PreKeySecrets")
            .field("one_time", &self.one_time.len())
            .field("one_time_kem", &self.one_time_kem.len())
            .field("retired_signed", &self.retired_signed.len())
            .finish()
    }
}

impl PreKeySecrets {
    /// Сколько одноразовых предключей осталось.
    ///
    /// Пул считается по меньшему из двух: сессия расходует и обычный,
    /// и пост-квантовый одноразовый ключ, поэтому исчерпание любого
    /// из них одинаково ослабляет forward secrecy.
    #[must_use]
    pub fn remaining_one_time(&self) -> usize {
        self.one_time.len().min(self.one_time_kem.len())
    }

    /// Пора ли пополнять пул одноразовых предключей.
    ///
    /// Порог намеренно выше нуля: пополнение требует обращения к серверу,
    /// и ждать полного исчерпания значило бы оставить пользователя без
    /// forward secrecy на время, пока запрос идёт.
    #[must_use]
    pub fn needs_refill(&self) -> bool {
        self.remaining_one_time() <= ONE_TIME_PRE_KEY_REFILL_THRESHOLD as usize
    }

    /// Пора ли ротировать подписанный предключ.
    ///
    /// Ротация раз в [`SIGNED_PRE_KEY_ROTATION_DAYS`] дней ограничивает
    /// окно, в течение которого утёкший `SPK` позволяет расшифровать
    /// перехваченные первые сообщения.
    #[must_use]
    pub fn needs_rotation(&self, now: Timestamp) -> bool {
        let age = now
            .as_millis()
            .saturating_sub(self.signed_pre_key_created.as_millis());

        age >= i64::from(SIGNED_PRE_KEY_ROTATION_DAYS).saturating_mul(DAY_MILLIS)
    }

    /// Извлекает приватный одноразовый предключ по идентификатору.
    ///
    /// Ключ **расходуется**: повторная выдача означала бы, что две сессии
    /// используют один одноразовый ключ, то есть он перестаёт быть
    /// одноразовым.
    pub fn take_one_time(&mut self, id: PreKeyId) -> Option<X25519PrivateKey> {
        let position = self.one_time.iter().position(|(key_id, _)| *key_id == id)?;

        Some(self.one_time.swap_remove(position).1)
    }

    /// Извлекает приватный одноразовый пост-квантовый предключ.
    pub fn take_one_time_kem(&mut self, id: PreKeyId) -> Option<MlKem1024PrivateKey> {
        let position = self
            .one_time_kem
            .iter()
            .position(|(key_id, _)| *key_id == id)?;

        Some(self.one_time_kem.swap_remove(position).1)
    }
}

/// Генерирует полный набор предключей.
///
/// Возвращает публичную часть для публикации на сервере и приватную
/// для записи в хранилище.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — сбой подписи предключа.
///
/// [`GasAppError::Crypto`]: gasapp_types::GasAppError::Crypto
pub fn generate<R: RngCore + CryptoRng>(
    identity: &IdentityKeyPair,
    pq: &PqIdentityKeyPair,
    device_id: gasapp_types::DeviceId,
    now: Timestamp,
    rng: &mut R,
) -> Result<(PreKeyBundle, PreKeySecrets)> {
    // Подписанные предключи.
    let signed_pre_key = X25519PrivateKey::generate(rng);
    let spk_public = signed_pre_key.public_key().as_bytes();
    let spk_signature = hybrid_sign(identity, pq, SIGNED_PRE_KEY_DOMAIN, spk_public.as_bytes())?;

    let signed_kem = MlKem1024PrivateKey::generate(rng);
    let kem_public = signed_kem.public_key().as_bytes();
    let kem_signature = hybrid_sign(identity, pq, KEM_PRE_KEY_DOMAIN, &kem_public)?;

    // Пулы одноразовых предключей.
    let one_time = generate_one_time_pool(rng);
    let one_time_kem = generate_one_time_kem_pool(rng);

    // Одноразовый пост-квантовый предключ уходит **с подписью**:
    // его подмена даёт атакующему всю пост-квантовую половину
    // общего секрета (раздел 6.2).
    let one_time_kem_published = one_time_kem
        .first()
        .map(|(id, key)| {
            let public = key.public_key().as_bytes();
            let signature = hybrid_sign(identity, pq, ONE_TIME_KEM_DOMAIN, &public)?;

            Ok::<_, gasapp_types::GasAppError>(SignedKemPreKey {
                id: *id,
                public: KemPublicKey::new(public),
                signature,
            })
        })
        .transpose()?;

    // ⚠️ В bundle уходит по одному одноразовому ключу из каждого пула,
    // а не весь пул. Остальные девяносто девять остаются здесь
    // и на сервер не попадают вовсе — их публикует обслуживание
    // (`Client::maintain_prekeys`) отдельным запросом.
    //
    // Прежде тут стояло «остальные сервер раздаёт следующим
    // собеседникам», и это было неправдой: у сервера лежал ровно
    // один ключ, первый же незнакомец его забирал, и все следующие
    // первые контакты шли без одноразового предключа.
    let bundle = PreKeyBundle {
        device_id,
        identity_key: *identity.public(),
        pq_identity: pq.public(),
        identity_binding: bind(identity, pq)?,
        signed_pre_key: SignedPreKey {
            id: PreKeyId::new(0),
            public: spk_public,
            signature: spk_signature,
        },
        one_time_pre_key: one_time
            .first()
            .map(|(id, key)| (*id, key.public_key().as_bytes())),
        signed_kem_pre_key: SignedKemPreKey {
            id: PreKeyId::new(0),
            public: KemPublicKey::new(kem_public),
            signature: kem_signature,
        },
        one_time_kem_pre_key: one_time_kem_published,
    };

    let secrets = PreKeySecrets {
        signed_pre_key,
        signed_pre_key_created: now,
        one_time,
        signed_kem,
        one_time_kem,
        retired_signed: Vec::new(),
    };

    Ok((bundle, secrets))
}

/// Ротирует подписанные предключи, сохраняя пулы одноразовых.
///
/// 🔐 Прежняя пара уходит в [`PreKeySecrets::retired_signed`] и хранится
/// [`RETIRED_SIGNED_KEEP_DAYS`] суток: начальное сообщение, зашифрованное
/// на неё до ротации, ещё может прийти.
///
/// ⚠️ Прежде здесь было написано, что прежний ключ «не уничтожается
/// немедленно» и что срок его хранения «определяет вызывающий код».
/// На деле функция затирала его на месте, и хранить было нечего.
/// Пока ротации не было, это не проявлялось; когда обслуживание
/// предключей её включило, каждый, кто впервые написал до ротации,
/// а был прочитан после, терял сообщение вместе со всей перепиской.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — сбой подписи.
///
/// [`GasAppError::Crypto`]: gasapp_types::GasAppError::Crypto
pub fn rotate_signed<R: RngCore + CryptoRng>(
    identity: &IdentityKeyPair,
    pq: &PqIdentityKeyPair,
    secrets: &mut PreKeySecrets,
    now: Timestamp,
    rng: &mut R,
) -> Result<(SignedPreKey, SignedKemPreKey)> {
    let previous_signed =
        core::mem::replace(&mut secrets.signed_pre_key, X25519PrivateKey::generate(rng));
    let previous_kem =
        core::mem::replace(&mut secrets.signed_kem, MlKem1024PrivateKey::generate(rng));
    secrets.signed_pre_key_created = now;

    secrets.retired_signed.insert(
        0,
        RetiredSigned {
            signed_pre_key: previous_signed,
            signed_kem: previous_kem,
            retired_at: now,
        },
    );
    prune_retired(secrets, now);

    signed_published(identity, pq, secrets)
}

/// Удаляет выведенные ключи старше срока и сверх предела.
///
/// 🔐 Хранить их дольше срока жизни конверта незачем, а каждый лишний
/// ключ — это прошлое, которое можно расшифровать, отняв устройство.
pub fn prune_retired(secrets: &mut PreKeySecrets, now: Timestamp) {
    let keep = RETIRED_SIGNED_KEEP_DAYS.saturating_mul(DAY_MILLIS);

    secrets.retired_signed.retain(|retired| {
        now.as_millis()
            .saturating_sub(retired.retired_at.as_millis())
            <= keep
    });
    secrets.retired_signed.truncate(MAX_RETIRED_SIGNED);
}

/// Собирает публичные части подписанных предключей из секретов.
///
/// # Зачем отдельно от [`rotate_signed`]
///
/// Публиковать подписанные предключи приходится не только при
/// ротации: пополнение пула одноразовых ключей идёт тем же запросом
/// `PUT /v1/keys/{device}`, а он требует и подписанную часть тоже.
/// Без этой функции вызывающему пришлось бы либо ротировать ключ
/// без надобности, либо повторить подпись у себя — то есть завести
/// вторую реализацию, которая однажды разойдётся с первой.
///
/// 🔐 Повторный вызов даёт тот же результат: подпись XEdDSA
/// детерминирована (раздел 3 спецификации), nonce выводится из ключа
/// и сообщения, а не из случайности. Поэтому опубликовать одну и ту же
/// подписанную часть дважды безопасно и ничего не меняет.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — сбой подписи.
///
/// [`GasAppError::Crypto`]: gasapp_types::GasAppError::Crypto
pub fn signed_published(
    identity: &IdentityKeyPair,
    pq: &PqIdentityKeyPair,
    secrets: &PreKeySecrets,
) -> Result<(SignedPreKey, SignedKemPreKey)> {
    let spk_public = secrets.signed_pre_key.public_key().as_bytes();
    let spk_signature = hybrid_sign(identity, pq, SIGNED_PRE_KEY_DOMAIN, spk_public.as_bytes())?;

    let kem_public = secrets.signed_kem.public_key().as_bytes();
    let kem_signature = hybrid_sign(identity, pq, KEM_PRE_KEY_DOMAIN, &kem_public)?;

    Ok((
        SignedPreKey {
            id: PreKeyId::new(0),
            public: spk_public,
            signature: spk_signature,
        },
        SignedKemPreKey {
            id: PreKeyId::new(0),
            public: KemPublicKey::new(kem_public),
            signature: kem_signature,
        },
    ))
}

/// Пополняет пулы одноразовых предключей до полного размера.
///
/// Возвращает публичные части добавленных ключей — их нужно отправить
/// на сервер.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — сбой подписи пост-квантового предключа.
///
/// [`GasAppError::Crypto`]: gasapp_types::GasAppError::Crypto
pub fn refill_one_time<R: RngCore + CryptoRng>(
    identity: &IdentityKeyPair,
    pq: &PqIdentityKeyPair,
    secrets: &mut PreKeySecrets,
    rng: &mut R,
) -> Result<(
    Vec<(PreKeyId, gasapp_types::PublicKeyBytes)>,
    Vec<SignedKemPreKey>,
)> {
    let target = ONE_TIME_PRE_KEY_POOL_SIZE as usize;

    // Идентификаторы продолжают нумерацию, а не начинаются заново:
    // повтор идентификатора означал бы, что сервер выдаст один и тот же
    // ключ дважды под разными записями.
    let mut next_id = next_free_id(secrets);

    // Пулы пополняются независимо: расход у них общий не всегда,
    // и дополнять полный пул до сверхполного незачем.
    let mut added = Vec::new();
    while secrets.one_time.len() < target {
        let key = X25519PrivateKey::generate(rng);
        let id = PreKeyId::new(next_id);
        next_id = next_id.saturating_add(1);

        added.push((id, key.public_key().as_bytes()));
        secrets.one_time.push((id, key));
    }

    let mut added_kem = Vec::new();
    while secrets.one_time_kem.len() < target {
        let key = MlKem1024PrivateKey::generate(rng);
        let id = PreKeyId::new(next_id);
        next_id = next_id.saturating_add(1);

        let public = key.public_key().as_bytes();
        let signature = hybrid_sign(identity, pq, ONE_TIME_KEM_DOMAIN, &public)?;

        added_kem.push(SignedKemPreKey {
            id,
            public: KemPublicKey::new(public),
            signature,
        });
        secrets.one_time_kem.push((id, key));
    }

    Ok((added, added_kem))
}

/// Выпускает `count` новых одноразовых предключей и добавляет их в пул.
///
/// Возвращает публичные части — их нужно отправить на сервер.
///
/// # Зачем отдельно от [`refill_one_time`]
///
/// [`refill_one_time`] дополняет пул **до полного размера**, считая
/// по своим же секретам. Этого достаточно, когда ключи расходует сам
/// владелец, принимая начальные сообщения.
///
/// ⚠️ Но расходует их не он. Одноразовый ключ вычёркивается,
/// когда его **забирает отправитель** — сервер отдаёт bundle и
/// удаляет запись. Владелец об этом не узнаёт никак: его локальный
/// список не меняется. Значит после того, как чужой вычерпал пул
/// на сервере, `refill_one_time` не добавит ничего: локально всё
/// на месте.
///
/// Поэтому пополнять надо по числу, которое знает **сервер**
/// (`GET /v1/keys/{device}/count`), а эта функция выпускает ровно
/// столько, сколько попросили.
///
/// # ⚠️ Прежние ключи не выбрасываются
///
/// Даже те, что сервер уже отдал и удалил. Отправитель, успевший
/// забрать ключ, пришлёт по нему начальное сообщение — и без
/// приватной половины оно не расшифруется. Выброшенный ключ
/// означал бы потерянное сообщение.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — сбой подписи пост-квантового предключа.
///
/// [`GasAppError::Crypto`]: gasapp_types::GasAppError::Crypto
pub fn mint_one_time<R: RngCore + CryptoRng>(
    identity: &IdentityKeyPair,
    pq: &PqIdentityKeyPair,
    secrets: &mut PreKeySecrets,
    count: usize,
    rng: &mut R,
) -> Result<(
    Vec<(PreKeyId, gasapp_types::PublicKeyBytes)>,
    Vec<SignedKemPreKey>,
)> {
    // Идентификаторы продолжают нумерацию, а не начинаются заново:
    // повтор идентификатора означал бы, что сервер выдаст один и тот же
    // ключ дважды под разными записями.
    let mut next_id = next_free_id(secrets);

    let mut added = Vec::with_capacity(count);
    let mut added_kem = Vec::with_capacity(count);

    for _ in 0..count {
        let key = X25519PrivateKey::generate(rng);
        let id = PreKeyId::new(next_id);
        next_id = next_id.saturating_add(1);

        added.push((id, key.public_key().as_bytes()));
        secrets.one_time.push((id, key));

        let kem = MlKem1024PrivateKey::generate(rng);
        let kem_id = PreKeyId::new(next_id);
        next_id = next_id.saturating_add(1);

        let public = kem.public_key().as_bytes();
        let signature = hybrid_sign(identity, pq, ONE_TIME_KEM_DOMAIN, &public)?;

        added_kem.push(SignedKemPreKey {
            id: kem_id,
            public: KemPublicKey::new(public),
            signature,
        });
        secrets.one_time_kem.push((kem_id, kem));
    }

    Ok((added, added_kem))
}

/// Наименьший неиспользованный идентификатор предключа.
fn next_free_id(secrets: &PreKeySecrets) -> u32 {
    let highest = secrets
        .one_time
        .iter()
        .map(|(id, _)| id.as_u32())
        .chain(secrets.one_time_kem.iter().map(|(id, _)| id.as_u32()))
        .max()
        .unwrap_or(0);

    highest.saturating_add(1)
}

/// Генерирует пул одноразовых предключей X25519.
fn generate_one_time_pool<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Vec<(PreKeyId, X25519PrivateKey)> {
    (1..=ONE_TIME_PRE_KEY_POOL_SIZE)
        .map(|index| (PreKeyId::new(index), X25519PrivateKey::generate(rng)))
        .collect()
}

/// Генерирует пул одноразовых пост-квантовых предключей.
fn generate_one_time_kem_pool<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Vec<(PreKeyId, MlKem1024PrivateKey)> {
    let offset = ONE_TIME_PRE_KEY_POOL_SIZE;

    (1..=ONE_TIME_PRE_KEY_POOL_SIZE)
        .map(|index| {
            (
                PreKeyId::new(offset.saturating_add(index)),
                MlKem1024PrivateKey::generate(rng),
            )
        })
        .collect()
}

/// Создаёт пару identity-ключей.
///
/// `IK` — ключ X25519: им выполняется DH и им же, по схеме XEdDSA,
/// подписываются предключи.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — сбой вывода публичного ключа.
///
/// [`GasAppError::Crypto`]: gasapp_types::GasAppError::Crypto
pub fn generate_identity<R: RngCore + CryptoRng>(rng: &mut R) -> Result<IdentityKeyPair> {
    let private = X25519PrivateKey::generate(rng);
    let private_bytes = private.expose_secret();
    let public = xeddsa::montgomery::public_key(&private_bytes)?;

    Ok(IdentityKeyPair::new(
        IdentityKey::new(public),
        Secret::new(*private_bytes.expose_secret()),
    ))
}

/// Версия формата сериализации секретов предключей.
///
/// 2 — с выведенными подписанными ключами. Версия 1 читается:
/// в ней выведенных ключей нет, и список пуст.
const SECRETS_VERSION: u8 = 2;

/// Прежняя версия формата, без выведенных ключей.
const SECRETS_VERSION_V1: u8 = 1;

/// Длина seed пост-квантового приватного ключа.
const KEM_SEED_LEN: usize = crate::mlkem::SEED_LEN;

impl PreKeySecrets {
    /// Сериализует секреты для записи в зашифрованное хранилище.
    ///
    /// # Куда это попадает
    ///
    /// Только в базу под SQLCipher. Байты содержат приватные ключи
    /// в открытом виде, поэтому за пределы устройства они не уходят
    /// никогда — ни в бэкап, ни в лог, ни через FFI.
    ///
    /// # Формат
    ///
    /// Ручной, как и у конверта: разбор идёт над содержимым базы,
    /// которое могло быть повреждено, и явные проверки длин здесь
    /// видны глазами.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — пул не помещается в счётчик длины.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = vec![SECRETS_VERSION];

        out.extend_from_slice(self.signed_pre_key.expose_secret().expose_secret());
        out.extend_from_slice(&self.signed_pre_key_created.as_millis().to_be_bytes());

        let signed_kem = self.signed_kem.expose_secret();
        out.extend_from_slice(signed_kem);

        write_pool(&mut out, &self.one_time, |key, buffer| {
            buffer.extend_from_slice(key.expose_secret().expose_secret());
        })?;

        write_pool(&mut out, &self.one_time_kem, |key, buffer| {
            buffer.extend_from_slice(key.expose_secret());
        })?;

        let retired =
            u32::try_from(self.retired_signed.len()).map_err(|_| GasAppError::Malformed)?;
        out.extend_from_slice(&retired.to_be_bytes());

        for key in &self.retired_signed {
            out.extend_from_slice(key.signed_pre_key.expose_secret().expose_secret());
            out.extend_from_slice(key.signed_kem.expose_secret());
            out.extend_from_slice(&key.retired_at.as_millis().to_be_bytes());
        }

        Ok(out)
    }

    /// Восстанавливает секреты из хранилища.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — неизвестная версия или обрыв данных;
    /// [`GasAppError::Crypto`] — байты не разбираются как ключ.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut offset = 0usize;

        let version = *bytes.first().ok_or(GasAppError::Malformed)?;
        if version != SECRETS_VERSION && version != SECRETS_VERSION_V1 {
            return Err(GasAppError::Malformed);
        }
        offset = offset.checked_add(1).ok_or(GasAppError::Malformed)?;

        let signed_raw = take(bytes, &mut offset, 32)?;
        let signed_pre_key = X25519PrivateKey::from_bytes(PrivateKeyBytes::new(
            signed_raw.try_into().map_err(|_| GasAppError::Malformed)?,
        ))?;

        let created_raw: [u8; 8] = take(bytes, &mut offset, 8)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)?;
        let signed_pre_key_created = Timestamp::from_millis(i64::from_be_bytes(created_raw));

        let signed_kem_raw = take(bytes, &mut offset, KEM_SEED_LEN)?;
        let signed_kem = MlKem1024PrivateKey::from_bytes(signed_kem_raw)?;

        let one_time = read_pool(bytes, &mut offset, 32, |raw| {
            X25519PrivateKey::from_bytes(PrivateKeyBytes::new(
                raw.try_into().map_err(|_| GasAppError::Malformed)?,
            ))
        })?;

        let one_time_kem = read_pool(bytes, &mut offset, KEM_SEED_LEN, |raw| {
            MlKem1024PrivateKey::from_bytes(raw)
        })?;

        let mut retired_signed = Vec::new();

        if version == SECRETS_VERSION {
            let count_raw: [u8; 4] = take(bytes, &mut offset, 4)?
                .try_into()
                .map_err(|_| GasAppError::Malformed)?;
            let count = usize::try_from(u32::from_be_bytes(count_raw))
                .map_err(|_| GasAppError::Malformed)?;

            // Счётчик из базы не доверяется: больше предела здесь
            // не бывает, и огромное число означало бы порчу.
            if count > MAX_RETIRED_SIGNED {
                return Err(GasAppError::Malformed);
            }

            for _ in 0..count {
                let signed_raw = take(bytes, &mut offset, 32)?;
                let signed_pre_key = X25519PrivateKey::from_bytes(PrivateKeyBytes::new(
                    signed_raw.try_into().map_err(|_| GasAppError::Malformed)?,
                ))?;
                let signed_kem =
                    MlKem1024PrivateKey::from_bytes(take(bytes, &mut offset, KEM_SEED_LEN)?)?;
                let retired_raw: [u8; 8] = take(bytes, &mut offset, 8)?
                    .try_into()
                    .map_err(|_| GasAppError::Malformed)?;

                retired_signed.push(RetiredSigned {
                    signed_pre_key,
                    signed_kem,
                    retired_at: Timestamp::from_millis(i64::from_be_bytes(retired_raw)),
                });
            }
        }

        // Хвост означает, что база хранит не то, что мы писали.
        if offset != bytes.len() {
            return Err(GasAppError::Malformed);
        }

        Ok(Self {
            signed_pre_key,
            signed_pre_key_created,
            one_time,
            signed_kem,
            one_time_kem,
            retired_signed,
        })
    }
}

/// Записывает пул одноразовых ключей: счётчик, затем пары id + ключ.
fn write_pool<K>(
    out: &mut Vec<u8>,
    pool: &[(PreKeyId, K)],
    mut write_key: impl FnMut(&K, &mut Vec<u8>),
) -> Result<()> {
    let count = u32::try_from(pool.len()).map_err(|_| GasAppError::Malformed)?;
    out.extend_from_slice(&count.to_be_bytes());

    for (id, key) in pool {
        out.extend_from_slice(&id.as_u32().to_be_bytes());
        write_key(key, out);
    }

    Ok(())
}

/// Читает пул одноразовых ключей.
fn read_pool<K>(
    bytes: &[u8],
    offset: &mut usize,
    key_len: usize,
    mut parse: impl FnMut(&[u8]) -> Result<K>,
) -> Result<Vec<(PreKeyId, K)>> {
    let count_raw: [u8; 4] = take(bytes, offset, 4)?
        .try_into()
        .map_err(|_| GasAppError::Malformed)?;
    let count = u32::from_be_bytes(count_raw) as usize;

    // Счётчик проверяется против оставшейся длины до выделения памяти:
    // повреждённая база с числом в четыре миллиарда не должна приводить
    // к попытке зарезервировать под него вектор.
    let per_entry = key_len.checked_add(4).ok_or(GasAppError::Malformed)?;
    let needed = count.checked_mul(per_entry).ok_or(GasAppError::Malformed)?;
    let remaining = bytes
        .len()
        .checked_sub(*offset)
        .ok_or(GasAppError::Malformed)?;
    if needed > remaining {
        return Err(GasAppError::Malformed);
    }

    let mut pool = Vec::with_capacity(count);
    for _ in 0..count {
        let id_raw: [u8; 4] = take(bytes, offset, 4)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)?;
        let raw = take(bytes, offset, key_len)?;

        pool.push((PreKeyId::new(u32::from_be_bytes(id_raw)), parse(raw)?));
    }

    Ok(pool)
}

/// Откусывает `len` байт, продвигая курсор.
fn take<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = offset.checked_add(len).ok_or(GasAppError::Malformed)?;
    let slice = bytes.get(*offset..end).ok_or(GasAppError::Malformed)?;
    *offset = end;

    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Пост-квантовая половина identity для тестов: один seed —
    /// одна пара, поэтому подписи в разных вызовах сходятся.
    fn test_pq() -> PqIdentityKeyPair {
        PqIdentityKeyPair::from_seed(&[0x51; 32])
    }
    use crate::pqxdh;
    use crate::pqxdh::KemPreKeyChoice;
    use gasapp_types::DeviceId;
    use rand_core::OsRng;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn later(days: i64) -> Timestamp {
        Timestamp::from_millis(
            now()
                .as_millis()
                .saturating_add(days.saturating_mul(DAY_MILLIS)),
        )
    }

    /// 🔐 Сгенерированный bundle проходит проверку подписей.
    ///
    /// Это связка генерации с проверкой: подписи, созданные здесь, обязаны
    /// приниматься тем же кодом, который проверяет чужие bundle.
    #[test]
    fn generated_bundle_verifies() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (bundle, _secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        assert!(pqxdh::verify_bundle(&bundle).is_ok());
    }

    /// Сгенерированный bundle пригоден для установления сессии.
    #[test]
    fn generated_bundle_establishes_session() {
        let responder = generate_identity(&mut OsRng).unwrap();
        let initiator = generate_identity(&mut OsRng).unwrap();

        let (bundle, mut secrets) = generate(
            &responder,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        let output = pqxdh::initiate(&initiator, &bundle, &mut OsRng).unwrap();

        assert!(!output.degraded, "полный bundle не должен быть ослабленным");

        // Получатель воспроизводит обмен своими приватными ключами.
        let one_time = output
            .one_time_pre_key_id
            .and_then(|id| secrets.take_one_time(id));
        let kem = match output.kem_choice {
            pqxdh::KemPreKeyChoice::OneTime(id) => secrets.take_one_time_kem(id).unwrap(),
            pqxdh::KemPreKeyChoice::Signed(_) => {
                MlKem1024PrivateKey::from_bytes(secrets.signed_kem.expose_secret()).unwrap()
            }
        };

        let theirs = pqxdh::respond(
            &pqxdh::ResponderKeys {
                identity: &responder,
                signed_pre_key: &secrets.signed_pre_key,
                one_time_pre_key: one_time.as_ref(),
                kem_pre_key: &kem,
            },
            initiator.public().public(),
            &output.ephemeral_public,
            &output.kem_ciphertext,
        )
        .unwrap();

        assert_eq!(output.shared_secret.expose_secret(), theirs.expose_secret());
    }

    /// Пулы создаются полного размера.
    #[test]
    fn pools_are_generated_at_full_size() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_bundle, secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        assert_eq!(secrets.one_time.len(), ONE_TIME_PRE_KEY_POOL_SIZE as usize);
        assert_eq!(
            secrets.one_time_kem.len(),
            ONE_TIME_PRE_KEY_POOL_SIZE as usize
        );
        assert!(!secrets.needs_refill());
    }

    /// Идентификаторы предключей не повторяются.
    ///
    /// Повтор означал бы, что сервер выдаст один ключ дважды под разными
    /// записями, и одноразовый ключ перестанет быть одноразовым.
    #[test]
    fn prekey_ids_are_unique() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_bundle, secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        let mut ids: Vec<u32> = secrets
            .one_time
            .iter()
            .map(|(id, _)| id.as_u32())
            .chain(secrets.one_time_kem.iter().map(|(id, _)| id.as_u32()))
            .collect();

        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();

        assert_eq!(ids.len(), total, "идентификаторы предключей повторяются");
    }

    /// Одноразовый ключ расходуется и не выдаётся повторно.
    #[test]
    fn one_time_key_is_consumed() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_bundle, mut secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        let id = secrets.one_time.first().map(|(id, _)| *id).unwrap();

        assert!(secrets.take_one_time(id).is_some());
        assert!(
            secrets.take_one_time(id).is_none(),
            "ключ выдан повторно — он перестал быть одноразовым"
        );
    }

    /// Пул пополняется до полного размера, идентификаторы продолжают нумерацию.
    #[test]
    fn refill_restores_pool_without_reusing_ids() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_bundle, mut secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        // Расходуем половину пула.
        let consumed: Vec<PreKeyId> = secrets
            .one_time
            .iter()
            .take(50)
            .map(|(id, _)| *id)
            .collect();
        for id in &consumed {
            secrets.take_one_time(*id);
        }

        assert!(secrets.needs_refill() || secrets.remaining_one_time() < 100);

        let before: Vec<u32> = secrets.one_time.iter().map(|(id, _)| id.as_u32()).collect();
        let (added, added_kem) =
            refill_one_time(&identity, &test_pq(), &mut secrets, &mut OsRng).unwrap();

        assert_eq!(secrets.one_time.len(), ONE_TIME_PRE_KEY_POOL_SIZE as usize);
        assert_eq!(added.len(), 50);
        assert!(added_kem.is_empty(), "пост-квантовый пул не расходовался");

        // Новые идентификаторы не пересекаются с прежними.
        for (id, _) in &added {
            assert!(
                !before.contains(&id.as_u32()),
                "идентификатор {} переиспользован",
                id.as_u32()
            );
        }
    }

    /// 🔐 Пополненные пост-квантовые предключи подписаны корректно.
    #[test]
    fn refilled_kem_prekeys_are_signed() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_bundle, mut secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        // Расходуем один пост-квантовый ключ.
        let id = secrets.one_time_kem.first().map(|(id, _)| *id).unwrap();
        secrets.take_one_time_kem(id);

        let (_added, added_kem) =
            refill_one_time(&identity, &test_pq(), &mut secrets, &mut OsRng).unwrap();

        assert_eq!(added_kem.len(), 1);
        for prekey in &added_kem {
            assert!(
                crate::pq_identity::hybrid_verify(
                    identity.public().public(),
                    &test_pq().public(),
                    crate::pq_identity::ONE_TIME_KEM_DOMAIN,
                    prekey.public.as_bytes(),
                    &prekey.signature,
                )
                .is_ok(),
                "подпись пополненного PQ-предключа не проходит проверку"
            );
        }
    }

    /// Ротация нужна через 7 дней, но не раньше.
    #[test]
    fn rotation_is_due_after_the_configured_period() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_bundle, secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        assert!(!secrets.needs_rotation(now()));
        assert!(!secrets.needs_rotation(later(i64::from(SIGNED_PRE_KEY_ROTATION_DAYS) - 1)));
        assert!(secrets.needs_rotation(later(i64::from(SIGNED_PRE_KEY_ROTATION_DAYS))));
    }

    /// 🔐 Ротация даёт новые ключи с корректными подписями.
    #[test]
    fn rotation_produces_fresh_signed_prekeys() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (bundle, mut secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        let old_spk = bundle.signed_pre_key.public;
        let rotate_at = later(i64::from(SIGNED_PRE_KEY_ROTATION_DAYS));

        let (spk, kem) =
            rotate_signed(&identity, &test_pq(), &mut secrets, rotate_at, &mut OsRng).unwrap();

        assert_ne!(spk.public, old_spk, "подписанный предключ не сменился");
        assert!(!secrets.needs_rotation(rotate_at), "срок сброшен");

        // Обе подписи проверяются identity-ключом владельца.
        assert!(crate::pq_identity::hybrid_verify(
            identity.public().public(),
            &test_pq().public(),
            crate::pq_identity::SIGNED_PRE_KEY_DOMAIN,
            spk.public.as_bytes(),
            &spk.signature,
        )
        .is_ok());
        assert!(crate::pq_identity::hybrid_verify(
            identity.public().public(),
            &test_pq().public(),
            crate::pq_identity::KEM_PRE_KEY_DOMAIN,
            kem.public.as_bytes(),
            &kem.signature,
        )
        .is_ok());
    }

    /// 🔐 Ротация сохраняет прежнюю пару, а не затирает её.
    ///
    /// Прежде `rotate_signed` заменял ключ на месте, и начальное
    /// сообщение, отправленное до ротации, не расшифровывалось никогда.
    #[test]
    fn rotation_retires_the_previous_pair() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_, mut secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        let previous = *secrets.signed_pre_key.expose_secret().expose_secret();
        let rotate_at = later(i64::from(SIGNED_PRE_KEY_ROTATION_DAYS));

        rotate_signed(&identity, &test_pq(), &mut secrets, rotate_at, &mut OsRng).unwrap();

        let retired = secrets
            .retired_signed
            .first()
            .expect("прежняя пара не сохранена");
        assert_eq!(
            *retired.signed_pre_key.expose_secret().expose_secret(),
            previous,
            "сохранён не тот ключ"
        );
        assert_eq!(retired.retired_at.as_millis(), rotate_at.as_millis());
    }

    /// 🔐 Выведенный ключ живёт срок конверта и не дольше.
    #[test]
    fn retired_pairs_expire_with_the_envelope_lifetime() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_, mut secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        rotate_signed(&identity, &test_pq(), &mut secrets, now(), &mut OsRng).unwrap();

        prune_retired(&mut secrets, later(RETIRED_SIGNED_KEEP_DAYS));
        assert_eq!(secrets.retired_signed.len(), 1, "удалён раньше срока");

        prune_retired(&mut secrets, later(RETIRED_SIGNED_KEEP_DAYS + 1));
        assert!(secrets.retired_signed.is_empty(), "пережил срок конверта");
    }

    /// Выведенных ключей не больше предела, даже при частых ротациях.
    #[test]
    fn retired_pairs_are_capped() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_, mut secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        for _ in 0..(MAX_RETIRED_SIGNED + 4) {
            rotate_signed(&identity, &test_pq(), &mut secrets, now(), &mut OsRng).unwrap();
        }

        assert_eq!(secrets.retired_signed.len(), MAX_RETIRED_SIGNED);
    }

    /// 🔐 Выведенные ключи переживают запись в хранилище.
    #[test]
    fn retired_pairs_survive_serialization() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_, mut secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();
        rotate_signed(&identity, &test_pq(), &mut secrets, now(), &mut OsRng).unwrap();

        let restored = PreKeySecrets::from_bytes(&secrets.to_bytes().unwrap()).unwrap();

        assert_eq!(
            restored.retired_signed.len(),
            1,
            "выведенный ключ потерян при записи"
        );
        assert_eq!(
            restored.retired_signed[0]
                .signed_pre_key
                .expose_secret()
                .expose_secret(),
            secrets.retired_signed[0]
                .signed_pre_key
                .expose_secret()
                .expose_secret()
        );
    }

    /// 🔐 Секреты старого формата (версия 1) читаются.
    ///
    /// Иначе обновление приложения сделало бы базу нечитаемой: ни одно
    /// входящее сообщение не расшифровалось бы.
    #[test]
    fn version_one_secrets_still_parse() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_, secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        // Версия 1 — это версия 2 без хвоста выведенных ключей.
        let mut bytes = secrets.to_bytes().unwrap();
        bytes.truncate(bytes.len() - 4);
        bytes[0] = SECRETS_VERSION_V1;

        let restored = PreKeySecrets::from_bytes(&bytes).expect("версия 1 не читается");

        assert!(restored.retired_signed.is_empty());
        assert_eq!(restored.one_time.len(), secrets.one_time.len());
    }

    /// Ротация сохраняет пулы одноразовых предключей.
    ///
    /// Они не связаны с подписанными и уничтожать их при ротации незачем —
    /// это лишило бы пользователя forward secrecy на ровном месте.
    #[test]
    fn rotation_preserves_one_time_pools() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_bundle, mut secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        let before = secrets.remaining_one_time();
        rotate_signed(&identity, &test_pq(), &mut secrets, later(7), &mut OsRng).unwrap();

        assert_eq!(secrets.remaining_one_time(), before);
    }

    /// Порог пополнения срабатывает до полного исчерпания.
    #[test]
    fn refill_threshold_triggers_before_exhaustion() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_bundle, mut secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        // Расходуем до порога.
        while secrets.remaining_one_time() > ONE_TIME_PRE_KEY_REFILL_THRESHOLD as usize {
            let id = secrets.one_time.first().map(|(id, _)| *id).unwrap();
            secrets.take_one_time(id);
        }

        assert!(secrets.needs_refill());
        assert!(
            secrets.remaining_one_time() > 0,
            "порог обязан срабатывать до полного исчерпания"
        );
    }

    /// Приватные ключи не печатаются в отладочном выводе.
    ///
    /// Проверяется отсутствие самих байт ключа, а не слова «Secret»:
    /// оно входит в имя типа `PreKeySecrets` и присутствует всегда.
    #[test]
    fn secrets_debug_is_redacted() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let (_bundle, secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .unwrap();

        let rendered = format!("{secrets:?}");

        assert!(rendered.contains("PreKeySecrets"));

        // Ни один байт подписанного предключа не должен просочиться.
        let spk = secrets.signed_pre_key.expose_secret();
        let hex = spk
            .expose_secret()
            .iter()
            .fold(String::new(), |mut acc, b| {
                use core::fmt::Write as _;

                let _ = write!(acc, "{b:02x}");
                acc
            });

        assert!(
            !rendered.contains(&hex),
            "приватный ключ в отладочном выводе"
        );
        // И вывод должен оставаться коротким: перечисления ключей в нём нет.
        assert!(
            rendered.len() < 128,
            "вывод подозрительно длинный: {rendered}"
        );
    }

    /// Секреты переживают запись и чтение без потери ключей.
    ///
    /// Сравниваются приватные байты, а не публичные: расхождение
    /// в приватной части означало бы, что после перезапуска устройство
    /// не расшифрует ни одного входящего сообщения.
    #[test]
    fn prekey_secrets_round_trip() {
        let identity = generate_identity(&mut OsRng).expect("identity");
        let (_, secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .expect("предключи");

        let bytes = secrets.to_bytes().expect("сериализуется");
        let restored = PreKeySecrets::from_bytes(&bytes).expect("разбирается");

        assert_eq!(
            restored.signed_pre_key.expose_secret().expose_secret(),
            secrets.signed_pre_key.expose_secret().expose_secret()
        );
        assert_eq!(
            restored.signed_kem.expose_secret(),
            secrets.signed_kem.expose_secret()
        );
        assert_eq!(restored.one_time.len(), secrets.one_time.len());
        assert_eq!(restored.one_time_kem.len(), secrets.one_time_kem.len());
        assert_eq!(
            restored.signed_pre_key_created.as_millis(),
            secrets.signed_pre_key_created.as_millis()
        );

        // Идентификаторы обязаны совпасть: по ним получатель находит
        // приватную часть предключа, который израсходовал отправитель.
        for (restored_key, original) in restored.one_time.iter().zip(secrets.one_time.iter()) {
            assert_eq!(restored_key.0, original.0);
            assert_eq!(
                restored_key.1.expose_secret().expose_secret(),
                original.1.expose_secret().expose_secret()
            );
        }
    }

    /// Восстановленные секреты действительно расшифровывают сессию.
    ///
    /// Проверка сильнее сравнения байтов: она ловит случай, когда ключи
    /// совпали, а идентификаторы пулов разъехались.
    #[test]
    fn restored_secrets_still_complete_pqxdh() {
        let bob_identity = generate_identity(&mut OsRng).expect("identity");
        let (bundle, secrets) = generate(
            &bob_identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .expect("предключи");

        let restored =
            PreKeySecrets::from_bytes(&secrets.to_bytes().expect("сериализуется")).expect("разбор");

        let alice_identity = generate_identity(&mut OsRng).expect("identity");
        let output = pqxdh::initiate(&alice_identity, &bundle, &mut OsRng).expect("инициация");

        let one_time = output.one_time_pre_key_id.and_then(|id| {
            restored
                .one_time
                .iter()
                .find(|(key_id, _)| *key_id == id)
                .map(|(_, key)| key)
        });

        let kem_pre_key = match output.kem_choice {
            KemPreKeyChoice::OneTime(id) => restored
                .one_time_kem
                .iter()
                .find(|(key_id, _)| *key_id == id)
                .map(|(_, key)| key)
                .expect("одноразовый пост-квантовый предключ на месте"),
            KemPreKeyChoice::Signed(_) => &restored.signed_kem,
        };

        let shared = pqxdh::respond(
            &pqxdh::ResponderKeys {
                identity: &bob_identity,
                signed_pre_key: &restored.signed_pre_key,
                one_time_pre_key: one_time,
                kem_pre_key,
            },
            bob_identity.public().public(),
            &output.ephemeral_public,
            &output.kem_ciphertext,
        );

        // Секрет должен сойтись: иначе после перезапуска устройства
        // все входящие первые сообщения перестали бы расшифровываться.
        assert!(shared.is_ok(), "восстановленные секреты не завершили PQXDH");
    }

    #[test]
    fn corrupted_secrets_are_rejected() {
        let identity = generate_identity(&mut OsRng).expect("identity");
        let (_, secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .expect("предключи");

        let bytes = secrets.to_bytes().expect("сериализуется");

        // Неизвестная версия формата.
        let mut wrong_version = bytes.clone();
        wrong_version[0] = SECRETS_VERSION.wrapping_add(1);
        assert!(PreKeySecrets::from_bytes(&wrong_version).is_err());

        // Обрыв данных: повреждение базы не должно приводить к панике.
        for cut in [1usize, 16, 64, bytes.len().wrapping_div(2)] {
            let truncated = bytes.get(..cut).expect("срез в границах");
            assert!(
                PreKeySecrets::from_bytes(truncated).is_err(),
                "обрезка до {cut} байт разобралась вместо отказа"
            );
        }

        // Хвост: база хранит не то, что мы писали.
        let mut with_tail = bytes;
        with_tail.push(0);
        assert!(PreKeySecrets::from_bytes(&with_tail).is_err());
    }

    /// Огромный счётчик пула отвергается без попытки выделить память.
    #[test]
    fn absurd_pool_count_is_rejected() {
        let identity = generate_identity(&mut OsRng).expect("identity");
        let (_, secrets) = generate(
            &identity,
            &test_pq(),
            DeviceId::generate(),
            now(),
            &mut OsRng,
        )
        .expect("предключи");

        let mut bytes = secrets.to_bytes().expect("сериализуется");

        // Счётчик первого пула лежит сразу после ключа, метки времени
        // и seed пост-квантового ключа.
        let count_offset = 1 + 32 + 8 + KEM_SEED_LEN;
        bytes
            .get_mut(count_offset..count_offset + 4)
            .expect("счётчик в границах")
            .copy_from_slice(&u32::MAX.to_be_bytes());

        assert!(PreKeySecrets::from_bytes(&bytes).is_err());
    }
}
