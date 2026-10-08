// SPDX-License-Identifier: Apache-2.0

//! Пропуска: анонимные одноразовые права, которые сервер выдаёт вслепую.
//!
//! # Зачем
//!
//! Подписка на канал анонимна — сервер не должен знать, кто читает
//! канал. Но анонимное действие без цены повторяется сколько угодно:
//! счётчик подписчиков накручивался циклом, и «работа» (proof-of-work)
//! лишь делала это чуть медленнее. Пропуск решает обе задачи сразу:
//!
//! * выдаётся **аккаунту** (за подписью устройства) и в ограниченном
//!   числе — накрутить подписчиков можно лишь настолько, сколько
//!   у нападающего аккаунтов, а аккаунт стоит подтверждённой почты;
//! * тратится **анонимно** — и сервер не может связать потраченный
//!   пропуск с тем, кому он его выдал.
//!
//! # Как
//!
//! Слепая подпись на эллиптической кривой (ristretto255) — та же
//! конструкция, что в Privacy Pass:
//!
//! ```text
//! клиент:  seed ← 32 случайных байта;  T = H1(seed)
//!          r ← случайный скаляр;       P = r·T          → серверу
//! сервер:  Q = k·P,  доказательство DLEQ: log_G(K) = log_P(Q)   → клиенту
//! клиент:  проверяет доказательство;   W = r⁻¹·Q = k·T
//! трата:   seed и HMAC(W, привязка)    → серверу, анонимно
//! сервер:  считает W = k·H1(seed) сам, сверяет HMAC, помечает seed
//!          потраченным
//! ```
//!
//! Сервер видел `P`, а при трате видит `seed` — и связать их не может:
//! `P` замаскирован случайным `r`, которого сервер не знает.
//!
//! # 🔐 Что проверяет доказательство и зачем оно клиенту
//!
//! Без него сервер мог бы подписывать пропуска **разными** ключами —
//! своим для каждого аккаунта — и при трате узнавать, чей пропуск, по
//! тому, каким ключом он проверился. Доказательство DLEQ показывает,
//! что подписано тем самым ключом `K`, который сервер объявил всем.
//!
//! # ⚠️ Чего это не даёт
//!
//! * **Время.** Сервер видит, что аккаунт взял пропуска в такой-то час
//!   и что вскоре кто-то анонимно подписался. Приложение берёт пропуска
//!   заранее и пачкой, а не перед подпиской, — но если запаса не было,
//!   выдача и трата стоят рядом.
//! * **Один ключ на всех — допущение.** Клиент сверяет ключ сервера
//!   только с тем, что тот отдал ему самому. Сервер, показывающий
//!   разным клиентам разные ключи, различил бы их; журнала ключей для
//!   этого ключа нет.
//! * **Не пост-квантово.** Квантовый противник, записавший выдачу,
//!   снял бы слепоту. Раскрылось бы «какой аккаунт читает какой канал»
//!   — не содержимое.
//!
//! Серверная половина продублирована в `gasapp-server-api::pass`
//! (разные лицензии); расхождение ловит общий эталонный вектор.

// Лимит `arithmetic_side_effects` рассчитан на целочисленное
// переполнение; операции над скалярами и точками кривой не переполняются.
#![allow(clippy::arithmetic_side_effects)]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity as _;
use hmac::{Hmac, Mac as _};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256, Sha512};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize as _;

use gasapp_types::{GasAppError, Result};

/// Длина зерна пропуска.
pub const SEED_LEN: usize = 32;

/// Длина сжатой точки и скаляра.
pub const POINT_LEN: usize = 32;

/// Длина доказательства DLEQ: вызов и ответ.
pub const PROOF_LEN: usize = 64;

/// Длина кода траты.
pub const MAC_LEN: usize = 32;

const POINT_DOMAIN: &[u8] = b"GASAPP_PASS_v1_POINT";
const DLEQ_DOMAIN: &[u8] = b"GASAPP_PASS_v1_DLEQ";
const REDEEM_DOMAIN: &[u8] = b"GASAPP_PASS_v1_REDEEM";
const SUBSCRIBE_DOMAIN: &[u8] = b"GASAPP_PASS_v1_SUBSCRIBE";
const KEY_DOMAIN: &[u8] = b"GASAPP_PASS_v1_KEY";

/// К чему привязана трата пропуска на подписку: канал и жетон.
///
/// ⚠️ Продублировано на сервере (`gasapp-server-api::pass`); эталон — тест.
#[must_use]
pub fn subscribe_binding(channel_uuid: &str, token: &[u8]) -> Vec<u8> {
    let channel = channel_uuid.to_ascii_lowercase();
    let mut binding = Vec::with_capacity(
        SUBSCRIBE_DOMAIN
            .len()
            .saturating_add(16)
            .saturating_add(channel.len())
            .saturating_add(token.len()),
    );

    binding.extend_from_slice(SUBSCRIBE_DOMAIN);
    for field in [channel.as_bytes(), token] {
        binding.extend_from_slice(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        binding.extend_from_slice(field);
    }

    binding
}

/// Точка кривой по зерну пропуска.
fn point_of(seed: &[u8; SEED_LEN]) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(POINT_DOMAIN);
    hasher.update(seed);

    RistrettoPoint::from_uniform_bytes(&hasher.finalize().into())
}

/// Вызов доказательства DLEQ по всему, что в нём участвует.
fn dleq_challenge(points: [&CompressedRistretto; 5]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(DLEQ_DOMAIN);
    hasher.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    for point in points {
        hasher.update(point.as_bytes());
    }

    Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
}

fn decompress(bytes: &[u8; POINT_LEN]) -> Result<RistrettoPoint> {
    let point = CompressedRistretto(*bytes)
        .decompress()
        .ok_or(GasAppError::Malformed)?;

    // Нейтральный элемент — не пропуск: под любым ключом он остаётся
    // собой и ничего не доказывает.
    if point == RistrettoPoint::identity() {
        return Err(GasAppError::Malformed);
    }

    Ok(point)
}

/// Заготовка пропуска: то, что клиент помнит, пока сервер подписывает.
pub struct PendingPass {
    seed: [u8; SEED_LEN],
    blind: Scalar,
    blinded: CompressedRistretto,
}

impl Drop for PendingPass {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.blind.zeroize();
    }
}

/// Готовит заготовку: случайное зерно и его замаскированную точку.
pub fn prepare<R: RngCore + CryptoRng>(rng: &mut R) -> PendingPass {
    let mut seed = [0u8; SEED_LEN];
    rng.fill_bytes(&mut seed);

    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    let mut blind = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();

    // Нулевой множитель обнулил бы точку; вероятность — 2⁻²⁵², но
    // проверка дешевле рассуждения.
    if blind == Scalar::ZERO {
        blind = Scalar::ONE;
    }

    PendingPass {
        blinded: (blind * point_of(&seed)).compress(),
        seed,
        blind,
    }
}

impl PendingPass {
    /// Замаскированная точка — то, что уходит серверу на подпись.
    #[must_use]
    pub fn blinded(&self) -> [u8; POINT_LEN] {
        self.blinded.to_bytes()
    }

    /// Проверяет подпись сервера и снимает маску.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — ответ сервера не точка кривой;
    /// * [`GasAppError::InvalidSignature`] — 🔐 доказательство не
    ///   сходится: подписано не тем ключом, который сервер объявил.
    ///   Такой пропуск выдал бы владельца при трате — он не принимается.
    pub fn finish(
        self,
        server_key: &[u8; POINT_LEN],
        signed: &[u8; POINT_LEN],
        proof: &[u8; PROOF_LEN],
    ) -> Result<Pass> {
        let key = decompress(server_key)?;
        let signed_point = decompress(signed)?;
        let blinded_point = decompress(&self.blinded.to_bytes())?;

        let (challenge_bytes, response_bytes) = proof.split_at(POINT_LEN);
        let challenge = scalar_of(challenge_bytes)?;
        let response = scalar_of(response_bytes)?;

        // A = s·G − c·K,  B = s·P − c·Q — и вызов обязан из них получиться.
        let commit_base = response * RISTRETTO_BASEPOINT_POINT - challenge * key;
        let commit_blinded = response * blinded_point - challenge * signed_point;

        let expected = dleq_challenge([
            &CompressedRistretto(*server_key),
            &self.blinded,
            &CompressedRistretto(*signed),
            &commit_base.compress(),
            &commit_blinded.compress(),
        ]);

        if !bool::from(expected.as_bytes().ct_eq(challenge.as_bytes())) {
            return Err(GasAppError::InvalidSignature);
        }

        Ok(Pass {
            seed: self.seed,
            secret: (self.blind.invert() * signed_point).compress().to_bytes(),
        })
    }
}

fn scalar_of(bytes: &[u8]) -> Result<Scalar> {
    let bytes: [u8; POINT_LEN] = bytes.try_into().map_err(|_| GasAppError::Malformed)?;

    Option::from(Scalar::from_canonical_bytes(bytes)).ok_or(GasAppError::Malformed)
}

/// Готовый пропуск: зерно и секрет `k·H1(seed)`, известный только
/// клиенту и серверу.
#[derive(Clone, PartialEq, Eq)]
pub struct Pass {
    seed: [u8; SEED_LEN],
    secret: [u8; POINT_LEN],
}

impl core::fmt::Debug for Pass {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Ни зерно, ни секрет в отладочный вывод не попадают.
        formatter.debug_struct("Pass").finish_non_exhaustive()
    }
}

impl Drop for Pass {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.secret.zeroize();
    }
}

impl Pass {
    /// Собирает пропуск из сохранённых половин.
    #[must_use]
    pub const fn from_parts(seed: [u8; SEED_LEN], secret: [u8; POINT_LEN]) -> Self {
        Self { seed, secret }
    }

    /// Зерно — уходит серверу при трате.
    #[must_use]
    pub const fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// Секрет — хранится на устройстве, серверу при трате не уходит.
    #[must_use]
    pub const fn secret(&self) -> &[u8; POINT_LEN] {
        &self.secret
    }

    /// Код траты: доказывает знание секрета и привязывает пропуск
    /// к тому, на что он тратится.
    ///
    /// 🔐 Сам секрет по сети не идёт. Перехвативший запрос не потратит
    /// пропуск на другое: код сходится только с этой `binding`.
    #[must_use]
    pub fn redeem(&self, binding: &[u8]) -> [u8; MAC_LEN] {
        redeem_mac(&self.secret, binding)
    }
}

/// Код траты по секрету пропуска и привязке.
fn redeem_mac(secret: &[u8; POINT_LEN], binding: &[u8]) -> [u8; MAC_LEN] {
    // `new_from_slice` не отказывает ни для какой длины ключа HMAC.
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return [0u8; MAC_LEN];
    };
    mac.update(REDEEM_DOMAIN);
    mac.update(&Sha256::digest(binding));

    mac.finalize().into_bytes().into()
}

/// Серверная половина — выдача и проверка пропусков.
///
/// Настоящий сервер считает то же самое своим кодом
/// (`gasapp-server-api::pass`, другая лицензия). Здесь она нужна
/// тестам клиента: поддельному серверу, который выдаёт и принимает
/// пропуска так же, как настоящий. Приложение её не вызывает.
pub struct Issuer {
    key: Scalar,
}

impl Issuer {
    /// Ключ пропусков по общему секрету узлов — как на сервере.
    #[must_use]
    pub fn derive(master: &[u8; 32]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(KEY_DOMAIN);
        hasher.update(master);

        Self {
            key: Scalar::from_bytes_mod_order_wide(&hasher.finalize().into()),
        }
    }

    /// Публичная половина ключа.
    #[must_use]
    pub fn public(&self) -> [u8; POINT_LEN] {
        (self.key * RISTRETTO_BASEPOINT_POINT).compress().to_bytes()
    }

    /// Подписывает замаскированную точку и доказывает, каким ключом.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — прислана не точка кривой.
    pub fn sign<R: RngCore + CryptoRng>(
        &self,
        blinded: &[u8; POINT_LEN],
        rng: &mut R,
    ) -> Result<([u8; POINT_LEN], [u8; PROOF_LEN])> {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);

        self.sign_with(blinded, Scalar::from_bytes_mod_order_wide(&wide))
    }

    fn sign_with(
        &self,
        blinded: &[u8; POINT_LEN],
        nonce: Scalar,
    ) -> Result<([u8; POINT_LEN], [u8; PROOF_LEN])> {
        let point = decompress(blinded)?;
        let signed = (self.key * point).compress();
        let challenge = dleq_challenge([
            &CompressedRistretto(self.public()),
            &CompressedRistretto(*blinded),
            &signed,
            &(nonce * RISTRETTO_BASEPOINT_POINT).compress(),
            &(nonce * point).compress(),
        ]);

        let mut proof = [0u8; PROOF_LEN];
        let (head, tail) = proof.split_at_mut(POINT_LEN);
        head.copy_from_slice(challenge.as_bytes());
        tail.copy_from_slice((nonce + challenge * self.key).as_bytes());

        Ok((signed.to_bytes(), proof))
    }

    /// Настоящий ли это пропуск и на это ли он тратится.
    #[must_use]
    pub fn accepts(&self, seed: &[u8; SEED_LEN], binding: &[u8], mac: &[u8; MAC_LEN]) -> bool {
        let secret = (self.key * point_of(seed)).compress().to_bytes();

        bool::from(redeem_mac(&secret, binding).ct_eq(mac))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    /// Выдающая сторона с заданным ключом — для эталонного вектора.
    fn issuer(byte: u8) -> Issuer {
        Issuer {
            key: Scalar::from_bytes_mod_order_wide(&[byte; 64]),
        }
    }

    fn nonce() -> Scalar {
        Scalar::from_bytes_mod_order_wide(&[0x5a; 64])
    }

    #[test]
    fn an_issued_pass_is_accepted_once_bound() {
        let server = issuer(7);
        let pending = prepare(&mut OsRng);
        let (signed, proof) = server.sign_with(&pending.blinded(), nonce()).unwrap();

        let pass = pending.finish(&server.public(), &signed, &proof).unwrap();
        let mac = pass.redeem(b"channel-1");

        assert!(server.accepts(pass.seed(), b"channel-1", &mac));
        // 🔐 Тот же код на другое действие не годится.
        assert!(!server.accepts(pass.seed(), b"channel-2", &mac));
        // И чужой ключ пропуск не принимает.
        assert!(!issuer(8).accepts(pass.seed(), b"channel-1", &mac));
    }

    /// 🔐 Сервер не видит при трате того, что видел при выдаче.
    #[test]
    fn what_is_signed_does_not_reveal_what_is_spent() {
        let server = issuer(7);
        let pending = prepare(&mut OsRng);
        let blinded = pending.blinded();
        let (signed, proof) = server.sign_with(&blinded, nonce()).unwrap();
        let pass = pending.finish(&server.public(), &signed, &proof).unwrap();

        assert_ne!(&blinded, pass.seed());
        assert_ne!(blinded, point_of(pass.seed()).compress().to_bytes());
        assert_ne!(&signed, pass.secret());
    }

    /// 🔐 Подпись другим ключом — способ пометить клиента — отвергается.
    #[test]
    fn a_pass_signed_with_another_key_is_refused() {
        let honest = issuer(7);
        let marking = issuer(9);

        let pending = prepare(&mut OsRng);
        let (signed, proof) = marking.sign_with(&pending.blinded(), nonce()).unwrap();
        assert!(matches!(
            pending.finish(&honest.public(), &signed, &proof),
            Err(GasAppError::InvalidSignature)
        ));

        // Испорченное доказательство — тоже.
        let pending = prepare(&mut OsRng);
        let (signed, mut proof) = honest.sign_with(&pending.blinded(), nonce()).unwrap();
        proof[40] ^= 1;
        assert!(pending.finish(&honest.public(), &signed, &proof).is_err());
    }

    #[test]
    fn junk_from_the_server_is_refused() {
        let server = issuer(7);
        let pending = prepare(&mut OsRng);
        let (signed, proof) = server.sign_with(&pending.blinded(), nonce()).unwrap();

        // Не точка кривой и нейтральный элемент.
        for bad in [[0xffu8; 32], [0u8; 32]] {
            let again = PendingPass {
                seed: pending.seed,
                blind: pending.blind,
                blinded: pending.blinded,
            };
            assert!(again.finish(&server.public(), &bad, &proof).is_err());
        }

        // Неканоничный скаляр в доказательстве.
        let mut wild = proof;
        wild[32..].copy_from_slice(&[0xff; 32]);
        assert!(pending.finish(&server.public(), &signed, &wild).is_err());
    }

    /// Эталон: те же числа проверяет серверная реализация
    /// (`gasapp-server-api::pass`). Расхождение половин означало бы, что
    /// ни один пропуск не принимается.
    #[test]
    fn matches_the_shared_vector() {
        let server = issuer(7);
        let seed = [0x11u8; SEED_LEN];
        let blind = Scalar::from_bytes_mod_order_wide(&[0x22; 64]);
        let pending = PendingPass {
            blinded: (blind * point_of(&seed)).compress(),
            seed,
            blind,
        };

        let (signed, proof) = server.sign_with(&pending.blinded(), nonce()).unwrap();
        let pass = pending.finish(&server.public(), &signed, &proof).unwrap();

        assert_eq!(hex(&server.public()), VECTOR_PUBLIC);
        assert_eq!(hex(pass.secret()), VECTOR_SECRET);
        assert_eq!(hex(&pass.redeem(b"binding")), VECTOR_MAC);
    }

    /// Привязка подписки совпадает с серверной: эталон посчитан
    /// независимо (Python, hashlib), тот же проверяет сервер.
    #[test]
    fn the_subscribe_binding_matches_the_reference() {
        let binding = subscribe_binding("AAAAAAAA-0000-0000-0000-000000000001", &[7; 32]);

        assert_eq!(&hex(&Sha256::digest(&binding))[..16], "3e059f1e20201add");
    }

    /// Ключ по общему секрету выводится так же, как на сервере, и
    /// пропуск проходит полный круг со случайной маской.
    #[test]
    fn a_derived_issuer_serves_a_full_round() {
        let server = Issuer::derive(&[9; 32]);
        let pending = prepare(&mut OsRng);
        let (signed, proof) = server.sign(&pending.blinded(), &mut OsRng).unwrap();
        let pass = pending.finish(&server.public(), &signed, &proof).unwrap();

        assert!(server.accepts(pass.seed(), b"x", &pass.redeem(b"x")));
        assert!(server.sign(&[0xff; 32], &mut OsRng).is_err());
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;

        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    const VECTOR_PUBLIC: &str = "505c1ac377c03a99e02454097496925ce2b785cd0dbbf36719d444f964b95c15";
    const VECTOR_SECRET: &str = "cef3d1498ef9dbff16b5d505743219e7268ed6977303b8c1ec0c826e2afccc4e";
    const VECTOR_MAC: &str = "9cf4975233e793cf2ed8f1da5d482e9bcf5bbff2a3e455ab1588ccfc980442f1";
}
