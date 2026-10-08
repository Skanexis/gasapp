// SPDX-License-Identifier: AGPL-3.0-only

//! Пропуска: анонимные одноразовые права, выданные вслепую.
//!
//! # Что это и зачем
//!
//! Подписка на канал анонимна: сервер не знает, кто читает канал.
//! Но анонимное действие без цены повторяется сколько угодно — счётчик
//! подписчиков накручивался циклом, а proof-of-work лишь замедлял это.
//! Пропуск связывает действие с аккаунтом **по числу**, не связывая
//! **по личности**:
//!
//! * выдаётся аккаунту за подписью устройства, не больше
//!   [`gasapp_server_db::passes::PASSES_PER_DAY`] в сутки;
//! * тратится анонимно, один раз;
//! * сервер не может связать потраченный пропуск с выданным: при
//!   выдаче он подписывает замаскированную точку, при трате видит зерно.
//!
//! Конструкция — слепая подпись на ristretto255 с доказательством DLEQ,
//! как в Privacy Pass. Клиентская половина и подробности —
//! `crates/gasapp-protocol/src/pass.rs`; общий эталонный вектор ловит
//! расхождение половин.
//!
//! # 🔐 Что остаётся в базе
//!
//! Сколько пропусков аккаунт взял сегодня (число, без каналов) и хеши
//! потраченных зёрен (без аккаунтов). Связи между ними в базе нет
//! и восстановить её нечем.
//!
//! # ⚠️ Чего сервер честно НЕ может обещать
//!
//! Что он не ведёт журнал времени выдачи и траты: по времени пару
//! «взял пропуск — тут же подписался» сопоставить можно. Приложение
//! берёт пропуска заранее и пачкой, чтобы пара не стояла рядом.

// Лимит `arithmetic_side_effects` рассчитан на целочисленное
// переполнение; операции над скалярами и точками кривой не переполняются.
#![allow(clippy::arithmetic_side_effects)]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity as _;
use hmac::{Hmac, Mac as _};
use rand_core::RngCore as _;
use sha2::{Digest as _, Sha256, Sha512};
use subtle::ConstantTimeEq as _;

/// Длина сжатой точки, скаляра, зерна и кода траты.
pub const LEN: usize = 32;

/// Длина доказательства DLEQ: вызов и ответ.
pub const PROOF_LEN: usize = 64;

const KEY_DOMAIN: &[u8] = b"GASAPP_PASS_v1_KEY";
const POINT_DOMAIN: &[u8] = b"GASAPP_PASS_v1_POINT";
const DLEQ_DOMAIN: &[u8] = b"GASAPP_PASS_v1_DLEQ";
const REDEEM_DOMAIN: &[u8] = b"GASAPP_PASS_v1_REDEEM";
const SUBSCRIBE_DOMAIN: &[u8] = b"GASAPP_PASS_v1_SUBSCRIBE";

/// Ключ, которым узел подписывает пропуска.
///
/// Выводится из ключа подписи сертификатов: тот уже общий для всех
/// узлов и уже хранится как секрет. Отдельная переменная была бы ещё
/// одним местом, где узлы могут разойтись, — а пропуск, выданный одним
/// узлом, обязан приниматься другим.
#[derive(Clone)]
pub struct PassKey {
    secret: Scalar,
}

impl core::fmt::Debug for PassKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Секрет в отладочный вывод не попадает.
        formatter.debug_struct("PassKey").finish_non_exhaustive()
    }
}

impl PassKey {
    /// Ключ пропусков узла по общему секрету узлов.
    #[must_use]
    pub fn derive(master: &[u8; 32]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(KEY_DOMAIN);
        hasher.update(master);

        Self {
            secret: Scalar::from_bytes_mod_order_wide(&hasher.finalize().into()),
        }
    }

    /// Публичная половина — её клиент сверяет с доказательством.
    #[must_use]
    pub fn public(&self) -> [u8; LEN] {
        (self.secret * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes()
    }

    /// Подписывает замаскированную точку и доказывает, что подписал
    /// объявленным ключом. `None` — прислана не точка кривой.
    #[must_use]
    pub fn sign(&self, blinded: &[u8; LEN]) -> Option<([u8; LEN], [u8; PROOF_LEN])> {
        let mut wide = [0u8; 64];
        rand_core::OsRng.fill_bytes(&mut wide);

        self.sign_with(blinded, Scalar::from_bytes_mod_order_wide(&wide))
    }

    fn sign_with(
        &self,
        blinded: &[u8; LEN],
        nonce: Scalar,
    ) -> Option<([u8; LEN], [u8; PROOF_LEN])> {
        let point = CompressedRistretto(*blinded).decompress()?;

        // Нейтральный элемент под любым ключом остаётся собой: подписывать
        // его — значит выдать «пропуск», который принял бы кто угодно.
        if point == RistrettoPoint::identity() {
            return None;
        }

        let signed = (self.secret * point).compress();
        let challenge = dleq_challenge([
            &CompressedRistretto(self.public()),
            &CompressedRistretto(*blinded),
            &signed,
            &(nonce * RISTRETTO_BASEPOINT_POINT).compress(),
            &(nonce * point).compress(),
        ]);
        let response = nonce + challenge * self.secret;

        let mut proof = [0u8; PROOF_LEN];
        let (head, tail) = proof.split_at_mut(LEN);
        head.copy_from_slice(challenge.as_bytes());
        tail.copy_from_slice(response.as_bytes());

        Some((signed.to_bytes(), proof))
    }

    /// Настоящий ли это пропуск и на это ли действие он тратится.
    ///
    /// Сервер сам считает секрет пропуска `k·H1(seed)` и сверяет код
    /// траты. Потрачен ли пропуск раньше, здесь не проверяется — это
    /// знает база (`gasapp_server_db::passes::spend`).
    #[must_use]
    pub fn accepts(&self, seed: &[u8; LEN], binding: &[u8], mac: &[u8; LEN]) -> bool {
        let secret = (self.secret * point_of(seed)).compress().to_bytes();

        // `new_from_slice` не отказывает ни для какой длины ключа HMAC.
        let Ok(mut expected) = Hmac::<Sha256>::new_from_slice(&secret) else {
            return false;
        };
        expected.update(REDEEM_DOMAIN);
        expected.update(&Sha256::digest(binding));

        bool::from(expected.finalize().into_bytes().as_slice().ct_eq(mac))
    }
}

/// К чему привязана трата пропуска на подписку: канал и жетон.
///
/// ⚠️ Продублировано у клиента (`gasapp-net::pass`); эталон — тест.
#[must_use]
pub fn subscribe_binding(channel_id: &str, token: &[u8]) -> Vec<u8> {
    let channel = channel_id.to_ascii_lowercase();
    let mut binding = Vec::with_capacity(SUBSCRIBE_DOMAIN.len() + 16 + channel.len() + token.len());

    binding.extend_from_slice(SUBSCRIBE_DOMAIN);
    for field in [channel.as_bytes(), token] {
        binding.extend_from_slice(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        binding.extend_from_slice(field);
    }

    binding
}

/// Точка кривой по зерну пропуска.
fn point_of(seed: &[u8; LEN]) -> RistrettoPoint {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> PassKey {
        PassKey {
            secret: Scalar::from_bytes_mod_order_wide(&[7; 64]),
        }
    }

    /// Эталон: те же числа проверяет клиентская реализация
    /// (`gasapp-protocol::pass`). Здесь клиентская половина — снятие
    /// маски — повторена в тесте вручную.
    #[test]
    fn matches_the_shared_vector() {
        let key = fixed_key();
        let seed = [0x11u8; LEN];
        let blind = Scalar::from_bytes_mod_order_wide(&[0x22; 64]);
        let blinded = (blind * point_of(&seed)).compress().to_bytes();

        let (signed, _) = key
            .sign_with(&blinded, Scalar::from_bytes_mod_order_wide(&[0x5a; 64]))
            .unwrap();
        let secret = (blind.invert() * CompressedRistretto(signed).decompress().unwrap())
            .compress()
            .to_bytes();

        assert_eq!(
            hex::encode(key.public()),
            "505c1ac377c03a99e02454097496925ce2b785cd0dbbf36719d444f964b95c15"
        );
        assert_eq!(
            hex::encode(secret),
            "cef3d1498ef9dbff16b5d505743219e7268ed6977303b8c1ec0c826e2afccc4e"
        );

        let mac: [u8; LEN] =
            hex::decode("9cf4975233e793cf2ed8f1da5d482e9bcf5bbff2a3e455ab1588ccfc980442f1")
                .unwrap()
                .try_into()
                .unwrap();
        assert!(key.accepts(&seed, b"binding", &mac));
        // 🔐 Не на то действие, не тот пропуск, не тот ключ.
        assert!(!key.accepts(&seed, b"other", &mac));
        assert!(!key.accepts(&[0x12; LEN], b"binding", &mac));
        assert!(!PassKey::derive(&[1; 32]).accepts(&seed, b"binding", &mac));
    }

    /// Не точку кривой и нейтральный элемент узел не подписывает.
    #[test]
    fn junk_is_not_signed() {
        let key = fixed_key();

        assert!(key.sign(&[0xff; LEN]).is_none());
        assert!(key.sign(&[0; LEN]).is_none());
        assert!(key
            .sign(&RISTRETTO_BASEPOINT_POINT.compress().to_bytes())
            .is_some());
    }

    /// Все узлы с одним общим секретом подписывают одним ключом.
    #[test]
    fn nodes_sharing_the_secret_share_the_key() {
        assert_eq!(
            PassKey::derive(&[9; 32]).public(),
            PassKey::derive(&[9; 32]).public()
        );
        assert_ne!(
            PassKey::derive(&[9; 32]).public(),
            PassKey::derive(&[8; 32]).public()
        );
    }

    #[test]
    fn the_binding_separates_channels_and_tokens() {
        let first = subscribe_binding("AAAAAAAA-0000-0000-0000-000000000001", &[1; 32]);

        assert_eq!(
            first,
            subscribe_binding("aaaaaaaa-0000-0000-0000-000000000001", &[1; 32])
        );
        assert_ne!(
            first,
            subscribe_binding("aaaaaaaa-0000-0000-0000-000000000002", &[1; 32])
        );
        assert_ne!(
            first,
            subscribe_binding("aaaaaaaa-0000-0000-0000-000000000001", &[2; 32])
        );
    }
}
