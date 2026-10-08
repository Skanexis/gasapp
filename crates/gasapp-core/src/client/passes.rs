// SPDX-License-Identifier: Apache-2.0

//! Запас пропусков — анонимных одноразовых прав на подписку.
//!
//! Криптография — в `gasapp_protocol::pass`. Здесь — когда пропуска
//! берутся и как тратятся:
//!
//! * **берутся** у сервера за подписью устройства, пачкой и заранее —
//!   когда запас на исходе, а не перед самой подпиской. Так сервер не
//!   видит пару «аккаунт взял пропуск — через секунду кто-то анонимно
//!   подписался»;
//! * **тратятся** без подписи устройства, отдельной цепочкой Tor:
//!   серверу достаются зерно и код траты, которые он не может связать
//!   с тем, что подписывал.
//!
//! 🔐 Пропуск, чьё доказательство не сошлось, в запас не попадает
//! вместе со всей пачкой: сервер, подписавший «не тем» ключом, пытался
//! пометить это устройство.

use gasapp_net::api::IssuePassesRequest;
use gasapp_net::client::Transport;
use gasapp_protocol::pass::{self, Pass};
use gasapp_types::{GasAppError, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::{hex, unhex, Client, DeviceSigner};

/// Сколько пропусков берётся за один раз.
///
/// Пачкой, чтобы выдача не совпадала по времени с каждой подпиской;
/// небольшой, чтобы не выбирать суточный предел аккаунта впустую.
const BATCH: usize = 8;

/// При каком запасе пора брать новую пачку.
const LOW_WATER: u32 = 3;

impl<T: Transport> Client<T> {
    /// Пополняет запас пропусков, если он на исходе. Возвращает, сколько
    /// пропусков добавилось.
    ///
    /// Вызывается заранее — при открытии списка каналов, — чтобы
    /// к моменту подписки запас уже был.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — аккаунт не зарегистрирован;
    /// * [`GasAppError::InvalidSignature`] — 🔐 сервер подписал пропуска
    ///   не тем ключом, который объявил: пачка отброшена целиком;
    /// * [`GasAppError::Network`] — сервер недоступен либо суточный
    ///   предел пропусков исчерпан.
    pub fn refill_passes<R: RngCore + CryptoRng>(
        &self,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<u32> {
        if self.storage.count_passes()? >= LOW_WATER {
            return Ok(0);
        }

        let (device_id, identity) = self.own_device()?;
        let pending: Vec<_> = (0..BATCH).map(|_| pass::prepare(rng)).collect();

        let issued = self.api.issue_passes(
            &device_id,
            &IssuePassesRequest {
                blinded: pending.iter().map(|one| hex(&one.blinded())).collect(),
            },
            &DeviceSigner::new(&identity, now),
        )?;

        if issued.signed.len() != pending.len() {
            return Err(GasAppError::Malformed);
        }

        let key: [u8; pass::POINT_LEN] = unhex(&issued.key)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)?;

        // Вся пачка либо ни одного: один негодный пропуск означает, что
        // серверу в этой выдаче верить нельзя.
        let mut fresh = Vec::with_capacity(pending.len());
        for (one, signed) in pending.into_iter().zip(&issued.signed) {
            let point: [u8; pass::POINT_LEN] = unhex(&signed.point)?
                .try_into()
                .map_err(|_| GasAppError::Malformed)?;
            let proof: [u8; pass::PROOF_LEN] = unhex(&signed.proof)?
                .try_into()
                .map_err(|_| GasAppError::Malformed)?;

            let finished = one.finish(&key, &point, &proof)?;
            fresh.push((*finished.seed(), *finished.secret()));
        }

        self.storage.store_passes(&fresh)?;

        Ok(u32::try_from(fresh.len()).unwrap_or(u32::MAX))
    }

    /// Забирает пропуск из запаса; если запас пуст — берёт новую пачку.
    pub(super) fn take_pass<R: RngCore + CryptoRng>(
        &self,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Pass> {
        if let Some((seed, secret)) = self.storage.take_pass()? {
            return Ok(Pass::from_parts(seed, secret));
        }

        // ⚠️ Запаса не было: выдача и трата окажутся рядом по времени.
        // Чтобы этого не случалось, запас пополняется заранее.
        self.refill_passes(now, rng)?;

        self.storage
            .take_pass()?
            .map(|(seed, secret)| Pass::from_parts(seed, secret))
            .ok_or(GasAppError::Network)
    }

    /// Возвращает в запас пропуск, который не удалось потратить из-за
    /// сети: сервер его не видел.
    pub(super) fn return_pass(&self, pass: &Pass) -> Result<()> {
        self.storage.store_passes(&[(*pass.seed(), *pass.secret())])
    }
}
