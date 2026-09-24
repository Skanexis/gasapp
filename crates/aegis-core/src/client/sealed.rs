// SPDX-License-Identifier: Apache-2.0

//! Sealed sender на стороне клиента (раздел 15.2).
//!
//! # Как это складывается
//!
//! ```text
//!   Алиса                                     Боб
//!     │  Initial: AccessKey(Алисы) ────────▶  │  сохраняет ключ Алисы,
//!     │  (обычный конверт: сервер видит       │  снимает отметку «свой
//!     │   отправителя — ключа Боба ещё нет)    │  ключ Алисе передан»
//!     │  Message: «привет» ────────────────▶  │
//!     │                                        │
//!     │  ◀──── запечатанный: AccessKey(Боба)   │
//!     │  ◀──── запечатанный: «привет-привет»   │
//!     │                                        │
//!     │  дальше в обе стороны — запечатанное   │
//! ```
//!
//! # 🔐 Первое сообщение тоже запечатано
//!
//! Сервер пропускает анонимный конверт с ключом доступа получателя,
//! а ключ получатель раздаёт внутри переписки. Пока переписки нет,
//! ключа нет. Прежде первое сообщение поэтому уходило обычным путём,
//! **за подписью отправителя**, и сервер видел, кто начал переписку
//! с кем, — то есть строил социальный граф по первым контактам.
//!
//! Теперь право на анонимную отправку без ключа доказывается работой:
//! proof-of-work над челленджем из устройства получателя и хеша
//! самого конверта (`aegis_net::pow::first_contact_challenge`).
//! Решение одноразово — для другого конверта нужна новая работа, —
//! и дорого для рассылки спама тысячам адресатов. Работа нужна только
//! до первого ответа: он приносит ключ доступа собеседника.
//!
//! Обычной отправки за подписью клиент больше не делает вовсе:
//! сервер не получает от него ни одного конверта с отправителем.
//!
//! # 🔐 Почему нет тихого отката на обычную отправку
//!
//! Если сервер отверг ключ доступа, отправка завершается ошибкой, а не
//! уходит незапечатанной. Против недобросовестного сервера откат
//! ничего не даёт: отказать в доставке он может и так. А вот узнать
//! отправителя он смог бы — достаточно отвечать отказом на каждый
//! запечатанный конверт, и клиент сам раскрывал бы себя повторной
//! отправкой. Отказ закрытым лишает сервер этого рычага.
//!
//! Устаревший ключ при этом забывается: собеседник мог переустановить
//! приложение. Следующая попытка уйдёт обычным путём, но это будет
//! видимое пользователю «не доставлено», а не молчаливая подмена.
//!
//! # Когда проверяется срок сертификата
//!
//! По времени постановки конверта в очередь, а не по «сейчас».
//! Сертификат живёт сутки, конверт — до тридцати дней. Проверка по
//! «сейчас» означала бы, что получатель, пробывший без сети дольше
//! суток, теряет все запечатанные сообщения. Время очереди приходит
//! от сервера, то есть подконтрольно ему, но это не ослабление:
//! сервер и так может выписать поддельный сертификат (см.
//! `aegis-protocol::sealed_sender`).

use aegis_net::api::{SealedAccessRequest, SealedSendRequest};
use aegis_net::client::Transport;
use aegis_net::pow;
use aegis_protocol::content::{Content, ACCESS_KEY_LEN};
use aegis_protocol::keys::{IdentityKeyPair, SessionState};
use aegis_protocol::mlkem::MlKem1024PrivateKey;
use aegis_protocol::prekeys::{MAX_RETIRED_SIGNED, RETIRED_SIGNED_KEEP_DAYS};
use aegis_protocol::sealed_sender::{self, SenderCertificate};
use aegis_protocol::x25519::X25519PrivateKey;
use aegis_storage::sealed::StoredCertificate;
use aegis_types::{
    AegisError, ChatId, Plaintext, PrivateKeyBytes, PublicKeyBytes, Result, Timestamp,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use super::{
    derive_chat_id, hex, parse_bundle, parse_public_key, peer_account, unhex, Client, DeviceSigner,
};
use crate::session;

/// Сутки в миллисекундах.
const DAY_MILLIS: i64 = 24 * 60 * 60 * 1000;

/// За сколько до истечения сертификат обновляется заранее.
///
/// Час запаса: сертификат, истекающий через минуту, успел бы истечь
/// в пути, и получатель с отстающими часами отверг бы сообщение.
const CERTIFICATE_REFRESH_MARGIN_MILLIS: i64 = 60 * 60 * 1000;

impl<T: Transport> Client<T> {
    /// Включён ли sealed sender: ключ доступа опубликован на сервере.
    ///
    /// Нужен центру безопасности: «сообщения скрывают отправителя» —
    /// утверждение, которое показывается только тогда, когда оно верно.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn sealed_sender_enabled(&self) -> Result<bool> {
        Ok(self
            .storage
            .own_access_key()?
            .is_some_and(|own| own.published_at.is_some()))
    }

    /// Собственный ключ ML-KEM sealed sender; заводится при первом обращении.
    ///
    /// 🔐 Seed — в зашифрованной базе. Им разворачивается пост-квантовая
    /// половина внешнего слоя каждого входящего конверта.
    pub(super) fn own_sealed_kem_key(&self) -> Result<MlKem1024PrivateKey> {
        if let Some((seed, _)) = self.storage.own_sealed_kem()? {
            return Ok(MlKem1024PrivateKey::from_seed(seed));
        }

        let mut seed = zeroize::Zeroizing::new([0u8; aegis_storage::sealed::SEALED_KEM_SEED_LEN]);
        rand_core::OsRng.fill_bytes(seed.as_mut());
        self.storage.init_own_sealed_kem(&seed)?;

        // Перечитывается, а не возвращается сгенерированный: при гонке
        // двух потоков в базе останется первый, и ключ обязан быть им.
        let (stored, _) = self.storage.own_sealed_kem()?.ok_or(AegisError::Storage)?;

        Ok(MlKem1024PrivateKey::from_seed(stored))
    }

    /// Сменяет ключ ML-KEM sealed sender, если он опубликован давно,
    /// и стирает выведенные ключи сверх срока.
    ///
    /// # 🔐 Зачем
    ///
    /// Ключ, не меняющийся никогда, раскрыл бы при изъятии устройства
    /// отправителя каждого конверта, записанного с сервера или с провода
    /// за всё время. Смена раз в [`aegis_protocol::SIGNED_PRE_KEY_ROTATION_DAYS`]
    /// дней и стирание прежних через [`RETIRED_SIGNED_KEEP_DAYS`] суток —
    /// столько живёт конверт в очереди — ограничивают это окно месяцем.
    ///
    /// Срок считается от публикации, а не от создания: неопубликованный
    /// ключ ещё никому не выдан, и менять его незачем. Возвращает `true`,
    /// если ключ сменён — его надо опубликовать.
    pub(super) fn rotate_sealed_kem_if_due<R: RngCore + CryptoRng>(
        &self,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<bool> {
        let keep = RETIRED_SIGNED_KEEP_DAYS.saturating_mul(DAY_MILLIS);
        self.storage.prune_retired_sealed_kems(
            Timestamp::from_millis(now.as_millis().saturating_sub(keep)),
            MAX_RETIRED_SIGNED,
        )?;

        let Some((_, Some(published))) = self.storage.own_sealed_kem()? else {
            return Ok(false);
        };

        let period =
            i64::from(aegis_protocol::SIGNED_PRE_KEY_ROTATION_DAYS).saturating_mul(DAY_MILLIS);

        if now.as_millis().saturating_sub(published.as_millis()) < period {
            return Ok(false);
        }

        let mut seed = zeroize::Zeroizing::new([0u8; aegis_storage::sealed::SEALED_KEM_SEED_LEN]);
        rng.fill_bytes(seed.as_mut());
        self.storage.rotate_own_sealed_kem(&seed, now)?;

        Ok(true)
    }

    /// Открытая часть ключа ML-KEM sealed sender и её подпись, hex.
    pub(super) fn sealed_kem_publication<R: RngCore + CryptoRng>(
        &self,
        identity: &IdentityKeyPair,
        _rng: &mut R,
    ) -> Result<(String, String)> {
        let public = self.own_sealed_kem_key()?.public_key().as_bytes();
        let signature =
            sealed_sender::sign_sealed_kem_key(identity, &self.own_pq_identity()?, &public)?;

        Ok((hex(&public), hex(&signature)))
    }

    /// Заводит и публикует собственный ключ доступа, если это ещё не сделано.
    ///
    /// 🔐 На сервер уходит только SHA-256 ключа. Сам ключ сервер увидит
    /// лишь в запросе отправителя, когда будет сверять его с хешем, —
    /// хранить его ему незачем, и утечка базы сервера не позволяет
    /// писать пользователю анонимно.
    pub(super) fn ensure_access_key<R: RngCore + CryptoRng>(
        &self,
        identity: &IdentityKeyPair,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<[u8; ACCESS_KEY_LEN]> {
        if self.storage.own_access_key()?.is_none() {
            let mut fresh = [0u8; ACCESS_KEY_LEN];
            rng.fill_bytes(&mut fresh);
            self.storage.init_own_access_key(&fresh)?;
        }

        let own = self.storage.own_access_key()?.ok_or(AegisError::Storage)?;

        if own.published_at.is_some() {
            return Ok(own.key);
        }

        let device_id = self.own_device_id()?.ok_or(AegisError::SessionNotFound)?;
        let hash = Sha256::digest(own.key);

        self.api.publish_sealed_access(
            &device_id,
            &SealedAccessRequest {
                access_key_hash: hex(hash.as_slice()),
                allow_from_anyone: false,
            },
            &DeviceSigner::new(identity, now),
        )?;

        // Отметка ставится после ответа сервера: ключ, отмеченный
        // опубликованным, но не дошедший до сервера, раздавался бы
        // собеседникам, и их запечатанные сообщения отвергались бы.
        self.storage.mark_own_access_key_published(now)?;

        Ok(own.key)
    }

    /// Возвращает действующий сертификат и ключ сервера, обновляя при нужде.
    ///
    /// `force` — забрать новый сертификат, даже если сохранённый ещё
    /// действует: так клиент узнаёт о смене ключа сервера, когда
    /// входящий сертификат не проверяется прежним ключом.
    ///
    /// # 🔐 Что проверяется у выданного сертификата
    ///
    /// Подпись, срок, и то, что сертификат выдан **нам**: нашему
    /// identity-ключу и нашему устройству. Сертификат на чужой ключ,
    /// вложенный в наши конверты, получатели отвергли бы, и отправка
    /// ломалась бы необъяснимо.
    pub(super) fn ensure_certificate(
        &self,
        identity: &IdentityKeyPair,
        now: Timestamp,
        force: bool,
    ) -> Result<(SenderCertificate, PublicKeyBytes)> {
        let stored = self.storage.sender_certificate()?;

        if !force {
            if let Some(current) = &stored {
                let fresh_enough = current.expires_at.as_millis()
                    > now
                        .as_millis()
                        .saturating_add(CERTIFICATE_REFRESH_MARGIN_MILLIS);

                if fresh_enough {
                    let certificate = SenderCertificate::from_bytes(&current.certificate)?;

                    return Ok((certificate, PublicKeyBytes::new(current.server_key)));
                }
            }
        }

        let device_id = self.own_device_id()?.ok_or(AegisError::SessionNotFound)?;

        let response = self
            .api
            .fetch_certificate(&device_id, &DeviceSigner::new(identity, now))?;

        let certificate = SenderCertificate::from_bytes(&unhex(&response.certificate)?)?;
        let server_key = parse_public_key(&response.server_key)?;

        certificate.verify(&server_key, now.as_millis())?;

        if certificate.identity_key != *identity.public().public() {
            return Err(AegisError::InvalidSignature);
        }

        let own_device = uuid::Uuid::parse_str(&device_id).map_err(|_| AegisError::Storage)?;
        if certificate.device_id != *own_device.as_bytes() {
            return Err(AegisError::InvalidSignature);
        }

        // 🔐 Смена ключа сервера записывается в журнал. Она бывает
        // законной — ротация, — но и подмена сервера выглядит так же,
        // и человек должен иметь возможность увидеть, когда она случилась.
        if let Some(previous) = &stored {
            if previous.server_key != *server_key.as_bytes() {
                self.storage
                    .log_security_event("sealed_sender_server_key_changed", None, now)?;
            }
        }

        self.storage.save_sender_certificate(&StoredCertificate {
            certificate: certificate.to_bytes(),
            expires_at: Timestamp::from_millis(certificate.expires_at_millis),
            server_key: *server_key.as_bytes(),
        })?;

        Ok((certificate, server_key))
    }

    /// Доставляет конверт: запечатанным, если собеседник дал ключ доступа.
    ///
    /// # Errors
    ///
    /// [`AegisError::InvalidSignature`] — сервер отверг ключ доступа;
    /// ключ забыт, отправка **не** повторена обычным путём (см. модуль);
    /// [`AegisError::Network`] — сервер недоступен.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn deliver<R: RngCore + CryptoRng>(
        &self,
        identity: &IdentityKeyPair,
        peer_identity: &PublicKeyBytes,
        peer_device: &str,
        peer_kem: &[u8],
        envelope: &[u8],
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        let peer = peer_account(peer_identity);

        let access_key = self.storage.contact_access_key(&peer)?;

        let (certificate, _) = self.ensure_certificate(identity, now, false)?;
        // 🔐 Гибрид X25519 + ML-KEM-1024: имя отправителя не раскроет
        // и тот, кто записал трафик сейчас и получит квантовый компьютер потом.
        let sealed = sealed_sender::seal(peer_identity, peer_kem, &certificate, envelope, rng)?;

        // 🔐 Без ключа доступа — тоже запечатано, но с proof-of-work
        // (см. описание модуля). Отправки за подписью здесь нет:
        // она раскрыла бы серверу отправителя первого сообщения.
        let pow_nonce = match access_key {
            Some(_) => None,
            None => Some(
                pow::solve(
                    &pow::first_contact_challenge(peer_device, &sealed),
                    pow::FIRST_CONTACT_DIFFICULTY,
                )
                .ok_or(AegisError::Crypto)?,
            ),
        };

        let outcome = self.api.send_sealed(&SealedSendRequest {
            destination_device_id: peer_device.to_owned(),
            sealed: hex(&sealed),
            access_key: access_key.map(|key| hex(&key)),
            pow_nonce,
        });

        match outcome {
            Ok(_) => Ok(()),
            Err(AegisError::InvalidSignature) => {
                self.storage.forget_contact_access_key(&peer)?;
                self.storage
                    .log_security_event("sealed_sender_access_rejected", None, now)?;

                Err(AegisError::InvalidSignature)
            }
            Err(other) => Err(other),
        }
    }

    /// Передаёт собеседнику собственный ключ доступа и возвращает сессию.
    ///
    /// `existing` — `None`, если сессии ещё нет: тогда ключ доступа
    /// становится первым сообщением новой сессии. Так получатель узнаёт
    /// identity отправителя из самого конверта инициации и может
    /// сохранить ключ за правильным собеседником.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn send_own_access_key<R: RngCore + CryptoRng>(
        &self,
        identity: &IdentityKeyPair,
        chat_id: &ChatId,
        existing: Option<SessionState>,
        peer_identity: &PublicKeyBytes,
        peer_device: &str,
        peer_kem: &[u8],
        now: Timestamp,
        rng: &mut R,
    ) -> Result<SessionState> {
        let own_key = self.ensure_access_key(identity, now, rng)?;
        // Своё имя — чтобы собеседник, которому мы пишем первыми, мог
        // ответить: начальный конверт имени не несёт.
        let share = Plaintext::new(
            Content::AccessKey {
                key: own_key,
                sender_username: self.own_username()?,
            }
            .to_bytes()?,
        );

        let outgoing = if let Some(state) = existing {
            session::continue_session(&state, &share)?
        } else {
            let response = self.api.fetch_bundle(peer_device)?;
            let bundle = parse_bundle(&response)?;

            // 🔐 Bundle обязан принадлежать тому, кому пишем: и
            // классическая, и пост-квантовая половины — те же, что
            // проверены и запомнены по discovery.
            if bundle.identity_key.public() != peer_identity {
                return Err(AegisError::IdentityChanged);
            }
            self.remember_peer_pq(&peer_account(peer_identity), &bundle.pq_identity, now)?;

            let started = session::start_session(identity, &bundle, &share, rng)?;

            // 🔐 Начало без одноразового ключа собеседника — в журнал.
            //
            // Такая сессия теряет вклад одноразового ключа в прямую
            // секретность первого сообщения. Бывает от исчерпания пула,
            // но так же выглядит и сервер, намеренно не выдающий
            // одноразовые ключи. Прежде флаг `degraded` вычислялся
            // и выбрасывался: заметить систематическое исчерпание было
            // нечем, хотя комментарий обещал показ в центре безопасности.
            if started.degraded {
                self.storage.log_security_event(
                    "session_started_without_one_time_key",
                    None,
                    now,
                )?;
            }

            started
        };

        // Сессия сохраняется до отправки — тот же порядок, что у любого
        // сообщения: потерянное состояние храповика хуже повторной попытки.
        self.storage.save_session(chat_id, &outgoing.session, now)?;
        self.deliver(
            identity,
            peer_identity,
            peer_device,
            peer_kem,
            &outgoing.envelope,
            now,
            rng,
        )?;
        self.storage
            .mark_access_key_shared(&peer_account(peer_identity), now)?;

        Ok(outgoing.session)
    }

    /// Снимает внешний слой sealed sender, если он есть.
    ///
    /// Возвращает внутренний конверт и сертификат отправителя; обычный
    /// конверт возвращается как есть, без сертификата. `None` —
    /// запечатанный конверт не разворачивается либо его сертификат
    /// не проверяется: такой конверт пропускается так же, как
    /// нерасшифровываемый обычный.
    pub(super) fn unwrap_wire(
        &self,
        identity: &IdentityKeyPair,
        wire: Vec<u8>,
        queued_at_seconds: i64,
        now: Timestamp,
    ) -> Option<(Vec<u8>, Option<SenderCertificate>)> {
        if !sealed_sender::is_sealed(&wire) {
            return Some((wire, None));
        }

        let (certificate, inner) = self
            .open_sealed(identity, &wire, queued_at_seconds, now)
            .ok()?;

        Some((inner, Some(certificate)))
    }

    /// Проверяет, что сертификат привязан к сессии, и записывает несовпадение.
    ///
    /// Обычный конверт сертификата не несёт и привязки не требует.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись в журнал безопасности не удалась.
    pub(super) fn certificate_bound(
        &self,
        identity: &IdentityKeyPair,
        certificate: Option<&SenderCertificate>,
        sender_identity: Option<&PublicKeyBytes>,
        known_chat: Option<&ChatId>,
        now: Timestamp,
    ) -> Result<bool> {
        let Some(certificate) = certificate else {
            return Ok(true);
        };

        if certificate_matches(
            identity.public().public(),
            certificate,
            sender_identity,
            known_chat,
        ) {
            return Ok(true);
        }

        // 🔐 Несовпадение — не сбой, а признак попытки выдать своё
        // сообщение за чужое. Оно записывается, чтобы его можно было
        // увидеть в журнале, а не только пропустить.
        self.storage
            .log_security_event("sealed_sender_certificate_mismatch", None, now)?;

        Ok(false)
    }

    /// Разворачивает запечатанный конверт и проверяет сертификат.
    ///
    /// Возвращает сертификат и внутренний конверт. Привязка сертификата
    /// к сессии проверяется вызывающим после расшифровки — см.
    /// [`certificate_matches`].
    pub(super) fn open_sealed(
        &self,
        identity: &IdentityKeyPair,
        raw: &[u8],
        queued_at_seconds: i64,
        now: Timestamp,
    ) -> Result<(SenderCertificate, Vec<u8>)> {
        let private = X25519PrivateKey::from_bytes(PrivateKeyBytes::new(
            *identity.private().expose_secret(),
        ))?;
        // 🔐 Действующий ключ, затем выведенные — от новых к старым:
        // конверт, запечатанный до смены, ещё может лежать в очереди.
        // Неверный ключ ML-KEM не ломает ничего: неявный отказ даёт
        // случайный секрет, и AES-GCM отвергает тег.
        let current = self.own_sealed_kem_key()?;
        let contents = match sealed_sender::unseal(&private, &current, raw) {
            Ok(contents) => contents,
            Err(first) => self
                .storage
                .retired_sealed_kems()?
                .into_iter()
                .find_map(|seed| {
                    sealed_sender::unseal(&private, &MlKem1024PrivateKey::from_seed(seed), raw).ok()
                })
                .ok_or(first)?,
        };
        let moment = validity_moment(queued_at_seconds, now);

        let (_, server_key) = self.ensure_certificate(identity, now, false)?;

        // Не проверился прежним ключом — возможно, сервер сменил ключ.
        // Один повторный запрос за свежим, и только затем отказ.
        if contents.certificate.verify(&server_key, moment).is_err() {
            let (_, fresh_key) = self.ensure_certificate(identity, now, true)?;
            contents.certificate.verify(&fresh_key, moment)?;
        }

        Ok((contents.certificate, contents.envelope))
    }
}

/// Привязан ли сертификат к той сессии, которой расшифровался конверт.
///
/// # 🔐 Зачем
///
/// Сертификат, снятый с полученного конверта, действует сутки. Без
/// привязки получатель мог бы вложить чужой сертификат в свой конверт
/// и выдать своё сообщение за сообщение того, чей сертификат снял.
/// Привязка требует, чтобы identity в сертификате совпала с identity
/// сессии:
///
/// * у конверта инициации — с identity отправителя из самого PQXDH;
/// * у сообщения в сессии — с собеседником этого чата.
pub(super) fn certificate_matches(
    own_identity: &PublicKeyBytes,
    certificate: &SenderCertificate,
    sender_identity: Option<&PublicKeyBytes>,
    known_chat: Option<&ChatId>,
) -> bool {
    match (sender_identity, known_chat) {
        (Some(sender), _) => *sender == certificate.identity_key,
        (None, Some(chat)) => derive_chat_id(own_identity, &certificate.identity_key) == *chat,
        (None, None) => false,
    }
}

/// Момент, на который проверяется срок сертификата, в миллисекундах.
///
/// Время очереди приходит в секундах, округлёнными до часа вниз
/// (раздел 15.4). Округление вниз не мешает: сертификат, действовавший
/// в момент отправки, действовал и в начале того же часа, если выдан
/// раньше. Будущее время очереди не принимается — берётся «сейчас».
fn validity_moment(queued_at_seconds: i64, now: Timestamp) -> i64 {
    if queued_at_seconds <= 0 {
        return now.as_millis();
    }

    queued_at_seconds.saturating_mul(1000).min(now.as_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate_for(identity: PublicKeyBytes) -> SenderCertificate {
        SenderCertificate {
            account_id: [1u8; 16],
            device_id: [2u8; 16],
            identity_key: identity,
            expires_at_millis: 0,
            signature: [0u8; 64],
        }
    }

    fn own() -> PublicKeyBytes {
        PublicKeyBytes::new([1u8; 32])
    }

    fn peer() -> PublicKeyBytes {
        PublicKeyBytes::new([2u8; 32])
    }

    fn stranger() -> PublicKeyBytes {
        PublicKeyBytes::new([3u8; 32])
    }

    /// Конверт инициации привязывается по identity отправителя.
    #[test]
    fn initial_envelope_binds_by_sender_identity() {
        let certificate = certificate_for(peer());

        assert!(certificate_matches(
            &own(),
            &certificate,
            Some(&peer()),
            None
        ));
        assert!(
            !certificate_matches(&own(), &certificate, Some(&stranger()), None),
            "чужой сертификат принят для конверта инициации"
        );
    }

    /// 🔐 Сообщение в сессии привязывается по чату.
    #[test]
    fn session_message_binds_by_chat() {
        let certificate = certificate_for(peer());
        let peer_chat = derive_chat_id(&own(), &peer());
        let stranger_chat = derive_chat_id(&own(), &stranger());

        assert!(certificate_matches(
            &own(),
            &certificate,
            None,
            Some(&peer_chat)
        ));
        assert!(
            !certificate_matches(&own(), &certificate, None, Some(&stranger_chat)),
            "сертификат собеседника принят в чужой сессии"
        );
    }

    /// Без контекста привязать нельзя — и сертификат не принимается.
    #[test]
    fn unknown_context_never_binds() {
        assert!(!certificate_matches(
            &own(),
            &certificate_for(peer()),
            None,
            None
        ));
    }

    /// Срок проверяется по времени очереди, если оно есть.
    #[test]
    fn validity_is_checked_at_queue_time() {
        let now = Timestamp::from_millis(10_000_000);

        assert_eq!(validity_moment(0, now), 10_000_000);
        assert_eq!(validity_moment(3600, now), 3_600_000);
        // Время очереди из будущего не принимается.
        assert_eq!(validity_moment(1_000_000_000, now), 10_000_000);
    }
}
