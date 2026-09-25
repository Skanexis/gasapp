// SPDX-License-Identifier: Apache-2.0

//! Журнал ключей в клиенте (спецификация §9.7, ADR-027).
//!
//! # Что даёт
//!
//! Ключ, найденный по `@имени`, годится для отправки без личной сверки,
//! если журнал сервера показывает его под этим именем **и сейчас, и
//! сутки назад** ([`kt::TRUST_DELAY_EPOCHS`]). Свою запись в журнале
//! клиент проверяет сам за каждую эпоху: чужой ключ под своим именем —
//! событие безопасности, и сервер не может его отрицать (оно в его же
//! хеш-цепочке).
//!
//! # 🔐 Почему сервер не может соврать выборочно
//!
//! * Корни эпох связаны хеш-цепочкой ([`Client::kt_sync`]): переписать
//!   прошлое для одного клиента нельзя, не разойдясь с тем, что он уже
//!   видел.
//! * Запросы к журналу анонимны (без подписи, своей цепочкой Tor):
//!   сервер не знает, кто проверяет, и вынужден показывать всем одно
//!   дерево. В одном дереве у индекса один лист — тот же, что проверяет
//!   владелец имени.
//! * Выдержка в сутки: свежую подмену владелец видит раньше, чем ей
//!   поверят собеседники.
//!
//! # Чего это не даёт
//!
//! Если владелец имени не открывал приложение дольше суток, подмена
//! в это время обнаружится только при его возвращении. Личная сверка
//! (safety number, QR, ссылка) остаётся сильнейшим подтверждением.

use aegis_net::api::{KtProofView, KtProofsRequest};
use aegis_net::client::Transport;
use aegis_protocol::content::Content;
use aegis_protocol::key_transparency::{self as kt, Proof, Terminal};
use aegis_protocol::pq_identity;
use aegis_types::{AegisError, PublicKeyBytes, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::{hex, unhex, Client};

/// Насколько цепочка может отставать от часов, оставаясь пригодной.
const FRESHNESS_EPOCHS: u64 = 2;

/// Предел эпох в одном запросе (как у сервера).
const MAX_PER_REQUEST: usize = 200;

/// Предел страниц вершин за одну синхронизацию.
const MAX_HEAD_PAGES: usize = 4;

/// Как часто отправлять собеседнику свою вершину журнала: раз в сутки.
const GOSSIP_INTERVAL_MILLIS: i64 = 24 * 60 * 60 * 1000;

/// Приставка настройки «когда собеседнику ушла вершина».
const GOSSIP_SETTING_PREFIX: &str = "kt_gossip:";

/// Что журнал говорит о ключе собеседника.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KtVerdict {
    /// Тот же лист в журнале сейчас и сутки назад: можно писать.
    Verified,
    /// Ключа в журнале нет, он новее суток или не совпадает с названным:
    /// нужна личная сверка (или подождать сутки).
    NotYet,
    /// Журнал недоступен или отстал: проверить нечем.
    Unavailable,
}

/// Итог проверки своего имени.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtSelfCheck {
    /// До какой эпохи проверено.
    pub checked_through: u64,
    /// 🔐 Эпохи, в которых под своим именем стоял чужой ключ.
    pub foreign_epochs: Vec<u64>,
}

/// Лист журнала в разобранном виде.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Leaf {
    identity_key: [u8; 32],
    pq_hash: [u8; 32],
    version: u64,
}

fn to32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| AegisError::Malformed)
}

fn hex32(text: &str) -> Result<[u8; 32]> {
    to32(&unhex(text)?)
}

/// Разбирает и проверяет доказательство против корня; возвращает лист
/// индекса, если он есть.
fn verified_leaf(view: &KtProofView, index: &[u8; 32], root: &[u8; 32]) -> Result<Option<Leaf>> {
    let siblings = view
        .siblings
        .iter()
        .map(|text| hex32(text))
        .collect::<Result<Vec<_>>>()?;

    let (terminal, leaf, expected) = match (&view.leaf, &view.other) {
        (Some(leaf), None) => {
            let leaf = Leaf {
                identity_key: hex32(&leaf.identity_key)?,
                pq_hash: hex32(&leaf.pq_hash)?,
                version: leaf.version,
            };
            let value = kt::leaf_value(index, &leaf.identity_key, &leaf.pq_hash, leaf.version);

            (
                Terminal::Leaf {
                    index: *index,
                    value,
                },
                Some(leaf),
                Some(value),
            )
        }
        (None, Some(other)) => (
            Terminal::Leaf {
                index: hex32(&other.index)?,
                value: hex32(&other.value)?,
            },
            None,
            None,
        ),
        (None, None) => (Terminal::Empty, None, None),
        (Some(_), Some(_)) => return Err(AegisError::Malformed),
    };

    Proof { siblings, terminal }
        .verify(root, index, expected.as_ref())
        .map_err(|_| AegisError::InvalidSignature)?;

    Ok(leaf)
}

impl<T: Transport> Client<T> {
    /// Синхронизирует цепочку вершин журнала и возвращает последнюю
    /// проверенную эпоху.
    ///
    /// Каждая новая вершина обязана продолжать сохранённую:
    /// `head(e) = H(e, root(e), head(предыдущей))`. Первая синхронизация
    /// принимает вершину на веру (как ключ при первом использовании);
    /// дальше цепочку не переписать.
    ///
    /// # Errors
    ///
    /// * [`AegisError::Network`] — сервер недоступен или цепочка отстала
    ///   от часов больше чем на [`FRESHNESS_EPOCHS`];
    /// * [`AegisError::InvalidSignature`] — 🔐 цепочка не продолжает
    ///   сохранённую (записывается событие `kt_log_forked`).
    pub fn kt_sync(&self, now: Timestamp) -> Result<u64> {
        let now_epoch = kt::epoch_at(now.as_millis());

        // Эпоха, на которой остановились, старше истории сервера —
        // продолжить не от чего: цепочка начинается заново.
        let mut previous = match self.storage.kt_latest_head()? {
            Some((epoch, _, head)) if epoch.saturating_add(kt::HISTORY_EPOCHS) > now_epoch => {
                Some((epoch, head))
            }
            Some(_) => {
                self.storage.kt_forget_heads()?;
                None
            }
            None => None,
        };

        for _ in 0..MAX_HEAD_PAGES {
            let response = self.api.kt_heads(previous.map(|(epoch, _)| epoch))?;
            let page = response.epochs.len();
            let mut verified = Vec::with_capacity(page);

            for view in &response.epochs {
                let root = hex32(&view.root)?;
                let head = hex32(&view.head)?;

                let continues = match previous {
                    // Сохранённая эпоха повторяется первой — обязана совпасть.
                    Some((epoch, stored)) if view.epoch == epoch => {
                        if head == stored {
                            continue;
                        }
                        false
                    }
                    Some((epoch, stored)) => {
                        view.epoch > epoch && head == kt::head(view.epoch, &root, &stored)
                    }
                    None => true,
                };

                if !continues {
                    // 🔐 Сервер показал цепочку, не продолжающую ту, что
                    // он показывал раньше. Цепочка начинается заново,
                    // а событие остаётся.
                    self.storage
                        .log_security_event("kt_log_forked", None, now)?;
                    self.storage.kt_forget_heads()?;

                    return Err(AegisError::InvalidSignature);
                }

                verified.push((view.epoch, root, head));
                previous = Some((view.epoch, head));
            }

            if let Some((latest, _, _)) = verified.last() {
                let keep_from = latest.saturating_sub(kt::HISTORY_EPOCHS);
                self.storage.kt_store_heads(&verified, keep_from)?;
            }

            if page < MAX_PER_REQUEST {
                break;
            }
        }

        let (latest, _, _) = self.storage.kt_latest_head()?.ok_or(AegisError::Network)?;

        if latest.saturating_add(FRESHNESS_EPOCHS) < now_epoch {
            return Err(AegisError::Network);
        }

        Ok(latest)
    }

    /// Проверяет ключ собеседника по журналу.
    ///
    /// `pq_identity_key` — пост-квантовая половина из ответа discovery (hex).
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — сбой базы. Сетевые сбои и испорченные
    /// ответы дают [`KtVerdict::Unavailable`], а не ошибку: отказ журнала
    /// значит «проверить нечем», и отправка просто требует личной сверки.
    pub fn kt_verify_contact(
        &self,
        username: &str,
        identity: &PublicKeyBytes,
        pq_identity_key: &str,
        now: Timestamp,
    ) -> Result<KtVerdict> {
        let Ok(latest) = self.kt_sync(now) else {
            return Ok(KtVerdict::Unavailable);
        };

        // Эпоха сутки назад — из своей цепочки. Её нет — журнал младше
        // суток (или цепочка начата только что): выдержку не проверить.
        let Some(old) = self
            .storage
            .kt_head_at_or_before(latest.saturating_sub(kt::TRUST_DELAY_EPOCHS))?
        else {
            return Ok(KtVerdict::NotYet);
        };
        let Some(current) = self.storage.kt_head_exact(latest)? else {
            return Ok(KtVerdict::Unavailable);
        };

        let index = kt::index(username);
        let Ok(response) = self.api.kt_proofs(&KtProofsRequest {
            index: hex(&index),
            epochs: vec![old.0, current.0],
        }) else {
            return Ok(KtVerdict::Unavailable);
        };

        let leaf_at = |epoch: u64, root: &[u8; 32]| -> Option<Result<Option<Leaf>>> {
            response
                .proofs
                .iter()
                .find(|view| view.epoch == epoch)
                .map(|view| verified_leaf(view, &index, root))
        };

        let (Some(Ok(then)), Some(Ok(now_leaf))) =
            (leaf_at(old.0, &old.1), leaf_at(current.0, &current.1))
        else {
            return Ok(KtVerdict::Unavailable);
        };

        let Ok(pq_public) = unhex(pq_identity_key) else {
            return Ok(KtVerdict::NotYet);
        };
        let named = Leaf {
            identity_key: *identity.as_bytes(),
            pq_hash: pq_identity::pq_identity_hash(&pq_public),
            version: 0,
        };

        Ok(match (then, now_leaf) {
            (Some(then), Some(now_leaf))
                if then == now_leaf
                    && now_leaf.identity_key == named.identity_key
                    && now_leaf.pq_hash == named.pq_hash =>
            {
                KtVerdict::Verified
            }
            _ => KtVerdict::NotYet,
        })
    }

    /// Проверяет своё имя в журнале за эпохи, прошедшие с прошлой
    /// проверки (не дальше [`kt::MONITOR_WINDOW_EPOCHS`]).
    ///
    /// 🔐 Чужой ключ под своим именем — событие безопасности
    /// `kt_foreign_key_for_own_name`: кто-то (сервер) показывал
    /// собеседникам не этот ключ.
    ///
    /// # Errors
    ///
    /// * [`AegisError::Uninitialized`] — аккаунт не зарегистрирован;
    /// * [`AegisError::Network`] — журнал недоступен;
    /// * [`AegisError::InvalidSignature`] — доказательство не сходится
    ///   с корнем или цепочка не продолжает сохранённую.
    pub fn kt_check_self(&self, now: Timestamp) -> Result<KtSelfCheck> {
        let username = self.own_username()?.ok_or(AegisError::Uninitialized)?;
        let (identity, _) = self.load_identity()?;
        let own = Leaf {
            identity_key: *identity.public().public().as_bytes(),
            pq_hash: pq_identity::pq_identity_hash(&self.own_pq_identity()?.public()),
            version: 0,
        };

        let latest = self.kt_sync(now)?;

        // Без состояния (обновление с прежней версии) — с текущей эпохи:
        // прошлое проверять не с чем.
        let (checked, mut version) = match self.storage.kt_self()? {
            Some(state) => state,
            None => (latest.saturating_sub(1), 0),
        };

        let from = checked
            .saturating_add(1)
            .max(latest.saturating_sub(kt::MONITOR_WINDOW_EPOCHS));
        let epochs = self.storage.kt_epochs_between(from, latest)?;
        let index = kt::index(&username);

        let mut foreign = Vec::new();
        let mut checked_through = checked;

        'chunks: for chunk in epochs.chunks(MAX_PER_REQUEST) {
            let response = self.api.kt_proofs(&KtProofsRequest {
                index: hex(&index),
                epochs: chunk.to_vec(),
            })?;

            for epoch in chunk {
                let Some(view) = response.proofs.iter().find(|view| view.epoch == *epoch) else {
                    // Сервер не выдал эпоху — дальше неё не проверено.
                    break 'chunks;
                };
                let (_, root, _) = self
                    .storage
                    .kt_head_exact(*epoch)?
                    .ok_or(AegisError::Storage)?;

                match verified_leaf(view, &index, &root)? {
                    // Своего листа ещё нет (регистрация новее эпохи).
                    None => {}
                    Some(leaf)
                        if leaf.identity_key == own.identity_key && leaf.pq_hash == own.pq_hash =>
                    {
                        // Версия не откатывается: откат — старый лист,
                        // показанный снова.
                        if leaf.version < version {
                            foreign.push(*epoch);
                        } else {
                            version = leaf.version;
                        }
                    }
                    Some(_) => foreign.push(*epoch),
                }

                checked_through = *epoch;
            }
        }

        if let (Some(first), Some(last)) = (foreign.first(), foreign.last()) {
            self.storage.log_security_event(
                "kt_foreign_key_for_own_name",
                Some(&format!("epochs {first}..{last}")),
                now,
            )?;
        }

        self.storage.set_kt_self(checked_through, version)?;

        Ok(KtSelfCheck {
            checked_through,
            foreign_epochs: foreign,
        })
    }

    /// Отправляет собеседнику свою вершину журнала — не чаще раза
    /// в [`GOSSIP_INTERVAL_MILLIS`] на собеседника.
    ///
    /// # Errors
    ///
    /// Ошибки отправки и журнала; вызывающий их не показывает.
    pub(super) fn kt_gossip_head<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        let key = format!("{GOSSIP_SETTING_PREFIX}{peer_username}");
        let last = self.storage.setting_int(&key, 0)?;

        if now.as_millis().saturating_sub(last) < GOSSIP_INTERVAL_MILLIS {
            return Ok(());
        }

        let Some((epoch, _, head)) = self.storage.kt_latest_head()? else {
            return Ok(());
        };

        self.send_content(peer_username, &Content::KtHead { epoch, head }, now, rng)?;
        self.storage.set_setting_int(&key, now.as_millis())
    }

    /// Сверяет вершину, присланную собеседником, со своей цепочкой.
    ///
    /// 🔐 Расхождение — событие `kt_peer_log_differs`: сервер показывает
    /// одному из двоих свою ветку журнала (или собеседник прислал
    /// неверную вершину — различить нельзя, поэтому это событие, а не
    /// приговор).
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — сбой базы. Недоступный журнал не ошибка:
    /// сверка просто откладывается до следующей вершины.
    pub(super) fn kt_compare_peer_head(
        &self,
        epoch: u64,
        head: &[u8; 32],
        now: Timestamp,
    ) -> Result<()> {
        let mut mine = self.storage.kt_head_exact(epoch)?;

        // Эпохи ещё нет — догнать цепочку (если она новее нашей).
        if mine.is_none()
            && self
                .storage
                .kt_latest_head()?
                .is_none_or(|(latest, _, _)| latest < epoch)
        {
            let _ = self.kt_sync(now);
            mine = self.storage.kt_head_exact(epoch)?;
        }

        if let Some((_, _, own)) = mine {
            if &own != head {
                self.storage.log_security_event(
                    "kt_peer_log_differs",
                    Some(&format!("epoch {epoch}")),
                    now,
                )?;
            }
        }

        Ok(())
    }

    /// Начинает проверку своего имени с текущей эпохи — после
    /// регистрации или возвращения аккаунта: прежние эпохи хранят
    /// прежний ключ (или ничего), и чужим он не был.
    pub(super) fn kt_start_self_check(&self, now: Timestamp) -> Result<()> {
        self.storage.set_kt_self(kt::epoch_at(now.as_millis()), 0)
    }
}
