// SPDX-License-Identifier: Apache-2.0

//! Боты: аккаунты, которые ведёт программа владельца.
//!
//! Бот — обычный аккаунт со своими ключами. Отличий два: его заводит
//! владелец с премиумом, и адреса почты у него нет. Что бот умеет,
//! решает его программа: она ходит на сервер теми же запросами, что и
//! приложение (см. крейт `gasapp-bot`).
//!
//! Две стороны:
//!
//! * **владелец** — в приложении: берёт у сервера одноразовый токен под
//!   имя на `bot`, видит своих ботов, удаляет их;
//! * **программа бота** — [`Client::register_bot`]: по токену заводит
//!   аккаунт со своими ключами.
//!
//! 🔐 Ключи бота рождаются там, где бот работает. Приложение владельца
//! их не видит, как и сервер; токен — право один раз занять имя, а не
//! ключ.
//!
//! ⚠️ Бот, назначенный администратором канала, получает то же, что
//! администратор-человек: право писать, а в закрытом канале — ещё и
//! секрет чтения. Программа бота и машина, где она работает, становятся
//! частью того, чему доверяет канал.

use gasapp_net::api::{BotNameRequest, RegisterBotRequest};
use gasapp_net::client::Transport;
use gasapp_net::pow;
use gasapp_protocol::pq_identity::PqIdentityKeyPair;
use gasapp_protocol::prekeys;
use gasapp_types::{canonical_username, DeviceId, GasAppError, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::{hex, Account, Client, DeviceSigner, POW_DIFFICULTY};

/// Чем обязано кончаться имя бота.
pub const BOT_SUFFIX: &str = "bot";

/// С чего начинается строка, которую владелец отдаёт программе бота.
pub const BOT_TOKEN_PREFIX: &str = "gasapp-bot:";

/// Длина токена сервера в шестнадцатеричных знаках.
const TOKEN_HEX_LEN: usize = 64;

/// Имя бота: каноничное и на `bot`.
///
/// # Errors
///
/// [`GasAppError::InvalidUsername`] — имя неканоничное либо не на `bot`.
pub fn bot_username(raw: &str) -> Result<String> {
    let username = canonical_username(raw)?;

    if username.len() > BOT_SUFFIX.len() && username.ends_with(BOT_SUFFIX) {
        Ok(username)
    } else {
        Err(GasAppError::InvalidUsername)
    }
}

/// Разбирает строку `gasapp-bot:<имя>:<токен>`.
fn parse_token(token: &str) -> Result<(String, String)> {
    let rest = token
        .trim()
        .strip_prefix(BOT_TOKEN_PREFIX)
        .ok_or(GasAppError::Malformed)?;
    let (username, secret) = rest.split_once(':').ok_or(GasAppError::Malformed)?;

    if secret.len() != TOKEN_HEX_LEN || !secret.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GasAppError::Malformed);
    }

    Ok((
        bot_username(username).map_err(|_| GasAppError::Malformed)?,
        secret.to_ascii_lowercase(),
    ))
}

impl<T: Transport> Client<T> {
    /// Берёт у сервера токен под имя будущего бота и возвращает строку
    /// для его программы: `gasapp-bot:<имя>:<токен>`.
    ///
    /// Токен действует час и годится один раз. На устройстве он не
    /// сохраняется: строку показывают владельцу, и он сам переносит её
    /// туда, где будет работать бот.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::InvalidUsername`] — имя неканоничное либо не на
    ///   `bot`;
    /// * [`GasAppError::Forbidden`] — у аккаунта нет премиума;
    /// * [`GasAppError::UsernameTaken`] — имя занято;
    /// * [`GasAppError::Network`] — сервер недоступен либо у владельца
    ///   предел ботов.
    pub fn create_bot(&self, username: &str, now: Timestamp) -> Result<String> {
        let username = bot_username(username)?;
        let (device_id, identity) = self.own_device()?;

        let issued = self.api.create_bot(
            &device_id,
            &BotNameRequest {
                username: username.clone(),
            },
            &DeviceSigner::new(&identity, now),
        )?;

        // 🔐 Токен приходит от сервера и уходит в строку, которую человек
        // копирует: в неё попадают только шестнадцатеричные знаки.
        if issued.token.len() != TOKEN_HEX_LEN
            || !issued.token.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(GasAppError::Malformed);
        }

        Ok(format!("{BOT_TOKEN_PREFIX}{username}:{}", issued.token))
    }

    /// Имена своих ботов. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сервер недоступен.
    pub fn bots(&self, now: Timestamp) -> Result<Vec<String>> {
        let (device_id, identity) = self.own_device()?;

        Ok(self
            .api
            .bots(&device_id, &DeviceSigner::new(&identity, now))?
            .into_iter()
            // 🔐 Имя от сервера попадает в интерфейс только каноничным.
            .filter_map(|bot| bot_username(&bot.username).ok())
            .collect())
    }

    /// Удаляет своего бота вместе с его аккаунтом: бот исчезает из
    /// каналов, где был администратором, а его программа больше не
    /// может войти.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — такого бота у аккаунта нет;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn delete_bot(&self, username: &str, now: Timestamp) -> Result<()> {
        let username = bot_username(username)?;
        let (device_id, identity) = self.own_device()?;

        self.api.delete_bot(
            &device_id,
            &BotNameRequest { username },
            &DeviceSigner::new(&identity, now),
        )
    }

    /// Регистрирует бота по строке от владельца. Вызывает программа
    /// бота — один раз, на пустом хранилище.
    ///
    /// Ключа восстановления у бота нет: потерял хранилище — владелец
    /// удаляет бота и заводит заново.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — это не строка токена;
    /// * [`GasAppError::Forbidden`] — токен не принят: истёк, уже
    ///   использован либо выдан под другое имя;
    /// * [`GasAppError::UsernameTaken`] — имя успели занять;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn register_bot<R: RngCore + CryptoRng>(
        &self,
        token: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Account> {
        let (username, token) = parse_token(token)?;

        let identity = prekeys::generate_identity(rng)?;
        let pq = PqIdentityKeyPair::generate(rng);
        let device_id = DeviceId::generate();
        let (bundle, secrets) = prekeys::generate(&identity, &pq, device_id, now, rng)?;

        // Работа — та же, что при обычной регистрации, и над тем же:
        // именем и ключами.
        let identity_bytes = identity.public().public().as_bytes();
        let challenge = pow::registration_challenge(&username, identity_bytes, identity_bytes);
        let nonce = pow::solve(&challenge, POW_DIFFICULTY).ok_or(GasAppError::Crypto)?;

        let identity_hex = hex(identity_bytes);
        let response = self.api.register_bot(&RegisterBotRequest {
            token,
            username: username.clone(),
            identity_key: identity_hex.clone(),
            device_identity_key: identity_hex,
            pq_identity_key: hex(&pq.public()),
            identity_binding: hex(&gasapp_protocol::pq_identity::bind(&identity, &pq)?),
            pow_challenge: hex(&challenge),
            pow_nonce: nonce,
        })?;

        self.finish_enrollment(
            &identity, &pq, &bundle, &secrets, &response, &username, now, rng,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bot_names_end_in_bot() {
        assert_eq!(bot_username("Helper_Bot").unwrap(), "helper_bot");
        assert!(bot_username("helper").is_err());
        assert!(bot_username("bot").is_err());
        assert!(bot_username("хелперbot").is_err());
    }

    #[test]
    fn tokens_are_parsed_strictly() {
        let secret = "ab".repeat(32);
        let (username, token) = parse_token(&format!(" gasapp-bot:news_bot:{secret}\n")).unwrap();
        assert_eq!(username, "news_bot");
        assert_eq!(token, secret);

        for bad in [
            format!("gasapp-bot:news:{secret}"),
            format!("gasapp-bot:news_bot:{}", &secret[..62]),
            format!("gasapp-bot:news_bot:{}zz", &secret[..62]),
            format!("gasapp://bot/news_bot:{secret}"),
            "gasapp-bot:news_bot".to_owned(),
        ] {
            assert!(parse_token(&bad).is_err(), "{bad}");
        }
    }
}
