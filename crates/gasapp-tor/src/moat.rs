// SPDX-License-Identifier: Apache-2.0

//! Свежие мосты от Tor Project (moat) — без капчи, через meek.
//!
//! # Зачем
//!
//! Встроенные в сборку мосты со временем попадают в списки цензора,
//! а просить человека пройти капчу на bridges.torproject.org там, где
//! этот сайт закрыт, бессмысленно. Tor Browser в таком случае спрашивает
//! мосты у moat — службы Tor Project, которая по стране отдаёт мосты,
//! работающие против её цензуры. Так же делает и приложение.
//!
//! # Как
//!
//! Сессия meek через CDN (фронт — крупный сайт), внутри неё — TLS до
//! bridges.torproject.org с проверкой сертификата по корням `WebPKI`:
//! CDN не может ни прочитать, ни подменить ответ. Запрос —
//! `POST /moat/circumvention/settings` со страной и транспортами.
//!
//! # 🔐 Что узнаёт Tor Project
//!
//! Что с этого адреса спросили мосты для такой-то страны — как у Tor
//! Browser. Сервер GasApp не участвует и не узнаёт ничего. Провайдер
//! видит HTTPS к фронту.

use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::BufReader;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::{meek, webtunnel};

/// Сессия meek до moat: адрес на CDN и фронт — как в Tor Browser.
pub const MOAT_URL: &str = "https://1723079976.rsc.cdn77.org";
/// Фронт сессии до moat.
pub const MOAT_FRONT: &str = "www.phpmyadmin.net";

/// Узел moat: его сертификат проверяется внутри сессии.
const MOAT_HOST: &str = "bridges.torproject.org";

/// Запрос мостов по стране.
const SETTINGS_PATH: &str = "/moat/circumvention/settings";

/// Страна, чей набор мостов берётся, когда для своей moat ничего не дал:
/// набор общий для стран с блокировкой Tor (Россия, Иран, Китай отдают
/// одни и те же мосты).
const FALLBACK_COUNTRY: &str = "ru";

/// Сколько ждать всего обмена: сессия meek небыстрая.
const MOAT_TIMEOUT: Duration = Duration::from_mins(2);

/// Предел ответа moat.
const MAX_ANSWER: usize = 256 * 1024;

/// Почему мосты не получены.
#[derive(Debug, thiserror::Error)]
pub enum MoatError {
    /// Код страны — не две латинские буквы.
    #[error("moat: country")]
    Country,
    /// moat недостижим: фронт закрыт, нет сети или истекло время.
    #[error("moat: unreachable")]
    Unreachable,
    /// Ответ не разобран.
    #[error("moat: answer")]
    Answer,
}

/// Спрашивает у moat мосты `WebTunnel` для страны.
///
/// `country` — код ISO 3166-1 (`ru`, `ir`…); без него или если для него
/// мостов нет, берётся общий набор стран с блокировкой. Строки мостов
/// возвращаются как есть — проверяет их вызывающий
/// (`gasapp-net::proxy::normalize_bridge_line`).
///
/// Блокирует поток до ответа (до двух минут): звать не из главного.
///
/// # Errors
///
/// [`MoatError`] — негодный код страны, moat недостижим или ответ
/// не разобран.
pub fn fetch_bridges(country: Option<&str>) -> Result<Vec<String>, MoatError> {
    let country = country
        .map(|code| {
            if code.len() == 2 && code.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                Ok(code.to_ascii_lowercase())
            } else {
                Err(MoatError::Country)
            }
        })
        .transpose()?;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| MoatError::Unreachable)?;

    runtime
        .block_on(async { timeout(MOAT_TIMEOUT, fetch(country)).await })
        .map_err(|_| MoatError::Unreachable)?
}

async fn fetch(country: Option<String>) -> Result<Vec<String>, MoatError> {
    let endpoint =
        meek::Endpoint::new(MOAT_URL, Some(MOAT_FRONT)).map_err(|_| MoatError::Answer)?;
    let tunnel = meek::connect(endpoint)
        .await
        .map_err(|_| MoatError::Unreachable)?;

    let name = ServerName::try_from(MOAT_HOST).map_err(|_| MoatError::Answer)?;
    let config = meek::tls_config().map_err(|_| MoatError::Answer)?;
    let tls = TlsConnector::from(config)
        .connect(name, tunnel)
        .await
        .map_err(|_| MoatError::Unreachable)?;
    let mut stream = BufReader::new(tls);

    let mut countries = Vec::new();
    countries.extend(country.filter(|code| code != FALLBACK_COUNTRY));
    countries.push(FALLBACK_COUNTRY.to_owned());

    for code in countries {
        // Код — ровно две латинские буквы: подставлять в JSON безопасно.
        let body = format!(r#"{{"country":"{code}","transports":["webtunnel"]}}"#);
        meek::write_post(
            &mut stream,
            MOAT_HOST,
            SETTINGS_PATH,
            &[("Content-Type", "application/vnd.api+json")],
            body.as_bytes(),
        )
        .await
        .map_err(|_| MoatError::Unreachable)?;

        let response = meek::read_response(&mut stream, MAX_ANSWER)
            .await
            .map_err(|_| MoatError::Unreachable)?;
        if response.status != 200 {
            return Err(MoatError::Answer);
        }

        let bridges = parse_settings(&response.body)?;
        if !bridges.is_empty() || !response.keep_alive {
            return Ok(bridges);
        }
    }

    Ok(Vec::new())
}

/// Строки мостов `WebTunnel` из ответа moat.
fn parse_settings(body: &[u8]) -> Result<Vec<String>, MoatError> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| MoatError::Answer)?;
    let settings = value
        .get("settings")
        .and_then(serde_json::Value::as_array)
        .ok_or(MoatError::Answer)?;

    let lines = settings
        .iter()
        .filter_map(|setting| setting.get("bridges"))
        .filter(|bridges| {
            bridges.get("type").and_then(serde_json::Value::as_str) == Some(webtunnel::TRANSPORT)
        })
        .filter_map(|bridges| bridges.get("bridge_strings"))
        .filter_map(serde_json::Value::as_array)
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .filter(|line| line.split_whitespace().next() == Some(webtunnel::TRANSPORT))
        .map(str::to_owned)
        .collect();

    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webtunnel_bridges_are_taken_from_the_answer() {
        let answer = br#"{"settings":[
            {"bridges":{"type":"snowflake","source":"bridgedb","bridge_strings":["snowflake 192.0.2.3:80 X"]}},
            {"bridges":{"type":"webtunnel","source":"bridgedb","bridge_strings":[
                "webtunnel [2001:db8::1]:443 AAAA url=https://a.example.org/p ver=0.0.5",
                "obfs4 192.0.2.9:1 BBBB cert=x"]}}
        ],"country":"ru"}"#;

        assert_eq!(
            parse_settings(answer).expect("разбор"),
            vec!["webtunnel [2001:db8::1]:443 AAAA url=https://a.example.org/p ver=0.0.5"]
        );
        assert!(parse_settings(br#"{"settings":[],"country":"it"}"#)
            .expect("пусто")
            .is_empty());
        assert!(parse_settings(br#"{"errors":[{"code":404}]}"#).is_err());
        assert!(parse_settings(b"<html>").is_err());
    }

    /// 🔐 Код страны попадает в JSON запроса — только две буквы.
    #[test]
    fn a_bad_country_is_refused_before_any_request() {
        for bad in ["", "r", "rus", "r\"", "р у"] {
            assert!(
                matches!(fetch_bridges(Some(bad)), Err(MoatError::Country)),
                "{bad}"
            );
        }
    }
}
