// SPDX-License-Identifier: Apache-2.0

//! Сверка формы запросов и ответов с контрактом сервера.
//!
//! # Зачем этот файл существует
//!
//! Клиент под Apache-2.0, сервер под AGPL-3.0, связать их зависимостью
//! нельзя (ADR-006). Поэтому типы `api` продублированы, и ничто
//! в компиляторе не мешает им разойтись с серверными: переименованное
//! поле или изменённый тип обнаружились бы только в бою.
//!
//! Здесь зафиксирована **проволочная форма** — точные имена полей
//! в JSON. Тесты сравнивают её с эталоном, снятым с серверных структур
//! (`server/aegis-server-api/src/routes.rs`). Расхождение роняет тест
//! на этой стороне, а не оставляет клиент молча несовместимым.
//!
//! Это не замена интеграционному тесту против живого сервера — тот
//! проверяет поведение, а этот форму. Форма ломается чаще.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_net::api::{
    BundleResponse, CertificateResponse, DiscoveryResponse, EnvelopeResponse, PublishKeysRequest,
    RegisterRequest, RegisterResponse, SealedAccessRequest, SealedReportRequest,
    SealedReportResponse, SealedSendRequest, SendRequest,
};

/// Возвращает отсортированный список полей JSON-объекта.
fn field_names(json: &str) -> Vec<String> {
    let value: serde_json::Value = serde_json::from_str(json).expect("корректный JSON");
    let object = value.as_object().expect("объект");

    let mut names: Vec<String> = object.keys().cloned().collect();
    names.sort();

    names
}

/// Поля запроса регистрации совпадают с серверными.
#[test]
fn register_request_matches_server_contract() {
    let request = RegisterRequest {
        username: "alice".to_owned(),
        identity_key: "aa".to_owned(),
        device_identity_key: "bb".to_owned(),
        pow_challenge: "cc".to_owned(),
        pow_nonce: 1,
    };

    let json = serde_json::to_string(&request).unwrap();

    assert_eq!(
        field_names(&json),
        vec![
            "device_identity_key",
            "identity_key",
            "pow_challenge",
            "pow_nonce",
            "username",
        ]
    );
}

/// Ответ регистрации разбирается из формы, которую отдаёт сервер.
///
/// Идентификаторы приходят строками: сервер сериализует `Uuid`,
/// а `serde_json` кодирует его как строку.
#[test]
fn register_response_parses_server_shape() {
    let body = r#"{"account_id":"3f2504e0-4f89-11d3-9a0c-0305e82c3301",
                   "device_id":"3f2504e0-4f89-11d3-9a0c-0305e82c3302"}"#;

    let response: RegisterResponse = serde_json::from_str(body).unwrap();

    assert!(response.account_id.starts_with("3f2504e0"));
    assert!(response.device_id.ends_with("3302"));
}

/// Ответ discovery разбирается из серверной формы.
#[test]
fn discovery_response_parses_server_shape() {
    let body = r#"{"account_id":"acc","identity_key":"deadbeef"}"#;

    let response: DiscoveryResponse = serde_json::from_str(body).unwrap();

    assert_eq!(response.identity_key, "deadbeef");
}

/// Публикация предключей: имена полей и форма кортежей.
///
/// Одноразовые ключи передаются массивами пар и троек — сервер
/// разбирает их как `Vec<(i32, String)>`, поэтому JSON обязан быть
/// массивом массивов, а не объектов.
#[test]
fn publish_keys_matches_server_contract() {
    let request = PublishKeysRequest {
        signed_key_id: 1,
        signed_public: "aa".to_owned(),
        signed_signature: "bb".to_owned(),
        kem_key_id: 2,
        kem_public: "cc".to_owned(),
        kem_signature: "dd".to_owned(),
        one_time: vec![(10, "ee".to_owned())],
        one_time_kem: vec![(20, "ff".to_owned(), "99".to_owned())],
    };

    let json = serde_json::to_string(&request).unwrap();

    assert_eq!(
        field_names(&json),
        vec![
            "kem_key_id",
            "kem_public",
            "kem_signature",
            "one_time",
            "one_time_kem",
            "signed_key_id",
            "signed_public",
            "signed_signature",
        ]
    );

    // Кортежи кодируются массивами, а не объектами.
    assert!(json.contains(r#""one_time":[[10,"ee"]]"#));
    assert!(json.contains(r#""one_time_kem":[[20,"ff","99"]]"#));
}

/// Пустые пулы допустимы: сервер объявляет поля с `#[serde(default)]`.
#[test]
fn publish_keys_allows_empty_pools() {
    let body = r#"{
        "signed_key_id":1,"signed_public":"aa","signed_signature":"bb",
        "kem_key_id":2,"kem_public":"cc","kem_signature":"dd"
    }"#;

    let request: PublishKeysRequest = serde_json::from_str(body).unwrap();

    assert!(request.one_time.is_empty());
    assert!(request.one_time_kem.is_empty());
}

/// Bundle разбирается вместе с флагом ослабления.
#[test]
fn bundle_response_parses_server_shape() {
    let body = r#"{
        "device_id":"dev","identity_key":"aa",
        "signed_key_id":1,"signed_public":"bb","signed_signature":"cc",
        "kem_key_id":2,"kem_public":"dd","kem_signature":"ee",
        "one_time":[10,"ff"],"one_time_kem":[20,"11","22"],
        "degraded":false
    }"#;

    let bundle: BundleResponse = serde_json::from_str(body).unwrap();

    assert_eq!(bundle.one_time, Some((10, "ff".to_owned())));
    assert_eq!(
        bundle.one_time_kem,
        Some((20, "11".to_owned(), "22".to_owned()))
    );
    assert!(!bundle.degraded);
}

/// 🔐 Исчерпанный пул приходит как `null`, а не как ошибка.
///
/// Отказ означал бы, что вычерпав чужой пул, атакующий лишает контакт
/// возможности принимать сообщения вовсе.
#[test]
fn bundle_response_handles_exhausted_pool() {
    let body = r#"{
        "device_id":"dev","identity_key":"aa",
        "signed_key_id":1,"signed_public":"bb","signed_signature":"cc",
        "kem_key_id":2,"kem_public":"dd","kem_signature":"ee",
        "one_time":null,"one_time_kem":null,"degraded":true
    }"#;

    let bundle: BundleResponse = serde_json::from_str(body).unwrap();

    assert!(bundle.one_time.is_none());
    assert!(bundle.degraded, "исчерпание пула обязано быть отмечено");
}

/// Отправка конверта: имена полей.
#[test]
fn send_request_matches_server_contract() {
    let request = SendRequest {
        destination_device_id: "dev".to_owned(),
        ciphertext: "aabb".to_owned(),
    };

    let json = serde_json::to_string(&request).unwrap();

    assert_eq!(
        field_names(&json),
        vec!["ciphertext", "destination_device_id"]
    );
}

/// Конверт разбирается вместе с округлённой меткой времени.
#[test]
fn envelope_response_parses_server_shape() {
    let body = r#"[{"envelope_id":"env","ciphertext":"aabb","queued_at_bucketed":1699999200}]"#;

    let envelopes: Vec<EnvelopeResponse> = serde_json::from_str(body).unwrap();

    assert_eq!(envelopes.len(), 1);
    let first = envelopes.first().unwrap();
    assert_eq!(first.queued_at_bucketed % 3600, 0, "метка не округлена");
}

/// 🔐 Шифротекст остаётся непрозрачным.
///
/// Клиент не разбирает содержимое конверта: он передаёт его в ядро
/// как есть. Тест фиксирует, что тип поля — строка hex, а не структура.
#[test]
fn ciphertext_stays_opaque() {
    let body = r#"[{"envelope_id":"e","ciphertext":"00ff","queued_at_bucketed":0}]"#;

    let envelopes: Vec<EnvelopeResponse> = serde_json::from_str(body).unwrap();
    let ciphertext = &envelopes.first().unwrap().ciphertext;

    assert_eq!(ciphertext, "00ff");
    assert_eq!(hex::decode(ciphertext).unwrap(), vec![0x00, 0xFF]);
}

// --- Sealed sender (раздел 15.2) ---

/// Поля анонимной отправки совпадают с серверными.
///
/// 🔐 Расхождение здесь означало бы, что sealed sender молча
/// не работает: сервер отвечал бы 400 на каждую попытку, и клиент
/// откатывался бы на обычную отправку — то есть на ту, где
/// отправитель виден.
#[test]
fn sealed_send_request_matches_server_contract() {
    let request = SealedSendRequest {
        destination_device_id: "11111111-1111-1111-1111-111111111111".to_owned(),
        sealed: "aabb".to_owned(),
        access_key: Some("ccdd".to_owned()),
        pow_nonce: None,
    };

    let json = serde_json::to_string(&request).unwrap();

    assert_eq!(
        field_names(&json),
        vec!["access_key", "destination_device_id", "sealed"]
    );
}

/// Отсутствующий ключ доступа сериализуется как `null`, а не пропадает.
///
/// Сервер читает поле как `Option`, и пропуск поля тоже разобрался бы.
/// Тест фиксирует форму, чтобы смена на `skip_serializing_if` была
/// осознанным решением, а не побочным эффектом правки.
#[test]
fn sealed_send_request_keeps_absent_access_key() {
    let request = SealedSendRequest {
        destination_device_id: "11111111-1111-1111-1111-111111111111".to_owned(),
        sealed: "aabb".to_owned(),
        access_key: None,
        pow_nonce: None,
    };

    let json = serde_json::to_string(&request).unwrap();

    assert!(
        json.contains("\"access_key\":null"),
        "форма изменилась: {json}"
    );
}

/// 🔐 Первый контакт: ключа доступа нет, есть решение proof-of-work.
///
/// Имя и тип поля совпадают с серверными — иначе каждое первое
/// сообщение отвергалось бы, и запечатать его было бы нечем.
#[test]
fn sealed_send_request_carries_first_contact_pow() {
    let request = SealedSendRequest {
        destination_device_id: "11111111-1111-1111-1111-111111111111".to_owned(),
        sealed: "aabb".to_owned(),
        access_key: None,
        pow_nonce: Some(7),
    };

    let json = serde_json::to_string(&request).unwrap();

    assert_eq!(
        field_names(&json),
        vec!["access_key", "destination_device_id", "pow_nonce", "sealed"]
    );
    assert!(json.contains("\"pow_nonce\":7"), "форма изменилась: {json}");
}

/// Поля публикации ключа доступа совпадают с серверными.
#[test]
fn sealed_access_request_matches_server_contract() {
    let request = SealedAccessRequest {
        access_key_hash: "aabb".to_owned(),
        allow_from_anyone: false,
    };

    let json = serde_json::to_string(&request).unwrap();

    assert_eq!(
        field_names(&json),
        vec!["access_key_hash", "allow_from_anyone"]
    );
}

/// Ответ с сертификатом разбирается в клиентский тип.
#[test]
fn certificate_response_parses_server_shape() {
    let json = r#"{
        "certificate": "aabb",
        "expires_at_millis": 1760000000000,
        "server_key": "ccdd"
    }"#;

    let response: CertificateResponse = serde_json::from_str(json).unwrap();

    assert_eq!(response.certificate, "aabb");
    assert_eq!(response.expires_at_millis, 1_760_000_000_000);
    assert_eq!(response.server_key, "ccdd");
}

/// Поля жалобы совпадают с серверными.
#[test]
fn sealed_report_request_matches_server_contract() {
    let request = SealedReportRequest {
        certificate: "aabb".to_owned(),
    };

    let json = serde_json::to_string(&request).unwrap();

    assert_eq!(field_names(&json), vec!["certificate"]);
}

/// Ответ на жалобу разбирается в клиентский тип.
#[test]
fn sealed_report_response_parses_server_shape() {
    let json = r#"{"recorded": true, "total_reporters": 3}"#;

    let response: SealedReportResponse = serde_json::from_str(json).unwrap();

    assert!(response.recorded);
    assert_eq!(response.total_reporters, 3);
}
