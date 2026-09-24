// SPDX-License-Identifier: Apache-2.0

//! Типы запросов и ответов сервера AEGIS.
//!
//! # Почему они продублированы, а не взяты из серверного крейта
//!
//! Клиент под Apache-2.0, сервер под AGPL-3.0 (ADR-006). Связать их
//! зависимостью нельзя: клиент, линкующий AGPL-код, обязан открыться
//! под AGPL, а это закрывает путь в App Store.
//!
//! Дублирование — осознанная плата. Расхождение форм ловится
//! интеграционным тестом против настоящего сервера
//! (`tests/against_server.rs`): он собирает JSON клиентскими типами
//! и разбирает серверными, поэтому несовпадение поля роняет тест,
//! а не остаётся до продакшена.
//!
//! # Про hex
//!
//! Все ключи и шифротексты передаются hex-строками, а не base64:
//! их сверяют глазами при отладке, а hex читается посимвольно.
//! Разница в объёме (33 %) на этих размерах несущественна.

use serde::{Deserialize, Serialize};

/// Запрос регистрации аккаунта.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Желаемое имя.
    pub username: String,
    /// Публичный identity-ключ аккаунта, hex.
    pub identity_key: String,
    /// Публичный identity-ключ первого устройства, hex.
    pub device_identity_key: String,
    /// Челлендж proof-of-work, hex.
    pub pow_challenge: String,
    /// Решение proof-of-work.
    pub pow_nonce: u64,
}

/// Ответ на регистрацию.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// Идентификатор аккаунта.
    pub account_id: String,
    /// Идентификатор первого устройства.
    pub device_id: String,
}

/// Ответ discovery: аккаунт найден по имени.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    /// Идентификатор аккаунта.
    pub account_id: String,
    /// Публичный identity-ключ, hex.
    pub identity_key: String,
    /// Устройства аккаунта.
    ///
    /// Prekey bundle и доставка адресуются по устройству, а не по
    /// аккаунту, поэтому без этого списка первая отправка невозможна.
    #[serde(default)]
    pub device_ids: Vec<String>,
    /// Ключ ML-KEM-1024 sealed sender первого устройства, hex.
    ///
    /// 🔐 Нужен, чтобы запечатать конверт гибридно: без него имя
    /// отправителя защищала бы только кривая X25519. Подписан
    /// identity-ключом владельца; подпись проверяет отправитель —
    /// сервер ключ раздаёт, но подменить не может.
    #[serde(default)]
    pub sealed_kem_public: Option<String>,
    /// Подпись ключа ML-KEM sealed sender, hex.
    #[serde(default)]
    pub sealed_kem_signature: Option<String>,
}

/// Публикация предключей устройства.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishKeysRequest {
    /// Идентификатор подписанного предключа.
    pub signed_key_id: i32,
    /// Публичная часть подписанного предключа, hex.
    pub signed_public: String,
    /// Подпись подписанного предключа, hex.
    pub signed_signature: String,
    /// Идентификатор пост-квантового предключа.
    pub kem_key_id: i32,
    /// Публичная часть пост-квантового предключа, hex.
    pub kem_public: String,
    /// Подпись пост-квантового предключа, hex.
    pub kem_signature: String,
    /// Одноразовые предключи: идентификатор и публичная часть.
    #[serde(default)]
    pub one_time: Vec<(i32, String)>,
    /// Одноразовые пост-квантовые: идентификатор, ключ, подпись.
    #[serde(default)]
    pub one_time_kem: Vec<(i32, String, String)>,
    /// Ключ ML-KEM-1024 sealed sender устройства, hex.
    ///
    /// Долгоживущий: публикуется один раз и больше не меняется.
    /// Отдаётся отправителям через discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_kem_public: Option<String>,
    /// Подпись ключа ML-KEM sealed sender identity-ключом, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_kem_signature: Option<String>,
}

/// Prekey bundle, полученный с сервера.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleResponse {
    /// Устройство, которому принадлежит набор.
    pub device_id: String,
    /// Identity-ключ устройства, hex.
    pub identity_key: String,
    /// Идентификатор подписанного предключа.
    pub signed_key_id: i32,
    /// Публичная часть подписанного предключа, hex.
    pub signed_public: String,
    /// Подпись, hex.
    pub signed_signature: String,
    /// Идентификатор пост-квантового предключа.
    pub kem_key_id: i32,
    /// Публичная часть пост-квантового предключа, hex.
    pub kem_public: String,
    /// Подпись пост-квантового предключа, hex.
    pub kem_signature: String,
    /// Одноразовый предключ, если пул не исчерпан.
    pub one_time: Option<(i32, String)>,
    /// Одноразовый пост-квантовый предключ.
    pub one_time_kem: Option<(i32, String, String)>,
    /// Ослаблена ли forward secrecy первого сообщения.
    ///
    /// Систематическое исчерпание пула может означать, что кто-то
    /// намеренно вычерпывает предключи собеседника, поэтому флаг
    /// показывается в Security Center, а не игнорируется.
    pub degraded: bool,
}

/// Конверт, ожидающий доставки.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeResponse {
    /// Идентификатор конверта.
    pub envelope_id: String,
    /// Шифротекст, hex.
    pub ciphertext: String,
    /// Время постановки в очередь, **округлённое до часа**.
    ///
    /// Точная метка не передаётся: она служила бы признаком для
    /// корреляции отправителя с получателем (раздел 15 плана).
    pub queued_at_bucketed: i64,
}

/// Запрос анонимной отправки (sealed sender, раздел 15.2).
///
/// 🔐 Подписи здесь нет намеренно: она и была бы той меткой
/// отправителя, которую sealed sender убирает. Право на отправку
/// доказывается ключом доступа получателя.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSendRequest {
    /// Устройство-получатель.
    pub destination_device_id: String,
    /// Запечатанный конверт, hex. Сервер его не разбирает.
    pub sealed: String,
    /// Ключ доступа получателя, hex.
    pub access_key: Option<String>,
    /// Решение proof-of-work первого контакта — когда ключа доступа
    /// получателя ещё нет (`pow::first_contact_challenge`).
    ///
    /// Не сериализуется, если его нет: сервер прежних версий
    /// неизвестное поле отверг бы.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pow_nonce: Option<u64>,
}

/// Ключ доступа, публикуемый получателем.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedAccessRequest {
    /// SHA-256 от ключа доступа, hex.
    ///
    /// 🔐 Уходит именно хеш: сам ключ сервер знать не должен.
    pub access_key_hash: String,
    /// Принимать ли конверты вообще без ключа доступа.
    pub allow_from_anyone: bool,
}

/// Сертификат отправителя, выданный сервером.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateResponse {
    /// Сертификат целиком, hex.
    pub certificate: String,
    /// Момент истечения, миллисекунды.
    pub expires_at_millis: i64,
    /// Публичный ключ сервера, hex.
    pub server_key: String,
}

/// Жалоба на отправителя, раскрытого получателем.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedReportRequest {
    /// Сертификат отправителя, извлечённый из конверта, hex.
    pub certificate: String,
}

/// Ответ на жалобу.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedReportResponse {
    /// Учтена ли жалоба.
    pub recorded: bool,
    /// Сколько разных людей пожаловались на этот аккаунт.
    pub total_reporters: i64,
}

/// Что исчезло вместе с аккаунтом.
///
/// Сервер отвечает числами, а не словом «готово»: право на удаление,
/// подтверждённое только словом, ничем не отличается от отсутствия
/// удаления. Всё перечисленное — данные самого запрашивающего.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountDeletedResponse {
    /// Сколько устройств удалено.
    pub devices: u64,
    /// Сколько недоставленных конвертов удалено.
    pub envelopes: u64,
    /// Сколько загруженных вложений удалено.
    pub attachments: u64,
}
