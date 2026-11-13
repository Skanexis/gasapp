// SPDX-License-Identifier: Apache-2.0

//! Типы запросов и ответов сервера GasApp.
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
    /// 🔐 Пост-квантовая половина identity — открытый ключ ML-DSA-65, hex
    /// (`gasapp_protocol::pq_identity`).
    pub pq_identity_key: String,
    /// Привязка половин identity друг к другу — гибридная подпись, hex.
    pub identity_binding: String,
    /// 🔐 Ключ восстановления аккаунта — классическая половина, hex
    /// (`gasapp_protocol::account_recovery`). Им новая установка
    /// возвращает себе имя.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key: Option<String>,
    /// Ключ восстановления аккаунта — ML-DSA-65, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_pq_key: Option<String>,
    /// Адрес почты, подтверждённый кодом.
    pub email: String,
    /// Код из письма.
    pub email_code: String,
    /// Челлендж proof-of-work, hex.
    pub pow_challenge: String,
    /// Решение proof-of-work.
    pub pow_nonce: u64,
}

/// Запрос перепривязки аккаунта к новой identity — имя остаётся.
///
/// 🔐 Подписан ключом восстановления аккаунта гибридно
/// (`gasapp_protocol::account_recovery::RecoverRequest`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverAccountRequest {
    /// Имя аккаунта.
    pub username: String,
    /// Новый identity-ключ, hex.
    pub identity_key: String,
    /// Identity-ключ нового устройства, hex.
    pub device_identity_key: String,
    /// Пост-квантовая половина новой identity, hex.
    pub pq_identity_key: String,
    /// Её привязка, hex.
    pub identity_binding: String,
    /// Момент подписи, мс.
    pub issued_at: i64,
    /// Гибридная подпись ключа восстановления, hex.
    pub signature: String,
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
    /// 🔐 Пост-квантовая половина identity — открытый ключ ML-DSA-65, hex
    /// (`gasapp_protocol::pq_identity`).
    #[serde(default)]
    pub pq_identity_key: Option<String>,
    /// Привязка половин identity друг к другу — гибридная подпись, hex.
    #[serde(default)]
    pub identity_binding: Option<String>,
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
    /// 🔐 Пост-квантовая половина identity — открытый ключ ML-DSA-65, hex
    /// (`gasapp_protocol::pq_identity`).
    ///
    /// Для аккаунтов, заведённых до гибридной identity: сервер
    /// записывает её с первой же публикацией ключей.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_identity_key: Option<String>,
    /// Привязка половин identity друг к другу — гибридная подпись, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_binding: Option<String>,
}

/// Prekey bundle, полученный с сервера.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleResponse {
    /// Устройство, которому принадлежит набор.
    pub device_id: String,
    /// Identity-ключ устройства, hex.
    pub identity_key: String,
    /// 🔐 Пост-квантовая половина identity — открытый ключ ML-DSA-65, hex
    /// (`gasapp_protocol::pq_identity`).
    #[serde(default)]
    pub pq_identity_key: Option<String>,
    /// Привязка половин identity друг к другу — гибридная подпись, hex.
    #[serde(default)]
    pub identity_binding: Option<String>,
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
    /// Причина: 1 спам или мошенничество, 2 незаконное, 3 безопасность
    /// детей, 4 травля или угрозы, 5 другое, 6 выдаёт себя за другого.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<u8>,
    /// Улики, запечатанные ключом оператора
    /// (`gasapp_protocol::report_evidence`), hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

/// Открытый ключ оператора для улик к жалобам.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportKeyResponse {
    /// X25519, hex; `None` — сервер улик не принимает.
    pub key: Option<String>,
}

/// Ответ на жалобу.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedReportResponse {
    /// Учтена ли жалоба.
    pub recorded: bool,
    /// Приняты ли улики (старый сервер поля не знает — `false`).
    #[serde(default)]
    pub evidence_stored: bool,
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

/// Эпоха журнала ключей (§9.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KtEpochView {
    /// Номер эпохи.
    pub epoch: u64,
    /// Корень дерева, hex.
    pub root: String,
    /// Вершина хеш-цепочки, hex.
    pub head: String,
}

/// Ответ со списком эпох.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KtHeadsResponse {
    /// Эпохи по возрастанию.
    pub epochs: Vec<KtEpochView>,
}

/// Запрос доказательств журнала.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KtProofsRequest {
    /// Индекс имени, hex.
    pub index: String,
    /// Эпохи.
    pub epochs: Vec<u64>,
}

/// Лист журнала.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KtLeafView {
    /// Identity-ключ, hex.
    pub identity_key: String,
    /// Хеш пост-квантовой половины, hex.
    pub pq_hash: String,
    /// Версия ключа имени.
    pub version: u64,
}

/// Чужой лист на конце пути — доказательство отсутствия.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KtOtherLeafView {
    /// Индекс, hex.
    pub index: String,
    /// Значение, hex.
    pub value: String,
}

/// Доказательство для одной эпохи.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KtProofView {
    /// Эпоха.
    pub epoch: u64,
    /// Лист индекса, если он есть.
    #[serde(default)]
    pub leaf: Option<KtLeafView>,
    /// Чужой лист на конце пути.
    #[serde(default)]
    pub other: Option<KtOtherLeafView>,
    /// Соседи от корня вниз, hex.
    pub siblings: Vec<String>,
}

/// Ответ с доказательствами.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KtProofsResponse {
    /// Доказательства для существующих эпох.
    pub proofs: Vec<KtProofView>,
}

/// Запрос письма с кодом подтверждения — шаг перед регистрацией.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailCodeRequest {
    /// Адрес почты в каноничном виде.
    pub email: String,
    /// Решение proof-of-work над `pow::email_code_challenge`.
    pub pow_nonce: u64,
    /// Окно времени, для которого найдено решение.
    pub window: u64,
}

/// Условия запроса письма с кодом.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailChallengeResponse {
    /// Сколько ведущих нулевых бит требует узел сейчас.
    pub difficulty: u32,
    /// Текущее окно времени.
    pub window: u64,
}

/// Состояние своего аккаунта.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStatusResponse {
    /// Есть ли премиум — право создавать каналы.
    pub premium: bool,
}

/// Запрос создания канала.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateChannelRequest {
    /// Идентификатор канала, UUID.
    pub channel_id: String,
    /// Публичный ключ подписи записей, hex.
    pub verify_key: String,
    /// Зашифрованное описание, hex.
    pub meta: String,
}

/// Запрос изменения канала: описание и/или публичность.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateChannelRequest {
    /// Новое зашифрованное описание, hex. Нет — описание не меняется.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<String>,
    /// Менять ли публичность. Без флага `handle` и `public_link`
    /// сервер не читает: так «не трогать» отличается от «закрыть».
    #[serde(default)]
    pub set_public: bool,
    /// Публичное имя; `None` при `set_public` — сделать канал закрытым.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// Ссылка-приглашение, которую сервер отдаёт по имени.
    ///
    /// 🔐 С ней сервер может читать канал: это цена публичности.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_link: Option<String>,
    /// Сделать канал закрытым (`true`) либо открытым (`false`); нет —
    /// не менять.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed: Option<bool>,
}

/// Токен уведомлений: устройство называет серверу его SHA-256.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyTokenRequest {
    /// SHA-256 токена, hex.
    pub token_hash: String,
}

/// Токен пуш-уведомлений платформы (APNs или FCM).
///
/// 🔐 Пуш — пустой: сервер просит Apple или Google показать «Новое
/// сообщение» на устройстве и ничего больше — ни текста, ни отправителя.
/// Посредник видит лишь, что устройству что-то пришло, и когда.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushTokenRequest {
    /// `apns`, `apns-sandbox` (отладочная сборка iOS) или `fcm`.
    pub provider: String,
    /// Токен устройства у провайдера.
    pub token: String,
}

/// Имя бота: запрос токена под него либо удаление бота.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotNameRequest {
    /// Имя бота — каноничное и на `bot`.
    pub username: String,
}

/// Токен, по которому программа бота зарегистрируется.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotTokenResponse {
    /// Токен, hex. Сервер отдаёт его один раз.
    pub token: String,
    /// Сколько секунд токен действует.
    #[serde(default)]
    pub expires_in: i64,
}

/// Бот глазами владельца.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotResponse {
    /// Аккаунт бота, UUID.
    pub account_id: String,
    /// Имя бота.
    pub username: String,
}

/// Регистрация бота его программой — по токену владельца.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterBotRequest {
    /// Токен от владельца, hex.
    pub token: String,
    /// Имя, под которое токен выдан.
    pub username: String,
    /// Публичный identity-ключ аккаунта, hex.
    pub identity_key: String,
    /// Публичный identity-ключ устройства, hex.
    pub device_identity_key: String,
    /// Пост-квантовая половина identity — ключ ML-DSA-65, hex.
    pub pq_identity_key: String,
    /// Привязка половин identity друг к другу, hex.
    pub identity_binding: String,
    /// Челлендж proof-of-work, hex.
    pub pow_challenge: String,
    /// Решение proof-of-work.
    pub pow_nonce: u64,
}

/// Ссылка-приглашение закрытого канала: хеш её метки.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInviteRequest {
    /// SHA-256 метки из ссылки, hex.
    pub invite_hash: String,
}

/// Заявка на вход в закрытый канал.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinChannelRequest {
    /// Метка из ссылки-приглашения, hex.
    pub invite: String,
    /// Одноразовый ключ с подписью аккаунта, hex.
    pub request: String,
}

/// Состояние заявки.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelJoinStatusResponse {
    /// `none`, `pending` либо `approved`.
    pub status: String,
    /// Ответ на одобренную заявку: зашифрованный секрет чтения, hex.
    #[serde(default)]
    pub grant: Option<String>,
}

/// Заявка глазами того, кто ведёт канал.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelJoinRequestResponse {
    /// Аккаунт заявителя, UUID.
    pub account_id: String,
    /// Его имя — по словам сервера.
    pub username: String,
    /// Одноразовый ключ с подписью, hex.
    pub request: String,
}

/// Ответ на заявку.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnswerChannelJoinRequest {
    /// Чья заявка, UUID.
    pub account_id: String,
    /// Секрет чтения, зашифрованный под заявку, hex; нет — отклонить.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    /// Удостоверение участника, hex: подпись того, кто ведёт канал,
    /// под ключом доставки из заявки.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
}

/// Подписчик глазами того, кто ведёт канал.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMemberResponse {
    /// Аккаунт, UUID.
    pub account_id: String,
    /// Имя — по словам сервера.
    pub username: String,
}

/// Запрос об одном подписчике: удалить либо снять запрет.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMemberRequest {
    /// Аккаунт, UUID.
    pub account_id: String,
}

/// Запрос публикации записи.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishPostRequest {
    /// Шифротекст записи, hex.
    pub body: String,
    /// Номер, под которым автор ждёт запись, — он же лежит внутри
    /// шифротекста. Если канал успел уйти вперёд, сервер отвечает
    /// `409` и запись не сохраняет.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

/// Запрос назначения администратора канала.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddChannelAdminRequest {
    /// Устройство будущего администратора, UUID, — из его заявки.
    pub device_id: String,
    /// Публичный ключ, которым он подписывает записи, hex.
    pub verify_key: String,
}

/// Запрос снятия администратора канала.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveChannelAdminRequest {
    /// Его публичный ключ подписи, hex.
    pub verify_key: String,
}

/// Ответ на публикацию и правку.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishPostResponse {
    /// Номер записи в канале.
    pub seq: u64,
    /// Номер изменения канала.
    #[serde(default)]
    pub rev: u64,
}

/// Запрос правки или удаления записи.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplacePostRequest {
    /// Номер записи.
    pub seq: u64,
    /// Исправленная запись либо подписанная отметка об удалении, hex.
    pub body: String,
    /// Удаление, а не правка.
    pub deleted: bool,
}

/// Ответ на загрузку медиа канала.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMediaResponse {
    /// Адрес блоба в канале, UUID.
    pub media_id: String,
}

/// Запрос удаления медиа канала.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteChannelMediaRequest {
    /// Адрес блоба в канале, UUID.
    pub media_id: String,
}

/// Канал глазами читателя.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelResponse {
    /// Идентификатор, UUID.
    pub channel_id: String,
    /// Публичный ключ подписи записей, hex.
    pub verify_key: String,
    /// Зашифрованное описание, hex.
    pub meta: String,
    /// Номер последней записи.
    pub last_seq: u64,
    /// Номер последнего изменения.
    #[serde(default)]
    pub last_rev: u64,
    /// Публичное имя, если канал публичный.
    #[serde(default)]
    pub handle: Option<String>,
    /// Ссылка-приглашение публичного канала.
    #[serde(default)]
    pub public_link: Option<String>,
    /// Число подписчиков — статистика сервера, ничем не подписана.
    #[serde(default)]
    pub subscribers: u64,
    /// Закрытый ли канал: вход по заявке, чтение — участникам.
    #[serde(default)]
    pub closed: bool,
    /// Номер действующего ключа чтения: растёт с каждой сменой ключа.
    #[serde(default)]
    pub key_epoch: u32,
}

/// Жалоба на канал.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportChannelRequest {
    /// Причина: 1 спам, 2 незаконное, 3 безопасность детей, 4 насилие
    /// и ненависть, 5 другое.
    pub reason: u8,
    /// Номер записи, на которую жалуются; нет — на канал целиком.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Ссылка канала — если жалобщик решил дать оператору прочитать
    /// записи.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

/// Ключ доставки участника закрытого канала.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMemberKeyRequest {
    /// Открытый ключ за подписью аккаунта, hex.
    pub member_key: String,
    /// Удостоверение, hex — его выписывает себе тот, кто ведёт канал.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
}

/// Ключ доставки участника — тому, кто ведёт канал.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMemberKeyResponse {
    /// Аккаунт участника, UUID.
    pub account_id: String,
    /// Ключ доставки, hex.
    pub member_key: String,
    /// Удостоверение участника, hex. 🔐 Проверяет его устройство, а не сервер.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
}

/// Ключ эпохи одному участнику.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelEpochGrant {
    /// Кому, UUID.
    pub account_id: String,
    /// Ключ эпохи шифротекстом под ключ доставки участника, hex.
    pub grant: String,
    /// Удостоверение на эту эпоху, hex; нет — прежнее остаётся.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
}

/// Смена ключа канала либо досылка ключей действующей эпохи.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyChannelRequest {
    /// Эпоха: следующая — при смене ключа, действующая — при досылке.
    pub epoch: u32,
    /// Звено цепочки к новой эпохе, hex; нет — досылка.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    /// Ключи участникам.
    pub grants: Vec<ChannelEpochGrant>,
}

/// Звено цепочки ключей.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelEpochResponse {
    /// Номер эпохи.
    pub epoch: u32,
    /// Прежний ключ, зашифрованный новым, за подписью сменившего, hex.
    pub record: String,
}

/// Запись канала.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPostResponse {
    /// Номер записи.
    pub seq: u64,
    /// Номер изменения.
    #[serde(default)]
    pub rev: u64,
    /// Шифротекст либо отметка об удалении, hex.
    pub body: String,
    /// Удалена ли запись — по словам сервера; верит читатель только
    /// подписанной отметке в `body`.
    #[serde(default)]
    pub deleted: bool,
    /// Час публикации по часам сервера, миллисекунды эпохи.
    pub posted_at: i64,
    /// Сколько подписчиков дочитали до записи.
    #[serde(default)]
    pub views: u64,
    /// Реакции: `эмодзи:число,…`.
    #[serde(default)]
    pub reactions: String,
}

/// Отметка «дочитал до записи».
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSeenRequest {
    /// Номер записи.
    pub seq: u64,
}

/// Реакция на запись.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelReactRequest {
    /// Номер записи.
    pub seq: u64,
    /// Эмодзи из закрытого набора; `None` — снять реакцию.
    pub emoji: Option<String>,
}
