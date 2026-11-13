// SPDX-License-Identifier: AGPL-3.0-only

//! Центр жалоб: очередь дел и дело по аккаунту.
//!
//! # 🔐 Как понять, есть ли нарушение, не читая переписку
//!
//! Сервер переписку не видит и не увидит. Решение строится на том, что
//! у него и так есть, плюс на том, что жалобщик **сам** решил показать:
//!
//! * **доказательство отправителя** — каждая жалоба несёт сертификат,
//!   подписанный сервером: этот аккаунт действительно писал жалобщику;
//! * **независимость жалоб** — разные жалобщики, разные сертификаты,
//!   разные дни; жалобщик, который жалуется на всех подряд, весит меньше;
//!   взаимные жалобы — скорее ссора, чем спам; пачка жалоб за один час —
//!   возможная накрутка;
//! * **причина** — её выбирает жалобщик; безопасность детей — сразу наверх;
//! * **улики** — сообщения обидчика и скриншоты, зашифрованные на
//!   телефоне ключом админ-центра. Один и тот же текст от разных
//!   жалобщиков — рассылка, то есть спам, без единого слова чужой
//!   переписки сверх показанного.
//!
//! Кто пожаловался, админ-центр не показывает нигде. Улики удаляются
//! решением по делу или через 30 дней.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use aws_lc_rs::{aead, agreement, hkdf};
use base64::Engine as _;
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use crate::queries::Reason;
use crate::{escape, icon};

// ---------------------------------------------------------------------
// Ключ улик

/// Заголовок запечатанных улик (`gasapp_protocol::report_evidence`).
const MAGIC: &[u8; 4] = b"GRE1";
const INFO: &[u8] = b"GasApp report evidence v1";

/// Закрытый ключ X25519 админ-центра для улик.
///
/// 🔐 Живёт только в учётных данных службы
/// (`/etc/gasapp/credentials/evidence_key`); в базу уходит лишь
/// открытый — его узлы отдают телефонам.
pub struct EvidenceKey {
    secret: agreement::PrivateKey,
    public: [u8; 32],
}

impl std::fmt::Debug for EvidenceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EvidenceKey(…)")
    }
}

impl EvidenceKey {
    /// Ключ из 32 байт hex.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        let bytes = hex::decode(text.trim()).ok()?;
        let secret = agreement::PrivateKey::from_private_key(&agreement::X25519, &bytes).ok()?;
        let public = secret.compute_public_key().ok()?;
        let public: [u8; 32] = public.as_ref().try_into().ok()?;
        Some(Self { secret, public })
    }

    /// Открытый ключ.
    #[must_use]
    pub const fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// Вскрывает запечатанные улики.
    #[must_use]
    pub fn open(&self, sealed: &[u8]) -> Option<Evidence> {
        let (magic, rest) = sealed.split_first_chunk::<4>()?;
        if magic != MAGIC {
            return None;
        }
        let (ephemeral, rest) = rest.split_first_chunk::<32>()?;
        let (nonce, body) = rest.split_first_chunk::<12>()?;

        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, ephemeral);
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(ephemeral);
        salt.extend_from_slice(&self.public);
        let mut key = [0u8; 32];
        agreement::agree(&self.secret, peer, (), |shared| {
            hkdf::Salt::new(hkdf::HKDF_SHA256, &salt)
                .extract(shared)
                .expand(&[INFO], hkdf::HKDF_SHA256)
                .and_then(|okm| okm.fill(&mut key))
                .map_err(|_| ())
        })
        .ok()?;

        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key).ok()?;
        let opener = aead::LessSafeKey::new(unbound);
        let mut buffer = body.to_vec();
        let plain = opener
            .open_in_place(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::from(MAGIC),
                &mut buffer,
            )
            .ok()?;
        decode(plain)
    }
}

/// Сообщение обидчика из улик.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    /// Время сообщения, миллисекунды Unix (слова жалобщика).
    pub sent_at_millis: i64,
    /// Текст.
    pub text: String,
}

/// Вскрытые улики одного жалобщика.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evidence {
    /// Сообщения обидчика.
    pub quotes: Vec<Quote>,
    /// Скриншоты, JPEG.
    pub images: Vec<Vec<u8>>,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if self.0.len() < count {
            return None;
        }
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn length(&mut self, limit: usize) -> Option<usize> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?)).ok()?;
        (length <= limit).then_some(length)
    }
}

/// Формат — зеркало `gasapp_protocol::report_evidence::decode`.
fn decode(raw: &[u8]) -> Option<Evidence> {
    let mut reader = Reader(raw);
    if reader.array::<1>()? != [1] {
        return None;
    }
    let mut evidence = Evidence::default();
    let [quotes] = reader.array::<1>()?;
    if quotes > 10 {
        return None;
    }
    for _ in 0..quotes {
        let sent_at_millis = i64::from_be_bytes(reader.array()?);
        let length = reader.length(4096)?;
        let text = String::from_utf8(reader.take(length)?.to_vec()).ok()?;
        evidence.quotes.push(Quote {
            sent_at_millis,
            text,
        });
    }
    let [images] = reader.array::<1>()?;
    if images > 5 {
        return None;
    }
    for _ in 0..images {
        let length = reader.length(400 * 1024)?;
        evidence.images.push(reader.take(length)?.to_vec());
    }
    reader.0.is_empty().then_some(evidence)
}

/// Публикует открытый ключ улик в базе — или убирает его, если ключа
/// у админ-центра нет: тогда узлы улик не принимают.
///
/// # Errors
///
/// Ошибка базы.
pub async fn publish_key(pool: &PgPool, key: Option<&EvidenceKey>) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE admin_state SET evidence_key = $1 WHERE id = 1")
        .bind(key.map(|key| key.public().to_vec()))
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------
// Сигналы и оценка

/// Причины жалоб, коды миграции 0030.
pub const REASONS: [(i16, &str); 6] = [
    (3, "Child safety"),
    (1, "Spam or scam"),
    (4, "Harassment or threats"),
    (6, "Impersonation"),
    (2, "Illegal content"),
    (5, "Something else"),
];

/// Что известно о деле — только счётчики.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signals {
    /// Разные жалобщики (устройства).
    pub reporters: i64,
    /// Разные сертификаты отправителя.
    pub certificates: i64,
    /// Всего жалоб.
    pub reports: i64,
    /// В скольких разных днях приходили жалобы.
    pub days: i64,
    /// Наибольшее число жалоб за один час.
    pub peak_hour: i64,
    /// Жалобщики, которые жаловались на пять и больше аккаунтов.
    pub serial_reporters: i64,
    /// Скольких своих жалобщиков этот аккаунт сам обжаловал.
    pub mutual: i64,
    /// Жалобщики, приложившие улики.
    pub evidence: i64,
    /// Жалобы по причинам, в порядке [`REASONS`]; последний — без причины.
    pub reasons: [i64; 7],
}

impl Signals {
    /// Жалоб с причиной «безопасность детей».
    #[must_use]
    pub fn child_safety(&self) -> i64 {
        self.reasons.first().copied().unwrap_or(0)
    }

    /// Независимые жалобщики: не больше разных сертификатов (один
    /// сертификат у десятка «жалобщиков» — скорее один человек) и без
    /// тех, кто жалуется на всех подряд.
    #[must_use]
    pub fn independent(&self) -> i64 {
        self.reporters
            .saturating_sub(self.serial_reporters)
            .min(self.certificates)
            .max(0)
    }

    /// Почти все жалобы — за один час: возможная накрутка.
    #[must_use]
    pub fn burst(&self) -> bool {
        self.reports >= 3 && self.peak_hour.saturating_mul(100) >= self.reports.saturating_mul(80)
    }

    /// Самая частая причина (кроме «без причины»).
    #[must_use]
    pub fn top_reason(&self) -> Option<i16> {
        REASONS
            .iter()
            .zip(self.reasons.iter())
            .filter(|(_, count)| **count > 0)
            .max_by_key(|(_, count)| **count)
            .map(|((code, _), _)| *code)
    }
}

/// Насколько дело готово к решению.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Безопасность детей — смотреть сейчас.
    Urgent,
    /// Сигналы сходятся.
    Strong,
    /// Есть основания посмотреть внимательно.
    Review,
    /// Одна жалоба без улик — решать рано.
    Weak,
}

impl Level {
    const fn badge(self) -> (&'static str, &'static str) {
        match self {
            Self::Urgent => ("bg-danger", "Urgent"),
            Self::Strong => ("bg-orange-lt", "Strong signals"),
            Self::Review => ("bg-yellow-lt", "Needs review"),
            Self::Weak => ("bg-secondary-lt", "Weak"),
        }
    }
}

/// Довод «за» или «против» нарушения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Усиливает (`true`) или ослабляет (`false`) подозрение.
    pub supports: bool,
    /// Текст для оператора.
    pub text: String,
}

fn plural(count: i64, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// Оценивает дело. Это подсказка оператору, а не решение: удаляет
/// всегда человек.
#[must_use]
pub fn assess(s: &Signals, shared_texts: i64) -> (Level, Vec<Finding>) {
    let independent = s.independent();
    let mut findings = Vec::new();
    let mut add = |supports: bool, text: String| findings.push(Finding { supports, text });

    add(
        independent >= 2,
        format!(
            "{} with a server-signed proof that this account messaged them.",
            plural(independent, "independent reporter", "independent reporters")
        ),
    );
    if s.certificates < s.reporters {
        add(
            false,
            format!(
                "Only {} for {} — several reports reuse one proof, which points to one person behind several accounts.",
                plural(s.certificates, "distinct certificate", "distinct certificates"),
                plural(s.reporters, "reporter", "reporters"),
            ),
        );
    }
    if s.days >= 2 {
        add(
            true,
            format!(
                "Reports span {} — sustained behaviour, not a single incident.",
                plural(s.days, "day", "days")
            ),
        );
    }
    if shared_texts > 0 {
        add(
            true,
            format!(
                "{} reported by different people — the same text sent to many: bulk messaging.",
                plural(shared_texts, "message was", "messages were")
            ),
        );
    }
    if s.burst() {
        add(
            false,
            "Most reports arrived within one hour — possible coordinated reporting.".to_owned(),
        );
    }
    if s.serial_reporters > 0 {
        add(
            false,
            format!(
                "{} also reported five or more other accounts — weigh them less.",
                plural(s.serial_reporters, "reporter", "reporters")
            ),
        );
    }
    if s.mutual > 0 {
        add(
            false,
            format!(
                "This account reported {} back — this looks like a two-way dispute.",
                plural(s.mutual, "of its reporters", "of its reporters")
            ),
        );
    }
    if s.evidence > 0 {
        add(
            true,
            format!(
                "{} attached evidence — read it below.",
                plural(s.evidence, "reporter", "reporters")
            ),
        );
    }

    let doubts = s.burst() || s.mutual > 0;
    let level = if s.child_safety() > 0 {
        Level::Urgent
    } else if !doubts
        && ((independent >= 3 && s.days >= 2)
            || shared_texts > 0
            || (s.evidence > 0 && independent >= 2))
    {
        Level::Strong
    } else if independent >= 2 || s.evidence > 0 {
        Level::Review
    } else {
        Level::Weak
    };
    (level, findings)
}

/// Сколько разных текстов прислали два и больше разных жалобщика.
///
/// Текст сравнивается без регистра, пробелов и цифр: рассылка часто
/// меняет в сообщении только число или имя.
#[must_use]
pub fn shared_texts(submissions: &[Evidence]) -> i64 {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for evidence in submissions {
        let own: HashSet<String> = evidence
            .quotes
            .iter()
            .map(|quote| {
                quote
                    .text
                    .chars()
                    .filter(|ch| !ch.is_whitespace() && !ch.is_ascii_digit())
                    .flat_map(char::to_lowercase)
                    .collect::<String>()
            })
            .filter(|text| text.chars().count() >= 12)
            .collect();
        for text in own {
            let count = seen.entry(text).or_insert(0);
            *count = count.saturating_add(1);
        }
    }
    i64::try_from(seen.values().filter(|count| **count >= 2).count()).unwrap_or(i64::MAX)
}

/// Ссылки в тексте — частый признак спама и мошенничества.
fn has_link(text: &str) -> bool {
    let lower = text.to_lowercase();
    ["http://", "https://", "www.", "t.me/", ".onion", "bit.ly"]
        .iter()
        .any(|marker| lower.contains(marker))
}

// ---------------------------------------------------------------------
// Запросы

/// Дело в очереди.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseRow {
    /// Аккаунт.
    pub account_id: Uuid,
    /// Имя.
    pub username: String,
    /// Час последней жалобы.
    pub last_report: String,
    /// Сигналы.
    pub signals: Signals,
}

/// Сигналы — общая часть запросов очереди и дела.
const SIGNALS_SQL: &str = "
    count(DISTINCT r.complainant_device) AS reporters,
    count(DISTINCT r.certificate_hash) AS certificates,
    count(*) AS reports,
    count(DISTINCT date_trunc('day', r.created_at)) AS days,
    (SELECT max(n) FROM (SELECT count(*) AS n FROM sealed_sender_reports h
        WHERE h.reported_account = a.account_id GROUP BY h.created_at) AS hours) AS peak_hour,
    count(DISTINCT r.complainant_device) FILTER (WHERE r.complainant_device IN (
        SELECT s.complainant_device FROM sealed_sender_reports s
         GROUP BY s.complainant_device HAVING count(DISTINCT s.reported_account) >= 5)) AS serial_reporters,
    (SELECT count(DISTINCT back.reported_account) FROM sealed_sender_reports back
       JOIN devices own ON own.device_id = back.complainant_device
      WHERE own.account_id = a.account_id
        AND back.reported_account IN (
            SELECT them.account_id FROM sealed_sender_reports theirs
              JOIN devices them ON them.device_id = theirs.complainant_device
             WHERE theirs.reported_account = a.account_id)) AS mutual,
    (SELECT count(*) FROM report_evidence e WHERE e.reported_account = a.account_id) AS evidence,
    count(*) FILTER (WHERE r.reason = 3) AS r3,
    count(*) FILTER (WHERE r.reason = 1) AS r1,
    count(*) FILTER (WHERE r.reason = 4) AS r4,
    count(*) FILTER (WHERE r.reason = 6) AS r6,
    count(*) FILTER (WHERE r.reason = 2) AS r2,
    count(*) FILTER (WHERE r.reason = 5) AS r5,
    count(*) FILTER (WHERE r.reason IS NULL) AS r0,
    to_char(max(r.created_at), 'YYYY-MM-DD HH24:00') AS last_report";

fn signals_of(row: &sqlx::postgres::PgRow) -> Result<Signals, sqlx::Error> {
    let count = |name: &str| {
        row.try_get::<Option<i64>, _>(name)
            .map(Option::unwrap_or_default)
    };
    Ok(Signals {
        reporters: count("reporters")?,
        certificates: count("certificates")?,
        reports: count("reports")?,
        days: count("days")?,
        peak_hour: count("peak_hour")?,
        serial_reporters: count("serial_reporters")?,
        mutual: count("mutual")?,
        evidence: count("evidence")?,
        reasons: [
            count("r3")?,
            count("r1")?,
            count("r4")?,
            count("r6")?,
            count("r2")?,
            count("r5")?,
            count("r0")?,
        ],
    })
}

/// Удаляет улики старше 30 дней (миграция 0030).
///
/// # Errors
///
/// Ошибка базы.
pub async fn purge_old_evidence(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM report_evidence WHERE created_at < now() - interval '30 days'")
        .execute(pool)
        .await?;
    Ok(())
}

/// Очередь дел по аккаунтам.
///
/// # Errors
///
/// Ошибка базы.
pub async fn queue(pool: &PgPool) -> Result<Vec<CaseRow>, sqlx::Error> {
    let sql = format!(
        "SELECT a.account_id, a.username, {SIGNALS_SQL}
           FROM sealed_sender_reports r
           JOIN accounts a ON a.account_id = r.reported_account
          GROUP BY a.account_id, a.username
          ORDER BY max(r.created_at) DESC
          LIMIT 300"
    );
    let rows = sqlx::query(&sql).fetch_all(pool).await?;
    let mut cases = rows
        .iter()
        .map(|row| {
            Ok(CaseRow {
                account_id: row.try_get("account_id")?,
                username: row.try_get("username")?,
                last_report: row
                    .try_get::<Option<String>, _>("last_report")?
                    .unwrap_or_default(),
                signals: signals_of(row)?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    // Срочное — наверх; внутри уровня — свежее выше (порядок запроса).
    cases.sort_by_key(|case| assess(&case.signals, 0).0);
    Ok(cases)
}

/// Дело целиком.
#[derive(Debug, Clone, Default)]
pub struct Case {
    /// Аккаунт.
    pub account_id: Uuid,
    /// Имя.
    pub username: String,
    /// Месяц последней активности.
    pub active_month: String,
    /// Устройств.
    pub devices: i64,
    /// Бот ли это.
    pub bot: bool,
    /// Премиум.
    pub premium: bool,
    /// Каналов у аккаунта.
    pub channels: i64,
    /// Жалоб на его каналы.
    pub channel_reports: i64,
    /// Первая и последняя жалоба.
    pub first_report: String,
    /// Последняя жалоба.
    pub last_report: String,
    /// Сигналы.
    pub signals: Signals,
    /// Жалобы по дням: (день, число).
    pub timeline: Vec<(String, i64)>,
    /// Улики: (час, запечатанное).
    pub sealed: Vec<(String, Vec<u8>)>,
    /// Заморозка либо блокировка, если действует.
    pub restriction: Option<crate::moderation::Restricted>,
}

/// Дело по аккаунту; `None` — жалоб на него нет (или аккаунта нет).
///
/// # Errors
///
/// Ошибка базы.
pub async fn case(pool: &PgPool, account_id: Uuid) -> Result<Option<Case>, sqlx::Error> {
    let sql = format!(
        "SELECT a.account_id, a.username, to_char(a.active_month, 'YYYY-MM') AS active_month,
                a.premium,
                (SELECT count(*) FROM devices d WHERE d.account_id = a.account_id) AS devices,
                EXISTS (SELECT 1 FROM bots b WHERE b.account_id = a.account_id) AS bot,
                (SELECT count(*) FROM channels c WHERE c.owner_account = a.account_id) AS channels,
                (SELECT count(*) FROM channel_reports cr JOIN channels c ON c.channel_id = cr.channel_id
                  WHERE c.owner_account = a.account_id) AS channel_reports,
                to_char(min(r.created_at), 'YYYY-MM-DD HH24:00') AS first_report,
                {SIGNALS_SQL}
           FROM sealed_sender_reports r
           JOIN accounts a ON a.account_id = r.reported_account
          WHERE a.account_id = $1
          GROUP BY a.account_id"
    );
    let Some(row) = sqlx::query(&sql)
        .bind(account_id)
        .fetch_optional(pool)
        .await?
    else {
        return Ok(None);
    };

    let timeline: Vec<(String, i64)> = sqlx::query_as(
        "SELECT to_char(date_trunc('day', created_at), 'MM-DD'), count(*)
           FROM sealed_sender_reports WHERE reported_account = $1
          GROUP BY date_trunc('day', created_at)
          ORDER BY date_trunc('day', created_at) DESC
          LIMIT 30",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;

    let sealed: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT to_char(created_at, 'YYYY-MM-DD HH24:00'), sealed
           FROM report_evidence
          WHERE reported_account = $1 AND created_at >= now() - interval '30 days'
          ORDER BY created_at",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;

    Ok(Some(Case {
        account_id: row.try_get("account_id")?,
        username: row.try_get("username")?,
        active_month: row
            .try_get::<Option<String>, _>("active_month")?
            .unwrap_or_default(),
        devices: row.try_get("devices")?,
        bot: row.try_get("bot")?,
        premium: row.try_get("premium")?,
        channels: row.try_get("channels")?,
        channel_reports: row.try_get("channel_reports")?,
        first_report: row
            .try_get::<Option<String>, _>("first_report")?
            .unwrap_or_default(),
        last_report: row
            .try_get::<Option<String>, _>("last_report")?
            .unwrap_or_default(),
        signals: signals_of(&row)?,
        timeline: timeline.into_iter().rev().collect(),
        sealed,
        restriction: crate::moderation::restriction(pool, account_id).await?,
    }))
}

// ---------------------------------------------------------------------
// HTML

fn level_badge(level: Level) -> String {
    let (class, label) = level.badge();
    format!("<span class=\"badge {class}\">{label}</span>")
}

fn reason_chips(s: &Signals) -> String {
    let mut html = String::new();
    for ((code, label), count) in REASONS.iter().zip(s.reasons.iter()) {
        if *count > 0 {
            let class = if *code == 3 {
                "bg-danger-lt"
            } else {
                "bg-secondary-lt"
            };
            let _ = write!(
                html,
                "<span class=\"badge {class} me-1\">{label} · {count}</span>"
            );
        }
    }
    if html.is_empty() {
        html.push_str("<span class=\"text-secondary small\">No reason given</span>");
    }
    html
}

/// Плитки счётчиков очереди.
fn queue_tiles(cases: &[CaseRow], assessed: &[Level], channel_cases: usize) -> String {
    let mut html = String::new();
    let urgent = assessed
        .iter()
        .filter(|level| **level == Level::Urgent)
        .count();
    let strong = assessed
        .iter()
        .filter(|level| **level == Level::Strong)
        .count();
    let with_evidence = cases
        .iter()
        .filter(|case| case.signals.evidence > 0)
        .count();
    let tile = |glyph: &str, tone: &str, label: &str, value: usize, hint: &str| {
        format!(
            "<div class=\"col-sm-6 col-xl-3\"><div class=\"card card-sm h-100\"><div class=\"card-body\">\
             <div class=\"row align-items-center\"><div class=\"col-auto\"><span class=\"stat-tile tone-{tone}\">{}</span></div>\
             <div class=\"col\"><div class=\"text-secondary fw-medium\">{label}</div><div class=\"stat-value num\">{value}</div>\
             <div class=\"text-secondary small\">{hint}</div></div></div></div></div></div>",
            icon(glyph)
        )
    };
    let _ = write!(
        html,
        "<div class=\"row row-cards mb-4\">{}{}{}{}</div>",
        tile(
            "alert-octagon",
            "bad",
            "Urgent",
            urgent,
            "Child safety — review now"
        ),
        tile(
            "flag",
            "warn",
            "Account cases",
            cases.len(),
            &format!("{strong} with strong signals")
        ),
        tile(
            "lock",
            "info",
            "With evidence",
            with_evidence,
            "Encrypted for this center only"
        ),
        tile(
            "broadcast",
            "info",
            "Channel cases",
            channel_cases,
            "Listed below"
        ),
    );
    html
}

/// Очередь: счётчики и таблица дел.
#[must_use]
pub fn queue_html(cases: &[CaseRow], channel_cases: usize, done: Option<&str>) -> String {
    let mut html = String::new();
    let flash = match done {
        Some("deleted") => Some("Account deleted. Its evidence was deleted with it."),
        Some("dismissed") => Some("Reports dismissed. Their evidence was deleted."),
        Some("channel_deleted") => Some("Channel deleted."),
        Some("frozen") => Some("Account frozen. The case is closed and its evidence deleted."),
        Some("blocked") => Some("Account blocked. The case is closed and its evidence deleted."),
        _ => None,
    };
    if let Some(text) = flash {
        let _ = write!(
            html,
            "<div class=\"alert alert-success\" role=\"status\">{text}</div>"
        );
    }

    let assessed: Vec<Level> = cases
        .iter()
        .map(|case| assess(&case.signals, 0).0)
        .collect();
    html.push_str(&queue_tiles(cases, &assessed, channel_cases));

    html.push_str(
        "<div class=\"card mb-4\"><div class=\"card-header\"><h3 class=\"card-title\">Reported accounts</h3>\
         <div class=\"card-actions text-secondary small\">Urgent first, then by strength of signals</div></div>",
    );
    if cases.is_empty() {
        html.push_str(
            "<div class=\"empty\"><p class=\"empty-title\">No account reports are waiting for review</p>\
             <p class=\"empty-subtitle text-secondary\">New reports appear here with their signals.</p></div></div>",
        );
        return html;
    }
    html.push_str(
        "<div class=\"table-responsive\"><table class=\"table table-vcenter card-table\"><thead><tr>\
         <th>Account</th><th>Assessment</th><th>Reasons</th><th class=\"text-end\">Independent</th>\
         <th class=\"text-end\">Certificates</th><th class=\"text-end\">Evidence</th><th>Latest</th><th class=\"w-1\"></th>\
         </tr></thead><tbody>",
    );
    for (case, level) in cases.iter().zip(assessed) {
        let s = &case.signals;
        let evidence = if s.evidence > 0 {
            format!(
                "<span class=\"badge bg-info-lt\">{} {}</span>",
                icon("lock"),
                s.evidence
            )
        } else {
            "<span class=\"text-secondary\">—</span>".to_owned()
        };
        let _ = write!(
            html,
            "<tr><td><a class=\"row-name\" href=\"/reports/account/{id}\">@{name}</a></td><td>{badge}</td><td>{chips}</td>\
             <td class=\"text-end num\">{independent}<span class=\"text-secondary\"> / {reporters}</span></td>\
             <td class=\"text-end num\">{certificates}</td><td class=\"text-end\">{evidence}</td>\
             <td class=\"text-secondary\">{last}</td>\
             <td><a class=\"btn btn-sm btn-ghost-warning\" href=\"/reports/account/{id}\">Open case {go}</a></td></tr>",
            name = escape(&case.username),
            badge = level_badge(level),
            chips = reason_chips(s),
            independent = s.independent(),
            reporters = s.reporters,
            certificates = s.certificates,
            last = escape(&case.last_report),
            id = case.account_id,
            go = icon("arrow-up-right"),
        );
    }
    html.push_str("</tbody></table></div></div>");
    html
}

fn quote_time(millis: i64) -> String {
    // Только дата и час — как всё время в админ-центре.
    let seconds = millis.div_euclid(1000);
    let day_number = seconds.div_euclid(86_400);
    let hour = seconds.rem_euclid(86_400).div_euclid(3600);
    // Гражданский календарь из дней с 1970-01-01 (алгоритм Хиннанта).
    let shifted = day_number.saturating_add(719_468);
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era = day_of_era
        .saturating_sub(day_of_era.div_euclid(1460))
        .saturating_add(day_of_era.div_euclid(36_524))
        .saturating_sub(day_of_era.div_euclid(146_096))
        .div_euclid(365);
    let day_of_year = day_of_era.saturating_sub(
        year_of_era
            .saturating_mul(365)
            .saturating_add(year_of_era.div_euclid(4))
            .saturating_sub(year_of_era.div_euclid(100)),
    );
    let shifted_month = day_of_year
        .saturating_mul(5)
        .saturating_add(2)
        .div_euclid(153);
    let day = day_of_year
        .saturating_sub(
            shifted_month
                .saturating_mul(153)
                .saturating_add(2)
                .div_euclid(5),
        )
        .saturating_add(1);
    let month = if shifted_month < 10 {
        shifted_month.saturating_add(3)
    } else {
        shifted_month.saturating_sub(9)
    };
    let year = year_of_era
        .saturating_add(era.saturating_mul(400))
        .saturating_add(i64::from(month <= 2));
    format!("{year:04}-{month:02}-{day:02} {hour:02}:00")
}

fn evidence_html(case: &Case, key: Option<&EvidenceKey>, opened: &[Option<Evidence>]) -> String {
    let mut html = String::from(
        "<div class=\"card mb-4\"><div class=\"card-header\"><h3 class=\"card-title\">Evidence</h3>\
         <div class=\"card-actions text-secondary small\">Deleted on decision or after 30 days</div></div><div class=\"card-body\">\
         <p class=\"text-secondary\">Reporters chose to share these. Only the sender proof is verified by the server; \
         texts and screenshots are the reporter's account and can be edited. Trust what independent reporters agree on.</p>",
    );
    if case.sealed.is_empty() {
        html.push_str(
            "<p class=\"m-0\">No evidence was attached to these reports.</p></div></div>",
        );
        return html;
    }
    if key.is_none() {
        html.push_str(
            "<div class=\"alert alert-warning m-0\">The evidence key is not configured, so evidence cannot be opened. \
             Run <code>admin.sh --install</code> again.</div></div></div>",
        );
        return html;
    }
    for (index, ((hour, _), evidence)) in case.sealed.iter().zip(opened).enumerate() {
        let _ = write!(
            html,
            "<div class=\"evidence\"><div class=\"evidence-head\">{} Submission {} <span class=\"text-secondary\">· received {}</span></div>",
            icon("lock-open"),
            index.saturating_add(1),
            escape(hour)
        );
        match evidence {
            None => html.push_str("<p class=\"text-danger m-0\">Could not open this submission: wrong key or damaged data.</p>"),
            Some(evidence) => {
                for quote in &evidence.quotes {
                    let link = if has_link(&quote.text) {
                        format!(" <span class=\"badge bg-warning-lt\">{} link</span>", icon("link"))
                    } else {
                        String::new()
                    };
                    let _ = write!(
                        html,
                        "<blockquote class=\"quote\"><div class=\"text-secondary small\">{}{link}</div>{}</blockquote>",
                        quote_time(quote.sent_at_millis),
                        escape(&quote.text).replace('\n', "<br>"),
                    );
                }
                if !evidence.images.is_empty() {
                    html.push_str("<div class=\"shots\">");
                    for image in &evidence.images {
                        // 🔐 Только JPEG и только как картинка: data: в img
                        // не исполняется, CSP пускает лишь img-src data:.
                        if image.starts_with(&[0xFF, 0xD8, 0xFF]) {
                            let data = base64::engine::general_purpose::STANDARD.encode(image);
                            let _ = write!(
                                html,
                                "<details class=\"shot\"><summary><img src=\"data:image/jpeg;base64,{data}\" alt=\"Screenshot\" loading=\"lazy\"></summary>\
                                 <img class=\"full\" src=\"data:image/jpeg;base64,{data}\" alt=\"Screenshot, full size\"></details>"
                            );
                        }
                    }
                    html.push_str("</div>");
                }
                if evidence.quotes.is_empty() && evidence.images.is_empty() {
                    html.push_str("<p class=\"text-secondary m-0\">Empty submission.</p>");
                }
            }
        }
        html.push_str("</div>");
    }
    html.push_str("</div></div>");
    html
}

fn suggested_reason(s: &Signals) -> Reason {
    match s.top_reason() {
        Some(3) => Reason::Csae,
        Some(4) => Reason::Harassment,
        Some(6) => Reason::Impersonation,
        Some(2) => Reason::Illegal,
        Some(5) => Reason::Other,
        _ => Reason::Spam,
    }
}

/// Страница дела.
#[must_use]
pub fn case_html(case: &Case, key: Option<&EvidenceKey>, csrf: &str) -> String {
    let opened: Vec<Option<Evidence>> = case
        .sealed
        .iter()
        .map(|(_, sealed)| key.and_then(|key| key.open(sealed)))
        .collect();
    let submissions: Vec<Evidence> = opened.iter().flatten().cloned().collect();
    let shared = shared_texts(&submissions);
    let links = submissions
        .iter()
        .flat_map(|evidence| &evidence.quotes)
        .filter(|quote| has_link(&quote.text))
        .count();
    let (level, mut findings) = assess(&case.signals, shared);
    if links > 0 {
        findings.push(Finding {
            supports: true,
            text: format!(
                "{} in the evidence contain links — a common sign of spam and scams.",
                plural(
                    i64::try_from(links).unwrap_or(i64::MAX),
                    "message",
                    "messages"
                )
            ),
        });
    }

    let mut html = head_html(case, level);
    html.push_str(&signals_html(case, &findings));
    html.push_str(&evidence_html(case, key, &opened));
    html.push_str(&decision_html(case, csrf));
    html
}

/// Шапка дела: имя, оценка, факты, плитки счётчиков.
fn head_html(case: &Case, level: Level) -> String {
    let verdict = match level {
        Level::Urgent => "Child safety was reported. Review the evidence now and act under the child safety policy; escalate to the authorities where the law requires.",
        Level::Strong => "Independent signals agree. Acting on this case is supported — confirm with the evidence first.",
        Level::Review => "There are grounds to look closely. Read the evidence and weigh the doubts below before acting.",
        Level::Weak => "Too little to act on. Wait for more independent reports or evidence; a single report is not proof of abuse.",
    };

    let mut facts = format!(
        "Last active {} · {} · ",
        escape(&case.active_month),
        plural(case.devices, "device", "devices")
    );
    if case.bot {
        facts.push_str("bot · ");
    }
    if case.premium {
        facts.push_str("premium · ");
    }
    let _ = write!(
        facts,
        "{} ({} reported)",
        plural(case.channels, "channel", "channels"),
        case.channel_reports
    );

    let s = &case.signals;
    let mut html = format!(
        "<div class=\"mb-3\"><a class=\"btn btn-ghost-secondary btn-sm\" href=\"/reports\">← Report queue</a></div>\
         <div class=\"card mb-4 case-head\"><div class=\"card-body\"><div class=\"d-flex flex-wrap align-items-center gap-3\">\
         <div class=\"flex-fill\"><div class=\"d-flex align-items-center gap-2\"><h3 class=\"m-0\">@{name}</h3>{badge}</div>\
         <div class=\"text-secondary small mt-1\">{facts}</div></div>\
         <div class=\"text-secondary small text-end\">First report {first}<br>Latest {last}</div></div>\
         <p class=\"verdict mt-3 mb-0\">{verdict}</p></div></div>",
        name = escape(&case.username),
        badge = level_badge(level),
        first = escape(&case.first_report),
        last = escape(&case.last_report),
    );

    let tile = |label: &str, value: i64, hint: &str| {
        format!(
            "<div class=\"col-6 col-xl-3\"><div class=\"card card-sm h-100\"><div class=\"card-body\">\
             <div class=\"text-secondary fw-medium\">{label}</div><div class=\"stat-value num\">{value}</div>\
             <div class=\"text-secondary small\">{hint}</div></div></div></div>"
        )
    };
    let _ = write!(
        html,
        "<div class=\"row row-cards mb-4\">{}{}{}{}</div>",
        tile(
            "Independent reporters",
            s.independent(),
            &format!("of {} in total", s.reporters)
        ),
        tile(
            "Distinct certificates",
            s.certificates,
            "Server-signed sender proofs"
        ),
        tile(
            "Days with reports",
            s.days,
            &format!("{} reports in total", s.reports)
        ),
        tile("With evidence", s.evidence, "Encrypted submissions"),
    );
    html
}

fn signals_html(case: &Case, findings: &[Finding]) -> String {
    let s = &case.signals;
    let mut html = String::from("<div class=\"row row-cards mb-4\"><div class=\"col-lg-7\"><div class=\"card h-100\"><div class=\"card-header\"><h3 class=\"card-title\">Signals</h3></div><ul class=\"list-group list-group-flush\">");
    for finding in findings {
        let (glyph, class) = if finding.supports {
            ("alert-triangle", "text-warning")
        } else {
            ("scale", "text-info")
        };
        let _ = write!(
            html,
            "<li class=\"list-group-item d-flex gap-2\"><span class=\"{class}\">{}</span><span>{}</span></li>",
            icon(glyph),
            escape(&finding.text)
        );
    }
    html.push_str("</ul></div></div><div class=\"col-lg-5\"><div class=\"card h-100\"><div class=\"card-header\"><h3 class=\"card-title\">Reasons</h3></div><div class=\"card-body\">");
    let total = s.reasons.iter().sum::<i64>().max(1);
    for ((code, label), count) in REASONS.iter().zip(s.reasons.iter()).chain(std::iter::once((
        &(0, "No reason given"),
        s.reasons.last().unwrap_or(&0),
    ))) {
        if *count == 0 {
            continue;
        }
        let width = count
            .saturating_mul(100)
            .checked_div(total)
            .unwrap_or(0)
            .clamp(2, 100);
        let tone = if *code == 3 { "bar-bad" } else { "bar-ink" };
        let _ = write!(
            html,
            "<div class=\"reason-row\"><div class=\"d-flex justify-content-between small\"><span>{label}</span><span class=\"num\">{count}</span></div>\
             <div class=\"reason-bar\"><span class=\"{tone}\" style=\"width:{width}%\"></span></div></div>"
        );
    }
    html.push_str("<div class=\"timeline mt-3\" aria-label=\"Reports per day\">");
    let peak = case
        .timeline
        .iter()
        .map(|(_, n)| *n)
        .max()
        .unwrap_or(1)
        .max(1);
    for (day, count) in &case.timeline {
        let height = count
            .saturating_mul(100)
            .checked_div(peak)
            .unwrap_or(0)
            .clamp(6, 100);
        let _ = write!(
            html,
            "<span title=\"{day}: {count}\" style=\"height:{height}%\"></span>",
            day = escape(day)
        );
    }
    html.push_str("</div><div class=\"text-secondary small mt-1\">Reports per day</div></div></div></div></div>");
    html
}

fn decision_html(case: &Case, csrf: &str) -> String {
    crate::moderation::decision_html(&crate::moderation::Decision {
        account_id: case.account_id,
        username: &case.username,
        restricted: case.restriction.as_ref(),
        suggested: suggested_reason(&case.signals),
        csrf,
        dismiss: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals() -> Signals {
        Signals {
            reporters: 3,
            certificates: 3,
            reports: 3,
            days: 2,
            peak_hour: 1,
            ..Signals::default()
        }
    }

    #[test]
    fn independent_reports_over_days_are_strong() {
        assert_eq!(assess(&signals(), 0).0, Level::Strong);
    }

    #[test]
    fn child_safety_is_urgent() {
        let mut s = signals();
        s.reasons[0] = 1;
        assert_eq!(assess(&s, 0).0, Level::Urgent);
    }

    #[test]
    fn single_report_is_weak_and_doubts_lower_the_level() {
        let single = Signals {
            reporters: 1,
            certificates: 1,
            reports: 1,
            days: 1,
            peak_hour: 1,
            ..Signals::default()
        };
        assert_eq!(assess(&single, 0).0, Level::Weak);

        let mut burst = signals();
        burst.days = 2;
        burst.peak_hour = 3;
        assert_eq!(
            assess(&burst, 0).0,
            Level::Review,
            "все жалобы за час — накрутка?"
        );

        let mut dispute = signals();
        dispute.mutual = 1;
        assert_eq!(assess(&dispute, 0).0, Level::Review);

        // Один сертификат на троих — один человек.
        let mut puppets = signals();
        puppets.certificates = 1;
        assert_eq!(puppets.independent(), 1);
        assert_eq!(assess(&puppets, 0).0, Level::Weak);
    }

    #[test]
    fn the_same_text_from_two_reporters_is_bulk_messaging() {
        let quote = |text: &str| Quote {
            sent_at_millis: 0,
            text: text.to_owned(),
        };
        let first = Evidence {
            quotes: vec![quote("You won 500 EUR! Claim at bit.ly/x")],
            images: vec![],
        };
        let second = Evidence {
            quotes: vec![quote("you won 900 eur!  claim at bit.ly/x")],
            images: vec![],
        };
        assert_eq!(shared_texts(&[first.clone(), second]), 1);
        assert_eq!(shared_texts(&[first.clone(), first]), 1);
        assert_eq!(shared_texts(&[]), 0);
        assert!(has_link("see https://example.com"));
    }

    #[test]
    fn quote_time_is_civil_utc() {
        assert_eq!(quote_time(0), "1970-01-01 00:00");
        assert_eq!(quote_time(1_700_000_000_000), "2023-11-14 22:00");
    }

    /// Запечатывает так же, как телефон: X25519 + HKDF + AES-GCM.
    fn seal_like_phone(key: &EvidenceKey, plain: &[u8]) -> Vec<u8> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let ephemeral =
            agreement::PrivateKey::generate(&agreement::X25519).unwrap_or_else(|_| unreachable!());
        let ephemeral_public = ephemeral
            .compute_public_key()
            .unwrap_or_else(|_| unreachable!());
        let mut salt = ephemeral_public.as_ref().to_vec();
        salt.extend_from_slice(key.public());
        let mut aes = [0u8; 32];
        agreement::agree(
            &ephemeral,
            agreement::UnparsedPublicKey::new(&agreement::X25519, key.public()),
            (),
            |shared| {
                hkdf::Salt::new(hkdf::HKDF_SHA256, &salt)
                    .extract(shared)
                    .expand(&[INFO], hkdf::HKDF_SHA256)
                    .and_then(|okm| okm.fill(&mut aes))
                    .map_err(|_| ())
            },
        )
        .unwrap_or_else(|()| unreachable!());
        let mut plain = plain.to_vec();
        let mut nonce = [0u8; 12];
        aws_lc_rs::rand::SecureRandom::fill(&rng, &mut nonce).unwrap_or_else(|_| unreachable!());
        let cipher = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &aes).unwrap_or_else(|_| unreachable!()),
        );
        cipher
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(MAGIC),
                &mut plain,
            )
            .unwrap_or_else(|_| unreachable!());
        let mut sealed = MAGIC.to_vec();
        sealed.extend_from_slice(ephemeral_public.as_ref());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&plain);

        sealed
    }

    fn plain_quotes(quotes: &[(i64, &str)]) -> Vec<u8> {
        let mut plain = vec![1u8, u8::try_from(quotes.len()).unwrap_or(0)];
        for (time, text) in quotes {
            plain.extend_from_slice(&time.to_be_bytes());
            plain.extend_from_slice(&u32::try_from(text.len()).unwrap_or(0).to_be_bytes());
            plain.extend_from_slice(text.as_bytes());
        }
        plain.push(0);
        plain
    }

    #[test]
    fn evidence_key_opens_what_the_phone_sealed() {
        let key = EvidenceKey::from_hex(&"07".repeat(32)).unwrap_or_else(|| unreachable!());
        let mut sealed = seal_like_phone(&key, &plain_quotes(&[(5, "hi")]));

        let opened = key.open(&sealed).unwrap_or_else(|| unreachable!());
        assert_eq!(
            opened.quotes,
            vec![Quote {
                sent_at_millis: 5,
                text: "hi".to_owned()
            }]
        );

        let last = sealed.len().saturating_sub(1);
        if let Some(byte) = sealed.get_mut(last) {
            *byte ^= 1;
        }
        assert!(key.open(&sealed).is_none(), "подделка не открывается");
    }

    #[test]
    fn case_page_escapes_and_has_no_reporter_identity() {
        let case = Case {
            username: "<b>x</b>".to_owned(),
            signals: signals(),
            ..Case::default()
        };
        let html = case_html(&case, None, "tok");
        assert!(html.contains("@&lt;b&gt;x&lt;/b&gt;"));
        assert!(html.contains("Reporter identities are never shown"));
        assert!(html.contains("name=\"confirm\" value=\"yes\" required"));
        assert!(html
            .chars()
            .all(|ch| !('\u{0400}'..='\u{04ff}').contains(&ch)));
    }

    /// Превью очереди и дела для глаз (`ADMIN_PREVIEW_DIR`).
    #[test]
    fn preview_case_pages() {
        let Ok(dir) = std::env::var("ADMIN_PREVIEW_DIR") else { return };
        let key = EvidenceKey::from_hex(&"07".repeat(32)).unwrap_or_else(|| unreachable!());
        let spam = "You won a 500 EUR voucher! Claim it today at https://bit.ly/gift-claim";
        let first = seal_like_phone(&key, &plain_quotes(&[(1_762_900_000_000, spam), (1_762_900_060_000, "Hurry, the offer ends tonight")]));
        let second = seal_like_phone(&key, &plain_quotes(&[(1_762_990_000_000, "You won a 900 EUR voucher! Claim it today at https://bit.ly/gift-claim")]));
        let mut signals = Signals { reporters: 4, certificates: 3, reports: 4, days: 3, peak_hour: 2, serial_reporters: 0, mutual: 0, evidence: 2, ..Signals::default() };
        signals.reasons = [0, 3, 0, 0, 0, 0, 1];
        let case = Case {
            account_id: Uuid::nil(),
            username: "promo_gifts".into(),
            active_month: "2026-11".into(),
            devices: 1,
            first_report: "2026-11-10 09:00".into(),
            last_report: "2026-11-12 21:00".into(),
            signals: signals.clone(),
            timeline: vec![("11-10".into(), 1), ("11-11".into(), 2), ("11-12".into(), 1)],
            sealed: vec![("2026-11-10 09:00".into(), first), ("2026-11-12 21:00".into(), second)],
            ..Case::default()
        };
        let mut urgent = Signals { reporters: 1, certificates: 1, reports: 1, days: 1, peak_hour: 1, ..Signals::default() };
        urgent.reasons[0] = 1;
        let weak = Signals { reporters: 1, certificates: 1, reports: 1, days: 1, peak_hour: 1, reasons: [0, 0, 1, 0, 0, 0, 0], ..Signals::default() };
        let rows = vec![
            CaseRow { account_id: Uuid::nil(), username: "promo_gifts".into(), last_report: "2026-11-12 21:00".into(), signals },
            CaseRow { account_id: Uuid::nil(), username: "night_owl".into(), last_report: "2026-11-12 23:00".into(), signals: urgent },
            CaseRow { account_id: Uuid::nil(), username: "marco_r".into(), last_report: "2026-11-11 14:00".into(), signals: weak },
        ];
        let mut rows = rows;
        rows.sort_by_key(|case| assess(&case.signals, 0).0);
        let _ = std::fs::write(format!("{dir}/reports.html"), crate::layout("Reports", "c", &queue_html(&rows, 1, None)));
        let _ = std::fs::write(format!("{dir}/case.html"), crate::layout("Reports", "c", &case_html(&case, Some(&key), "c")));
    }
}
