// SPDX-License-Identifier: Apache-2.0

//! Криптографический протокол AEGIS: PQXDH, Triple Ratchet, safety numbers.
//!
//! # Статус
//!
//! Реализованы PQXDH, Double Ratchet, XEdDSA, sealed sender, Sender Keys,
//! формат содержимого, предключи, safety number и проверка версии
//! протокола. Постквантовый храповик SPQR написан и протестирован,
//! но в сессии **не подключён** (см. спецификацию, §6).
//!
//! ⚠️ Прежде здесь стоял статус этапа M1: «криптографические операции
//! появятся в M2».
//!
//! # Свойства крейта
//!
//! Крейт намеренно ничего не знает о сети, хранилище и платформе. Он не
//! обращается к диску, не берёт системное время и не создаёт источник
//! случайности — всё это передаётся снаружи. Благодаря этому:
//!
//! * поведение полностью воспроизводимо в тестах;
//! * аудитору достаточно прочитать один крейт;
//! * объём аудита ограничен, что напрямую влияет на его стоимость (ADR-026).
//!
//! # Целевой объём
//!
//! Не более 3500 строк. Это бюджетное ограничение, а не стилистическое:
//! стоимость внешнего аудита пропорциональна объёму криптографического кода.
//
pub mod account_recovery;
pub mod aead;
pub mod contact_link;
pub mod content;
pub mod double_ratchet;
pub mod engine;
pub mod envelope;
pub mod group;
pub mod keys;
pub mod mlkem;
pub mod padding;
pub mod pq_identity;
pub mod pqxdh;
pub mod prekeys;
pub mod protocol_engine;
pub mod qr;
pub mod sealed_sender;
pub mod sender_key;
pub mod spqr;
pub mod x25519;
pub mod xeddsa;

mod fingerprint;
mod version;

// Все движки переписаны с нуля и подключены к сборке: `pqxdh.rs` (подписи
// предключей проверяются ключом владельца bundle), `double_ratchet.rs`
// (цепочка на HMAC с разными константами, заголовок аутентифицируется как
// AAD), `spqr.rs` (гибридное комбинирование `HKDF(MK_classic ‖ MK_pq)`
// по ADR-021) и `protocol_engine.rs` — единственная реализация
// `ProtocolEngine`, собирающая три храповика в один движок.
//
// Черновики прежних редакций остаются в `draft/` для сверки; все пять
// дефектов раздела 23.0.1 закрыты.

pub use double_ratchet::RatchetState;
pub use engine::{Clock, InitialMessage, InitiatedSession, ProtocolEngine};
pub use fingerprint::{Fingerprint, SafetyNumber, SAFETY_NUMBER_DIGITS};
pub use keys::{
    IdentityKey, IdentityKeyPair, KemPublicKey, PreKeyBundle, PreKeyId, SessionState,
    SignedKemPreKey, SignedPreKey,
};
pub use mlkem::{MlKem1024PrivateKey, MlKem1024PublicKey, MlKem768PrivateKey, MlKem768PublicKey};
pub use pqxdh::{InitiatorOutput, KemPreKeyChoice, ResponderKeys, SharedSecret, SHARED_SECRET_LEN};
pub use protocol_engine::AegisEngine;
pub use spqr::{Chunk, ChunkAssembler, EpochId, PqRatchet, CHUNK_SIZE, MAX_CHUNKS};
pub use version::ProtocolVersion;
pub use xeddsa::{XEdDSAPrivateKey, XEdDSAPublicKey};

/// Версия крейта, доступная во время выполнения.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Максимальное число пропущенных message key, которое клиент готов вычислить
/// в пределах одной цепочки.
///
/// # Зачем нужен лимит
///
/// Double Ratchet допускает доставку не по порядку: получив сообщение
/// с номером N, клиент должен вычислить и сохранить ключи для всех
/// пропущенных сообщений до N. Без верхней границы сообщение со счётчиком
/// `u32::MAX` заставило бы клиент выполнить четыре миллиарда операций HMAC
/// и попытаться сохранить столько же ключей — отказ в обслуживанием одним
/// пакетом (раздел 6.3 плана).
pub const MAX_SKIPPED_MESSAGE_KEYS: u32 = 1_000;

/// Максимальное число цепочек, для которых хранятся пропущенные ключи.
pub const MAX_SKIPPED_CHAINS: u32 = 5;

/// Срок жизни сохранённого пропущенного message key.
///
/// По истечении ключ уничтожается, даже если сообщение так и не пришло:
/// хранить ключевой материал бесконечно означает бесконечно расширять
/// окно компрометации.
pub const SKIPPED_KEY_TTL_DAYS: u32 = 30;

/// Период ротации подписанного предключа.
pub const SIGNED_PRE_KEY_ROTATION_DAYS: u32 = 7;

/// Размер пула одноразовых предключей, публикуемых на сервере.
pub const ONE_TIME_PRE_KEY_POOL_SIZE: u32 = 100;

/// Порог пополнения пула одноразовых предключей.
pub const ONE_TIME_PRE_KEY_REFILL_THRESHOLD: u32 = 20;

#[cfg(test)]
mod tests {
    use super::*;

    /// Лимиты проверяются на этапе компиляции, а не в тестах: это
    /// инварианты значений, а не поведения. Ошибка в них должна
    /// останавливать сборку, а не ждать запуска тестов.
    ///
    /// Порог пополнения меньше размера пула — иначе пул пополнялся бы
    /// непрерывно.
    const _: () = assert!(ONE_TIME_PRE_KEY_REFILL_THRESHOLD < ONE_TIME_PRE_KEY_POOL_SIZE);

    /// Лимит пропущенных ключей существует, чтобы ограничить работу,
    /// а не чтобы формально присутствовать. Верхняя оценка объёма работы
    /// на одно входящее сообщение должна оставаться обозримой.
    const _: () = assert!(MAX_SKIPPED_MESSAGE_KEYS <= 10_000);
    const _: () = assert!(
        (MAX_SKIPPED_MESSAGE_KEYS as u64) * (MAX_SKIPPED_CHAINS as u64) <= 100_000,
        "worst case на одно сообщение слишком велик"
    );

    /// TTL пропущенных ключей ограничивает окно компрометации.
    const _: () = assert!(SKIPPED_KEY_TTL_DAYS <= 30);

    #[test]
    fn crate_version_is_semver() {
        let parts: Vec<&str> = VERSION.split('.').collect();

        assert_eq!(parts.len(), 3, "ожидался формат MAJOR.MINOR.PATCH");
        for part in parts {
            assert!(part.parse::<u32>().is_ok(), "не число: {part}");
        }
    }
}
