// SPDX-License-Identifier: Apache-2.0

//! Ключевой материал протокола: identity-ключи и prekey bundle.
//!
//! Здесь определены типы, но не операции над ними — реализация PQXDH
//! появится в M2. Разделение сделано намеренно: контракт должен быть
//! зафиксирован до того, как под него пишется криптография.

use core::fmt;

use aegis_types::{DeviceId, PublicKeyBytes, Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Публичный identity-ключ устройства (X25519).
///
/// Долгоживущий. Меняется только при переустановке приложения или
/// восстановлении из backup — и то и другое видно собеседнику как
/// смена safety number.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct IdentityKey(PublicKeyBytes);

impl IdentityKey {
    /// Оборачивает публичный ключ как identity-ключ.
    #[must_use]
    pub const fn new(key: PublicKeyBytes) -> Self {
        Self(key)
    }

    /// Возвращает публичный ключ.
    #[must_use]
    pub const fn public(&self) -> &PublicKeyBytes {
        &self.0
    }
}

/// Пара identity-ключей устройства.
///
/// Приватная часть никогда не покидает устройство и не попадает в backup
/// (раздел 12.5 плана): восстановление создаёт новую identity, а не
/// воскрешает старую.
#[derive(ZeroizeOnDrop)]
pub struct IdentityKeyPair {
    #[zeroize(skip)]
    public: IdentityKey,
    private: Secret<[u8; 32]>,
}

impl IdentityKeyPair {
    /// Собирает пару из публичной и приватной частей.
    #[must_use]
    pub const fn new(public: IdentityKey, private: Secret<[u8; 32]>) -> Self {
        Self { public, private }
    }

    /// Публичная часть.
    #[must_use]
    pub const fn public(&self) -> &IdentityKey {
        &self.public
    }

    /// Приватная часть.
    #[must_use]
    pub const fn private(&self) -> &Secret<[u8; 32]> {
        &self.private
    }
}

impl fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Публичную часть показать можно, приватную — ни при каких условиях.
        f.debug_struct("IdentityKeyPair")
            .field("public", &self.public)
            .field("private", &"<redacted>")
            .finish()
    }
}

/// Идентификатор одноразового или подписанного предключа.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PreKeyId(u32);

impl PreKeyId {
    /// Оборачивает числовой идентификатор.
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Числовое представление.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Подписанный предключ: публичная часть плюс подпись identity-ключом.
///
/// Подпись — единственное, что связывает предключ с владельцем. Сервер
/// раздаёт предключи и в принципе может подменить их, поэтому проверка
/// подписи при разборе bundle обязательна и не имеет «мягкого» режима
/// (раздел 6.2 плана).
#[derive(Clone, Debug)]
pub struct SignedPreKey {
    /// Идентификатор предключа.
    pub id: PreKeyId,
    /// Публичная часть.
    pub public: PublicKeyBytes,
    /// Подпись XEdDSA, сделанная identity-ключом владельца.
    pub signature: Vec<u8>,
}

/// Публичная часть пост-квантового предключа (ML-KEM).
///
/// Отдельный тип от [`PublicKeyBytes`], потому что ключи ML-KEM заметно
/// больше 32 байт и путать их с X25519 нельзя.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KemPublicKey(Vec<u8>);

impl KemPublicKey {
    /// Оборачивает байты публичного ключа KEM.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Возвращает байты ключа.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Подписанный пост-квантовый предключ.
#[derive(Clone, Debug)]
pub struct SignedKemPreKey {
    /// Идентификатор предключа.
    pub id: PreKeyId,
    /// Публичная часть ML-KEM.
    pub public: KemPublicKey,
    /// Подпись XEdDSA, сделанная identity-ключом владельца.
    pub signature: Vec<u8>,
}

/// Набор публичных ключей одного устройства, полученный с сервера.
///
/// # Что здесь может подменить сервер
///
/// Всё. Именно поэтому:
///
/// * `signed_pre_key` и `signed_kem_pre_key` подписаны `identity_key`;
/// * сам `identity_key` проверяется пользователем через safety number;
/// * пост-квантовая составляющая обязательна — поля `signed_kem_pre_key`
///   нет в варианте `Option`, потому что сессия без неё не устанавливается
///   (ADR-021).
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    /// Устройство, которому принадлежит набор.
    pub device_id: DeviceId,
    /// Публичный identity-ключ устройства.
    pub identity_key: IdentityKey,
    /// 🔐 Пост-квантовая половина identity — открытый ключ ML-DSA-65
    /// (см. `pq_identity`). Подписи предключей гибридные: проверяются
    /// и ею, и классической.
    pub pq_identity: Vec<u8>,
    /// Привязка половин identity друг к другу (`pq_identity::bind`).
    pub identity_binding: Vec<u8>,
    /// Подписанный предключ, ротация раз в 7 дней.
    pub signed_pre_key: SignedPreKey,
    /// Одноразовый предключ. Может отсутствовать, если пул исчерпан.
    ///
    /// Отсутствие допустимо, но должно фиксироваться в журнале
    /// безопасности: это ослабление forward secrecy для первого сообщения.
    pub one_time_pre_key: Option<(PreKeyId, PublicKeyBytes)>,
    /// Подписанный пост-квантовый предключ. Обязателен.
    pub signed_kem_pre_key: SignedKemPreKey,
    /// Одноразовый пост-квантовый предключ. Может отсутствовать.
    /// Одноразовый пост-квантовый предключ — **вместе с подписью**.
    ///
    /// 🔐 Подпись здесь обязательна, в отличие от классического
    /// одноразового предключа. Подмена классического ничего
    /// не даёт: его вклад входит в общий секрет наряду с тремя
    /// диффи-хеллманами по долговременным ключам. Подмена
    /// пост-квантового даёт атакующему всю пост-квантовую половину
    /// общего секрета — то есть снимает защиту, ради которой
    /// гибридная схема и существует (раздел 6.2).
    ///
    /// ⚠️ Прежде здесь лежала пара без подписи. Сервер её присылал,
    /// сетевой слой разбирал, а `parse_bundle` отбрасывал третьим
    /// элементом кортежа — `|(id, key, _)|`. Проверять было нечего.
    pub one_time_kem_pre_key: Option<SignedKemPreKey>,
}

impl PreKeyBundle {
    /// Была ли forward secrecy первого сообщения ослаблена из-за
    /// исчерпания пула одноразовых предключей.
    ///
    /// Результат показывается в Security Center, а не игнорируется:
    /// систематическое исчерпание пула может означать, что кто-то
    /// намеренно вычерпывает предключи собеседника.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        self.one_time_pre_key.is_none() || self.one_time_kem_pre_key.is_none()
    }
}

/// Состояние сессии Double Ratchet ⊕ SPQR.
///
/// Для внешнего кода — непрозрачный блоб. Внутренняя структура появится
/// в M2 и останется приватной: ни UI, ни хранилище не должны уметь
/// разбирать состояние ratchet, они только сохраняют и загружают его.
#[derive(ZeroizeOnDrop)]
pub struct SessionState {
    serialized: Secret<Vec<u8>>,
}

impl SessionState {
    /// Восстанавливает состояние из сохранённого представления.
    #[must_use]
    pub const fn from_serialized(serialized: Secret<Vec<u8>>) -> Self {
        Self { serialized }
    }

    /// Возвращает сериализованное представление для записи в хранилище.
    ///
    /// Хранилище обязано записать это только в зашифрованном виде
    /// (раздел 11 плана): состояние ratchet — материал уровня A3.
    #[must_use]
    pub const fn serialized(&self) -> &Secret<Vec<u8>> {
        &self.serialized
    }
}

impl fmt::Debug for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionState<redacted>")
    }
}

impl Zeroize for KemPublicKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::PublicKeyBytes;

    fn sample_bundle(otp: bool, kem_otp: bool) -> PreKeyBundle {
        PreKeyBundle {
            device_id: DeviceId::generate(),
            identity_key: IdentityKey::new(PublicKeyBytes::new([1; 32])),
            pq_identity: vec![6; 1952],
            identity_binding: Vec::new(),
            signed_pre_key: SignedPreKey {
                id: PreKeyId::new(1),
                public: PublicKeyBytes::new([2; 32]),
                signature: vec![0; 64],
            },
            one_time_pre_key: otp.then(|| (PreKeyId::new(2), PublicKeyBytes::new([3; 32]))),
            signed_kem_pre_key: SignedKemPreKey {
                id: PreKeyId::new(3),
                public: KemPublicKey::new(vec![4; 1568]),
                signature: vec![0; 64],
            },
            one_time_kem_pre_key: kem_otp.then(|| SignedKemPreKey {
                id: PreKeyId::new(4),
                public: KemPublicKey::new(vec![5; 1568]),
                signature: vec![0; 64],
            }),
        }
    }

    #[test]
    fn full_bundle_is_not_degraded() {
        assert!(!sample_bundle(true, true).is_degraded());
    }

    /// Исчерпание любого из двух пулов одноразовых предключей ослабляет
    /// forward secrecy первого сообщения и должно быть заметно.
    #[test]
    fn missing_one_time_key_marks_bundle_degraded() {
        assert!(sample_bundle(false, true).is_degraded());
        assert!(sample_bundle(true, false).is_degraded());
        assert!(sample_bundle(false, false).is_degraded());
    }

    #[test]
    fn identity_key_pair_debug_hides_private_part() {
        let pair = IdentityKeyPair::new(
            IdentityKey::new(PublicKeyBytes::new([0xAB; 32])),
            Secret::new([0xCD; 32]),
        );
        let rendered = format!("{pair:?}");

        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("cd"));
        assert!(!rendered.contains("205")); // 0xCD в десятичном виде
    }

    #[test]
    fn session_state_debug_is_opaque() {
        let state = SessionState::from_serialized(Secret::new(b"root key material".to_vec()));
        assert_eq!(format!("{state:?}"), "SessionState<redacted>");
    }
}
