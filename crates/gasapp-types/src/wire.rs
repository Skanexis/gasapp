// SPDX-License-Identifier: Apache-2.0

//! Типы, разделяющие открытые и зашифрованные данные на уровне системы типов.
//!
//! Раздел 8.2 плана вводит архитектурный инвариант: сетевой слой принимает
//! только [`Ciphertext`] и [`PublicKeyBytes`]. [`Plaintext`] не реализует
//! ни `Serialize`, ни `Debug` с содержимым, поэтому попытка отправить
//! открытый текст в сеть не компилируется — а не «отлавливается на ревью».

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Открытые данные: содержимое сообщения до шифрования или после расшифровки.
///
/// Живёт только в RAM и только внутри `gasapp-core`/`gasapp-protocol`.
/// Сознательно не сериализуется: см. модульную документацию.
#[derive(ZeroizeOnDrop)]
pub struct Plaintext(Vec<u8>);

impl Plaintext {
    /// Оборачивает байты как открытый текст.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Возвращает содержимое.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Длина в байтах.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Пуст ли буфер.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Длина раскрывается намеренно: она и так видна атакующему по размеру
        // пакета, а при отладке ошибок паддинга (раздел 15.3) она необходима.
        write!(f, "Plaintext<redacted, {} bytes>", self.0.len())
    }
}

/// Зашифрованные данные. Единственный тип полезной нагрузки, который
/// разрешено передавать в сеть и записывать на диск.
#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    /// Оборачивает байты как шифротекст.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Возвращает байты шифротекста.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Разбирает обёртку, отдавая внутренний буфер.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Длина в байтах.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Пуст ли буфер.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ciphertext<{} bytes>", self.0.len())
    }
}

/// Публичный ключ в байтовом представлении.
///
/// Публичные ключи не секретны, но заведены отдельным типом, чтобы их
/// нельзя было перепутать с приватными на границах модулей.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKeyBytes([u8; 32]);

impl PublicKeyBytes {
    /// Оборачивает 32 байта публичного ключа.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Возвращает байты ключа.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Публичный ключ не секрет — печатаем первые 4 байта для отладки.
        // Деструктуризация вместо индексации: индексация запрещена
        // clippy-правилом indexing_slicing (раздел 4.2).
        let [b0, b1, b2, b3, ..] = self.0;
        write!(f, "PublicKey({b0:02x}{b1:02x}{b2:02x}{b3:02x}…)")
    }
}

/// Приватный ключ. Всегда обнуляется, никогда не сериализуется.
#[derive(ZeroizeOnDrop)]
pub struct PrivateKeyBytes([u8; 32]);

impl PrivateKeyBytes {
    /// Оборачивает 32 байта приватного ключа.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Возвращает байты ключа.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PrivateKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey<redacted>")
    }
}

impl Zeroize for PrivateKeyBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_debug_hides_content_but_shows_length() {
        let pt = Plaintext::new(b"attack at dawn".to_vec());
        let rendered = format!("{pt:?}");

        assert!(!rendered.contains("attack"));
        assert!(rendered.contains("14 bytes"));
    }

    #[test]
    fn private_key_debug_is_fully_redacted() {
        let key = PrivateKeyBytes::new([0xCD; 32]);
        let rendered = format!("{key:?}");

        assert_eq!(rendered, "PrivateKey<redacted>");
        assert!(!rendered.contains("cd"));
    }

    #[test]
    fn public_key_debug_shows_prefix_only() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xde;
        bytes[1] = 0xad;
        bytes[2] = 0xbe;
        bytes[3] = 0xef;

        assert_eq!(
            format!("{:?}", PublicKeyBytes::new(bytes)),
            "PublicKey(deadbeef…)"
        );
    }

    #[test]
    fn ciphertext_roundtrips_through_bytes() {
        let ct = Ciphertext::new(vec![1, 2, 3, 4]);
        assert_eq!(ct.as_bytes(), &[1, 2, 3, 4]);
        assert_eq!(ct.clone().into_bytes(), vec![1, 2, 3, 4]);
    }
}
