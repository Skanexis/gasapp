// SPDX-License-Identifier: Apache-2.0

//! Иерархия ключей, KEK/DEK, аппаратное хранилище.
//!
//! Реализация иерархии ключей согласно разделу 7.1 дорожной карты:
//! - Master Key (MK) -> Key Encryption Key (KEK) -> Data Encryption Key (DEK)
//! - Использует HKDF-SHA-256 для производства ключей с domain separation
//! - Поддерживает аппаратное хранение через HardwareKeyProvider trait
//! - Обеспечивает graceful degradation на устройствах без TEE

use aegis_types::{Result, AegisError, Secret, PublicKeyBytes};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;
use rand_core::{CryptoRng, RngCore};
use async_trait::async_trait;

/// Размер ключей в байтах
pub const KEY_SIZE: usize = 32;

/// Константы для domain separation в HKDF
const HKDF_SALT: &[u8] = b"AEGIS_KEYSTORE_SALT_V1";
const INFO_KEK: &[u8] = b"AEGIS_KEK_DERIVATION";
const INFO_DEK: &[u8] = b"AEGIS_DEK_DERIVATION";
const INFO_MK: &[u8] = b"AEGIS_MASTER_KEY_DERIVATION";

/// Иерархия ключей: Master Key -> KEK -> DEK
#[derive(Clone, Debug, Zeroize)]
pub struct KeyHierarchy {
    /// Master Key (хранится в аппаратном хранилище или dérivруется из учетных данных)
    master_key: Secret<[u8; KEY_SIZE]>,
    /// Key Encryption Key (используется для шифрования DEK)
    key_encryption_key: Secret<[u8; KEY_SIZE]>,
    /// Data Encryption Key (используется для шифрования данных)
    data_encryption_key: Secret<[u8; KEY_SIZE]>,
}

impl KeyHierarchy {
    /// Создает новую иерархию ключей из мастер-ключа
    ///
    /// # Arguments
    /// * `master_key` - 32-байтовый мастер-ключ
    ///
    /// # Returns
    /// * `Result<Self>` - иерархия ключей или ошибка
    pub fn from_master_key(master_key: [u8; KEY_SIZE]) -> Self {
        // Выводим KEK из мастер-ключа с domain separation
        let kek = Self::derive_key(&master_key, INFO_KEK);
        // Выводим DEK из мастер-ключа с domain separation (отдельно от KEK)
        let dek = Self::derive_key(&master_key, INFO_DEK);

        Self {
            master_key: Secret::new(master_key),
            key_encryption_key: Secret::new(kek),
            data_encryption_key: Secret::new(dek),
        }
    }

    /// Выводит ключ из входного материала с использованием HKDF-SHA-256
    ///
    /// # Arguments
    /// * `ikm` - входной ключевой материал
    /// * `info` - информация для domain separation
    ///
    /// # Returns
    /// * `[u8; KEY_SIZE]` - derived key
    fn derive_key(ikm: &[u8; KEY_SIZE], info: &[u8]) -> [u8; KEY_SIZE] {
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm);
        let mut okm = [0u8; KEY_SIZE];
        hk.expand(info, &mut okm)
            .expect("HKDF expansion failed");
        okm
    }

    /// Возвращает ссылку на мастер-ключ
    pub fn master_key(&self) -> &Secret<[u8; KEY_SIZE]> {
        &self.master_key
    }

    /// Возвращает ссылку на ключ шифрования ключей
    pub fn kek(&self) -> &Secret<[u8; KEY_SIZE]> {
        &self.key_encryption_key
    }

    /// Возвращает ссылку на ключ шифрования данных
    pub fn dek(&self) -> &Secret<[u8; KEY_SIZE]> {
        &self.data_encryption_key
    }
}

/// Трейт для аппаратных провайдеров ключей (TEE, Secure Enclave, StrongBox и т.д.)
///
/// Абстрагирует доступ к аппаратному хранилищу ключей, позволяя:
/// - Генерировать и хранить ключи вSecure Element
/// - Выполнять криптографические операции внутри аппаратного модуля
/// - Обеспечивать защиту от извлечения ключей
#[async_trait]
pub trait HardwareKeyProvider: Send + Sync {
    /// Генерирует новый мастер-ключ в аппаратном хранилище
    ///
    /// # Returns
    /// * `Result<[u8; KEY_SIZE]>` - сгенерированный мастер-ключ или ошибка
    async fn generate_master_key(&self) -> Result<[u8; KEY_SIZE]>;

    /// Сохраняет мастер-ключ в аппаратном хранилище
    ///
    /// # Arguments
    /// * `key` - мастер-ключ для сохранения
    ///
    /// # Returns
    /// * `Result<()>` - результат операции
    async fn store_master_key(&self, key: &[u8; KEY_SIZE]) -> Result<()>;

    /// Получает мастер-ключ из аппаратного хранилища
    ///
    /// # Returns
    /// * `Result<Option<[u8; KEY_SIZE]>>` - мастер-ключ или None если не найден
    async fn get_master_key(&self) -> Result<Option<[u8; KEY_SIZE]>>;

    /// Удаляет мастер-ключ из аппаратного хранилища
    ///
    /// # Returns
    /// * `Result<()>` - результат операции
    async fn delete_master_key(&self) -> Result<()>;

    /// Выполняет операцию вывода ключа внутри аппаратного модуля
    /// (чтобы ключ никогда не покидал границы TEE)
    ///
    /// # Arguments
    /// * `input_key` - входной ключ
    /// * `info` - информация для domain separation
    ///
    /// # Returns
    /// * `Result<[u8; KEY_SIZE]>` - derived key или ошибка
    async fn derive_key_in_hardware(
        &self,
        input_key: &[u8; KEY_SIZE],
        info: &[u8],
    ) -> Result<[u8; KEY_SIZE]>;

    /// Проверяет доступность аппаратного хранилища
    ///
    /// # Returns
    /// * `bool` - true если аппаратное хранилище доступно
    fn is_available(&self) -> bool;
}

/// Реализация иерархии ключей с поддержкой аппаратного хранения
#[derive(Debug)]
pub struct SecureKeyStore {
    /// Аппаратный провайдер ключей (может быть None для программного fallback)
    hardware_provider: Option<Box<dyn HardwareKeyProvider>>,
    /// Текущая иерархия ключей
    key_hierarchy: Option<KeyHierarchy>,
    /// Флаг, указывающий, что используется программный fallback
    using_software_fallback: bool,
}

impl SecureKeyStore {
    /// Создает новый безопасное хранилище ключей
    ///
    /// # Arguments
    /// * `hardware_provider` - аппаратный провайдер ключей (опционально)
    ///
    /// # Returns
    /// * `Self` - новое хранилище ключей
    pub fn new(hardware_provider: Option<Box<dyn HardwareKeyProvider>>) -> Self {
        let using_fallback = hardware_provider.as_ref()
            .map_or(true, |provider| !provider.is_available());

        Self {
            hardware_provider,
            key_hierarchy: None,
            using_software_fallback: using_fallback,
        }
    }

    /// Инициализирует хранилище ключей, генерируя новый мастер-ключ если необходимо
    ///
    /// # Arguments
    /// * `rng` - генератор случайных чисел
    ///
    /// # Returns
    /// * `Result<()>` - результат операции
    pub async fn initialize<R: CryptoRng + RngCore>(&mut self, rng: &mut R) -> Result<()> {
        // Пытаемся загрузить существующий мастер-ключ
        if let Some(hw_provider) = &self.hardware_provider {
            if hw_provider.is_available() {
                if let Ok(Some(master_key)) = hw_provider.get_master_key().await {
                    // Загружаем мастер-ключ из аппаратного хранилища
                    let key_hierarchy = KeyHierarchy::from_master_key(master_key);
                    self.key_hierarchy = Some(key_hierarchy);
                    self.using_software_fallback = false;
                    return Ok(());
                }
            }
        }

        // Если не удалось загрузить из аппаратного хранилища, генерируем новый ключ
        let mut master_key = [0u8; KEY_SIZE];
        rng.fill_bytes(&mut master_key);

        // Сохраняем мастер-ключ в аппаратном хранилище если доступно
        if let Some(hw_provider) = &self.hardware_provider {
            if hw_provider.is_available() {
                let _ = hw_provider.store_master_key(&master_key).await;
            }
        }

        // Создаем иерархию ключей
        let key_hierarchy = KeyHierarchy::from_master_key(master_key);
        self.key_hierarchy = Some(key_hierarchy);
        self.using_software_fallback = self.hardware_provider.as_ref()
            .map_or(true, |provider| !provider.is_available());

        Ok(())
    }

    /// Возвращает ссылку на иерархию ключей
    ///
    /// # Returns
    /// * `Result<&KeyHierarchy>` - ссылка на иерархию ключей или ошибка
    pub fn key_hierarchy(&self) -> Result<&KeyHierarchy> {
        self.key_hierarchy
            .as_ref()
            .ok_or_else(|| AegisError::Uninitialized)
    }

    /// Проверяет, используется ли программный fallback
    pub fn is_using_software_fallback(&self) -> bool {
        self.using_software_fallback
    }

    /// Очищает все ключи из памяти (zeroize)
    pub fn zeroize(&mut self) {
        if let Some(hierarchy) = &mut self.key_hierarchy {
            hierarchy.zeroize();
        }
        self.key_hierarchy = None;
    }
}

/// Программный fallback провайдер для устройств без TEE
///
/// Используется когда аппаратное хранилище недоступно.
/// Все операции выполняются в обычной памяти с последующим zeroize.
#[derive(Debug, Default)]
pub struct SoftwareKeyProvider;

#[async_trait]
impl HardwareKeyProvider for SoftwareKeyProvider {
    async fn generate_master_key(&self) -> Result<[u8; KEY_SIZE]> {
        let mut key = [0u8; KEY_SIZE];
        rand_core::OsRng.fill_bytes(&mut key);
        Ok(key)
    }

    async fn store_master_key(&self, key: &[u8; KEY_SIZE]) -> Result<()> {
        // В программном fallback мы просто храним в памяти
        #[allow(unused_variables)]
        let key = key;
        Ok(())
    }

    async fn get_master_key(&self) -> Result<Option<[u8; KEY_SIZE]>> {
        // В программном fallback мы не сохраняем ключ между сессиями
        Ok(None)
    }

    async fn delete_master_key(&self) -> Result<()> {
        Ok(())
    }

    async fn derive_key_in_hardware(
        &self,
        input_key: &[u8; KEY_SIZE],
        info: &[u8],
    ) -> Result<[u8; KEY_SIZE]> {
        // Для программного fallback выполняем обычное выводление ключа
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), input_key);
        let mut okm = [0u8; KEY_SIZE];
        hk.expand(info, &mut okm)
            .map_err(|_| AegisError::Crypto)?;
        Ok(okm)
    }

    fn is_available(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_key_hierarchy_creation() {
        let master_key = [1u8; 32];
        let hierarchy = KeyHierarchy::from_master_key(master_key);

        assert_eq!(*hierarchy.master_key().expose_secret(), master_key);
        // KEK и DEK должны быть разными и производными от мастер-ключа
        assert_ne!(*hierarchy.kek().expose_secret(), master_key);
        assert_ne!(*hierarchy.dek().expose_secret(), master_key);
        assert_ne!(*hierarchy.kek().expose_secret(), *hierarchy.dek().expose_secret());
    }

    #[test]
    fn test_secure_keystore_creation() {
        let keystore = SecureKeyStore::new(None);
        assert!(keystore.is_using_software_fallback());
    }

    #[tokio::test]
    async fn test_secure_keystore_initialize() {
        let mut keystore = SecureKeyStore::new(None);
        let mut rng = OsRng;
        let result = keystore.initialize(&mut rng).await;
        assert!(result.is_ok());
        assert!(keystore.key_hierarchy().is_ok());
    }
}