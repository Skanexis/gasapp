// SPDX-License-Identifier: Apache-2.0

//! Иерархия ключей, KEK/DEK, аппаратное хранилище.
//!
//! Реализация иерархии ключей согласно разделу 7.1 дорожной карты:
//! - Master Key (MK) -> Key Encryption Key (KEK) -> Data Encryption Key (DEK)
//! - Использует HKDF-SHA-256 для производства ключей с domain separation
//! - Поддерживает аппаратное хранение через HardwareKeyProvider trait
//! - Обеспечивает graceful degradation на устройствах без TEE

use aegis_types::{AegisError, Result, Secret};
use async_trait::async_trait;
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;

/// Размер ключей в байтах
pub const KEY_SIZE: usize = 32;

/// Константы для domain separation в HKDF.
///
/// Разные метки `info` при одном и том же входном ключе дают независимые
/// выходы: именно это делает KEK и DEK несвязанными, хотя оба выведены
/// из одного мастер-ключа (раздел 7.1 плана).
const HKDF_SALT: &[u8] = b"AEGIS_KEYSTORE_SALT_V1";
const INFO_KEK: &[u8] = b"AEGIS_KEK_DERIVATION";
const INFO_DEK: &[u8] = b"AEGIS_DEK_DERIVATION";

/// Иерархия ключей: Master Key -> KEK -> DEK
///
/// # Почему тип не `Clone` и не `Zeroize`
///
/// `Secret<T>` намеренно не реализует ни `Clone`, ни `Zeroize`: копия
/// секрета — это второй экземпляр ключевого материала, который придётся
/// отдельно отслеживать и затирать, а `Secret` уже затирает себя сам при
/// уничтожении (`ZeroizeOnDrop`). Прежние derive `Clone`/`Zeroize` в этой
/// строке не компилировались именно по этой причине — ограничение сработало
/// как задумано и было снято здесь, а не ослаблено в `aegis-types`.
#[derive(Debug)]
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
        hk.expand(info, &mut okm).expect("HKDF expansion failed");
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
///
/// `Debug` реализован вручную: производный `Debug` требовал бы его от
/// `dyn HardwareKeyProvider`, а обязывать к этому каждую платформенную
/// реализацию (Secure Enclave, StrongBox) незачем — печатать там нечего,
/// кроме факта доступности.
pub struct SecureKeyStore {
    /// Аппаратный провайдер ключей (может быть None для программного fallback)
    hardware_provider: Option<Box<dyn HardwareKeyProvider>>,
    /// Текущая иерархия ключей
    key_hierarchy: Option<KeyHierarchy>,
    /// Флаг, указывающий, что используется программный fallback
    using_software_fallback: bool,
}

impl core::fmt::Debug for SecureKeyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Ни ключи, ни их наличие в конкретных полях не раскрываются:
        // отладочный вывод попадает в логи, а логи переживают сессию.
        f.debug_struct("SecureKeyStore")
            .field("hardware_provider", &self.hardware_provider.is_some())
            .field("initialized", &self.key_hierarchy.is_some())
            .field("using_software_fallback", &self.using_software_fallback)
            .finish()
    }
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
        let using_fallback = hardware_provider
            .as_ref()
            .is_none_or(|provider| !provider.is_available());

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
        self.using_software_fallback = self
            .hardware_provider
            .as_ref()
            .is_none_or(|provider| !provider.is_available());

        Ok(())
    }

    /// Возвращает ссылку на иерархию ключей
    ///
    /// # Returns
    /// * `Result<&KeyHierarchy>` - ссылка на иерархию ключей или ошибка
    pub fn key_hierarchy(&self) -> Result<&KeyHierarchy> {
        self.key_hierarchy.as_ref().ok_or(AegisError::Uninitialized)
    }

    /// Проверяет, используется ли программный fallback
    pub fn is_using_software_fallback(&self) -> bool {
        self.using_software_fallback
    }

    /// Очищает все ключи из памяти.
    ///
    /// Затирание выполняет не этот метод, а `Drop` у `Secret<T>` внутри
    /// [`KeyHierarchy`]: достаточно уронить значение. Явный вызов `zeroize`
    /// на иерархии здесь стоял раньше и не компилировался — `Secret`
    /// намеренно не реализует `Zeroize`, чтобы затирание нельзя было
    /// «выполнить» над копией, оставив оригинал в памяти.
    pub fn wipe(&mut self) {
        // `take` роняет иерархию, её поля-`Secret` затирают себя в `Drop`.
        drop(self.key_hierarchy.take());
    }
}

/// Программный fallback провайдер для устройств без TEE
///
/// Используется когда аппаратное хранилище недоступно.
/// Все операции выполняются в обычной памяти с последующим zeroize.
#[derive(Debug, Default)]
pub struct SoftwareKeyProvider;

// Предупреждение о неиспользуемом времени жизни порождает сам макрос
// `async_trait` при разворачивании, а не код в этом файле. Подавляется
// точечно на импле, а не глобально в crate-lints.
#[allow(clippy::extra_unused_lifetimes)]
#[async_trait]
impl HardwareKeyProvider for SoftwareKeyProvider {
    async fn generate_master_key(&self) -> Result<[u8; KEY_SIZE]> {
        let mut key = [0u8; KEY_SIZE];
        rand_core::OsRng.fill_bytes(&mut key);
        Ok(key)
    }

    async fn store_master_key(&self, _key: &[u8; KEY_SIZE]) -> Result<()> {
        // Программный fallback ничего не сохраняет между сессиями: класть
        // мастер-ключ на диск в открытом виде хуже, чем не иметь провайдера
        // вовсе. Ключ существует только в памяти текущего процесса —
        // отсюда же и `get_master_key`, всегда возвращающий `None`.
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
        hk.expand(info, &mut okm).map_err(|_| AegisError::Crypto)?;
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
        assert_ne!(
            *hierarchy.kek().expose_secret(),
            *hierarchy.dek().expose_secret()
        );
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

    /// Вывод ключей детерминирован: один мастер-ключ даёт одну и ту же
    /// иерархию. Без этого свойства данные, зашифрованные до перезапуска,
    /// перестали бы расшифровываться после него.
    #[test]
    fn derivation_is_deterministic() {
        let master_key = [0x42u8; KEY_SIZE];

        let first = KeyHierarchy::from_master_key(master_key);
        let second = KeyHierarchy::from_master_key(master_key);

        assert_eq!(
            first.kek().expose_secret(),
            second.kek().expose_secret(),
            "KEK должен зависеть только от мастер-ключа"
        );
        assert_eq!(first.dek().expose_secret(), second.dek().expose_secret());
    }

    /// Разные мастер-ключи дают полностью независимые иерархии.
    #[test]
    fn different_master_keys_give_different_hierarchies() {
        let first = KeyHierarchy::from_master_key([1u8; KEY_SIZE]);
        // Отличие ровно в одном бите — лавинный эффект HKDF должен его размазать.
        let mut other = [1u8; KEY_SIZE];
        other[0] ^= 1;
        let second = KeyHierarchy::from_master_key(other);

        assert_ne!(first.kek().expose_secret(), second.kek().expose_secret());
        assert_ne!(first.dek().expose_secret(), second.dek().expose_secret());
    }

    /// Ни один выведенный ключ не совпадает с другим и не равен нулю.
    ///
    /// Проверка на нули не формальность: заглушка, возвращающая нулевой
    /// буфер вместо ключа, уже встречалась в этом проекте (см. `mlkem`),
    /// и выглядит она как полностью рабочий код.
    #[test]
    fn derived_keys_are_distinct_and_nonzero() {
        let hierarchy = KeyHierarchy::from_master_key([7u8; KEY_SIZE]);

        let master = hierarchy.master_key().expose_secret();
        let kek = hierarchy.kek().expose_secret();
        let dek = hierarchy.dek().expose_secret();

        for key in [master, kek, dek] {
            assert_ne!(key, &[0u8; KEY_SIZE], "ключ не должен быть нулевым");
        }

        assert_ne!(kek, dek, "domain separation: KEK и DEK независимы");
        assert_ne!(kek, master);
        assert_ne!(dek, master);
    }

    /// Обращение к иерархии до инициализации — ошибка, а не паника.
    #[test]
    fn hierarchy_before_initialization_is_an_error() {
        let keystore = SecureKeyStore::new(None);

        assert!(matches!(
            keystore.key_hierarchy(),
            Err(AegisError::Uninitialized)
        ));
    }

    /// `wipe` возвращает хранилище в неинициализированное состояние.
    #[tokio::test]
    async fn wipe_clears_the_hierarchy() {
        let mut keystore = SecureKeyStore::new(None);
        keystore.initialize(&mut OsRng).await.unwrap();
        assert!(keystore.key_hierarchy().is_ok());

        keystore.wipe();

        assert!(matches!(
            keystore.key_hierarchy(),
            Err(AegisError::Uninitialized)
        ));
    }

    /// Отладочный вывод не раскрывает ключевой материал.
    #[tokio::test]
    async fn debug_output_does_not_leak_keys() {
        let mut keystore = SecureKeyStore::new(Some(Box::new(SoftwareKeyProvider)));
        keystore.initialize(&mut OsRng).await.unwrap();

        let rendered = format!("{keystore:?}");

        assert!(rendered.contains("initialized: true"));
        // Ни одного байта ключа в выводе быть не должно.
        let master = *keystore
            .key_hierarchy()
            .unwrap()
            .master_key()
            .expose_secret();
        let hex: String = master.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!rendered.contains(&hex));
    }
}
