// SPDX-License-Identifier: Apache-2.0

//! Иерархия ключей, KEK/DEK, аппаратное хранилище.
//!
//! Реализация иерархии ключей согласно разделу 7.1 дорожной карты:
//! - Master Key (MK) -> Key Encryption Key (KEK) -> Data Encryption Key (DEK)
//! - Использует HKDF-SHA-256 для производства ключей с domain separation
//! - Поддерживает аппаратное хранение через трейт [`HardwareKeyProvider`]
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
// Суффикс `_key` у всех трёх полей — не небрежность именования: это
// MK/KEK/DEK из раздела 7.1 плана, и каждое поле названо ровно так, как
// сущность называется в спецификации. Переименование ради снятия lint
// рассогласовало бы код с документом, по которому его проверяет аудитор.
#[allow(clippy::struct_field_names)]
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
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — сбой вывода ключей через HKDF.
    pub fn from_master_key(master_key: [u8; KEY_SIZE]) -> Result<Self> {
        // Выводим KEK из мастер-ключа с domain separation
        let kek = Self::derive_key(&master_key, INFO_KEK)?;
        // Выводим DEK из мастер-ключа с domain separation (отдельно от KEK)
        let dek = Self::derive_key(&master_key, INFO_DEK)?;

        Ok(Self {
            master_key: Secret::new(master_key),
            key_encryption_key: Secret::new(kek),
            data_encryption_key: Secret::new(dek),
        })
    }

    /// Выводит ключ из входного материала с использованием HKDF-SHA-256
    ///
    /// # Arguments
    /// * `ikm` - входной ключевой материал
    /// * `info` - информация для domain separation
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — сбой HKDF.
    ///
    /// Практически недостижимо: `expand` отказывает единственным способом —
    /// когда запрошено больше 255 × 32 = 8160 байт, а здесь запрашивается
    /// ровно [`KEY_SIZE`] = 32. Ошибка всё равно возвращается, а не
    /// подавляется: на этом месте стоял `expect`, то есть недостижимая ветка
    /// была записана как паника, что запрещено разделом 4.2 плана. Подменять
    /// её нулевым ключом нельзя тем более — молча выведенный нулевой ключ
    /// хуже и паники, и ошибки.
    fn derive_key(ikm: &[u8; KEY_SIZE], info: &[u8]) -> Result<[u8; KEY_SIZE]> {
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm);
        let mut okm = [0u8; KEY_SIZE];

        hk.expand(info, &mut okm).map_err(|_| AegisError::Crypto)?;

        Ok(okm)
    }

    /// Возвращает ссылку на мастер-ключ
    #[must_use]
    pub const fn master_key(&self) -> &Secret<[u8; KEY_SIZE]> {
        &self.master_key
    }

    /// Возвращает ссылку на ключ шифрования ключей
    #[must_use]
    pub const fn kek(&self) -> &Secret<[u8; KEY_SIZE]> {
        &self.key_encryption_key
    }

    /// Возвращает ссылку на ключ шифрования данных
    #[must_use]
    pub const fn dek(&self) -> &Secret<[u8; KEY_SIZE]> {
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
    #[must_use]
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
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — сбой вывода иерархии ключей через HKDF.
    pub async fn initialize<R: CryptoRng + RngCore>(&mut self, rng: &mut R) -> Result<()> {
        // Пытаемся загрузить существующий мастер-ключ
        if let Some(hw_provider) = &self.hardware_provider {
            if hw_provider.is_available() {
                if let Ok(Some(master_key)) = hw_provider.get_master_key().await {
                    // Загружаем мастер-ключ из аппаратного хранилища
                    let key_hierarchy = KeyHierarchy::from_master_key(master_key)?;
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
        let key_hierarchy = KeyHierarchy::from_master_key(master_key)?;
        self.key_hierarchy = Some(key_hierarchy);
        self.using_software_fallback = self
            .hardware_provider
            .as_ref()
            .is_none_or(|provider| !provider.is_available());

        Ok(())
    }

    /// Возвращает ссылку на иерархию ключей
    ///
    /// # Errors
    ///
    /// [`AegisError::Uninitialized`] — хранилище используется до вызова
    /// [`SecureKeyStore::initialize`].
    pub fn key_hierarchy(&self) -> Result<&KeyHierarchy> {
        self.key_hierarchy.as_ref().ok_or(AegisError::Uninitialized)
    }

    /// Проверяет, используется ли программный fallback
    #[must_use]
    pub const fn is_using_software_fallback(&self) -> bool {
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
//
// `unused_async` — по той же причине с другой стороны: сигнатуры заданы
// трейтом [`HardwareKeyProvider`], где они асинхронны, потому что реальные
// реализации (Secure Enclave, StrongBox) ходят в аппаратный модуль. То, что
// программной заглушке ждать нечего, сигнатуру трейта не отменяет.
#[allow(clippy::extra_unused_lifetimes, clippy::unused_async)]
#[async_trait]
impl HardwareKeyProvider for SoftwareKeyProvider {
    async fn generate_master_key(&self) -> Result<[u8; KEY_SIZE]> {
        let mut key = [0u8; KEY_SIZE];
        rand_core::OsRng.fill_bytes(&mut key);
        Ok(key)
    }

    async fn store_master_key(&self, key: &[u8; KEY_SIZE]) -> Result<()> {
        // Программный fallback ничего не сохраняет между сессиями: класть
        // мастер-ключ на диск в открытом виде хуже, чем не иметь провайдера
        // вовсе. Ключ существует только в памяти текущего процесса —
        // отсюда же и `get_master_key`, всегда возвращающий `None`.
        let _ = key;

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

    /// Провайдер, изображающий устройство без TEE.
    ///
    /// `is_available` возвращает `false` — ровно так ведёт себя платформа,
    /// на которой аппаратное хранилище отсутствует или недоступно.
    #[derive(Debug, Default)]
    struct UnavailableHardware;

    #[allow(clippy::extra_unused_lifetimes, clippy::unused_async)]
    #[async_trait]
    impl HardwareKeyProvider for UnavailableHardware {
        async fn generate_master_key(&self) -> Result<[u8; KEY_SIZE]> {
            Err(AegisError::HardwareKeyStore)
        }

        async fn store_master_key(&self, key: &[u8; KEY_SIZE]) -> Result<()> {
            let _ = key;

            Err(AegisError::HardwareKeyStore)
        }

        async fn get_master_key(&self) -> Result<Option<[u8; KEY_SIZE]>> {
            Err(AegisError::HardwareKeyStore)
        }

        async fn delete_master_key(&self) -> Result<()> {
            Err(AegisError::HardwareKeyStore)
        }

        async fn derive_key_in_hardware(
            &self,
            input_key: &[u8; KEY_SIZE],
            info: &[u8],
        ) -> Result<[u8; KEY_SIZE]> {
            let _ = (input_key, info);

            Err(AegisError::HardwareKeyStore)
        }

        fn is_available(&self) -> bool {
            false
        }
    }

    /// 🔐 Graceful degradation: без TEE хранилище всё равно работает.
    ///
    /// Отсутствие аппаратного хранилища — не отказ, а ослабление: ключи
    /// живут в памяти процесса вместо защищённого модуля. Приложение
    /// обязано запуститься и явно сообщить о деградации, а не упасть.
    #[test]
    fn initializes_without_hardware_support() {
        futures_lite_block_on(async {
            let mut keystore = SecureKeyStore::new(Some(Box::new(UnavailableHardware)));

            keystore
                .initialize(&mut OsRng)
                .await
                .expect("без TEE инициализация обязана проходить");

            assert!(
                keystore.is_using_software_fallback(),
                "деградация должна быть отмечена явно"
            );
            assert!(keystore.key_hierarchy().is_ok());
        });
    }

    /// 🔐 Без провайдера вовсе — тоже программный fallback.
    #[test]
    fn initializes_without_any_provider() {
        futures_lite_block_on(async {
            let mut keystore = SecureKeyStore::new(None);

            keystore.initialize(&mut OsRng).await.unwrap();

            assert!(keystore.is_using_software_fallback());
            assert!(keystore.key_hierarchy().is_ok());
        });
    }

    /// С доступным аппаратным хранилищем деградация не отмечается.
    #[test]
    fn hardware_backed_store_is_not_marked_degraded() {
        futures_lite_block_on(async {
            let mut keystore = SecureKeyStore::new(Some(Box::new(SoftwareKeyProvider)));

            keystore.initialize(&mut OsRng).await.unwrap();

            // `SoftwareKeyProvider::is_available` возвращает `true`,
            // поэтому путь считается «аппаратным» с точки зрения флага.
            assert!(!keystore.is_using_software_fallback());
        });
    }

    /// Минимальный исполнитель `async` без внешних зависимостей.
    ///
    /// Крейт не тянет `tokio` ради трёх тестов: трейт асинхронный, но
    /// программные реализации ничего не ждут, поэтому достаточно
    /// прокрутить future до готовности.
    fn futures_lite_block_on<F: core::future::Future>(future: F) -> F::Output {
        use core::task::{Context, Poll, Waker};

        // `Waker::noop` из стандартной библиотеки: собственный vtable
        // потребовал бы `unsafe`, запрещённого правилом 4.2.
        let waker = Waker::noop().clone();
        let mut context = Context::from_waker(&waker);
        let mut future = core::pin::pin!(future);

        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => {}
            }
        }
    }

    #[test]
    fn test_key_hierarchy_creation() {
        let master_key = [1u8; 32];
        let hierarchy = KeyHierarchy::from_master_key(master_key).unwrap();

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

        let first = KeyHierarchy::from_master_key(master_key).unwrap();
        let second = KeyHierarchy::from_master_key(master_key).unwrap();

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
        let first = KeyHierarchy::from_master_key([1u8; KEY_SIZE]).unwrap();
        // Отличие ровно в одном бите — лавинный эффект HKDF должен его размазать.
        let mut other = [1u8; KEY_SIZE];
        other[0] ^= 1;
        let second = KeyHierarchy::from_master_key(other).unwrap();

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
        let hierarchy = KeyHierarchy::from_master_key([7u8; KEY_SIZE]).unwrap();

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
        let hex = master.iter().fold(String::new(), |mut acc, byte| {
            use core::fmt::Write as _;

            let _ = write!(acc, "{byte:02x}");
            acc
        });
        assert!(!rendered.contains(&hex));
    }
}
