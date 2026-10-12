// SPDX-License-Identifier: Apache-2.0

//! Граница FFI между `gasapp-core` и клиентами на Swift и Kotlin.
//!
//! # Правила этого крейта
//!
//! 1. **Тонкий слой.** Здесь только конвертация типов и перехват паник.
//!    Любая логика принадлежит `gasapp-core`.
//! 2. **Никакого ключевого материала.** Через границу не проходят ключи —
//!    только открытый текст, идентификаторы и непрозрачные handle
//!    (раздел 10.3 плана). В публичном API ниже нет ни одной функции,
//!    возвращающей приватный ключ, состояние ratchet или message key.
//! 3. **Паника не пересекает границу.** Разворачивание стека через границу
//!    FFI — неопределённое поведение, поэтому каждая точка входа
//!    оборачивается в [`std::panic::catch_unwind`].
//! 4. **Ошибки не раскрывают деталей.** Текст ошибки уходит в логи
//!    платформы, поэтому [`FfiError`] намеренно неинформативен о содержимом.
//!
//! # Как получаются биндинги
//!
//! Используется библиотечный режим UniFFI: Swift и Kotlin генерируются
//! по собранной библиотеке, а не по отдельному файлу описания интерфейса.
//! Отдельное описание неизбежно расходится с кодом — компилятор его
//! не проверяет.

use std::panic::{catch_unwind, AssertUnwindSafe};

use gasapp_protocol::{Fingerprint, ProtocolVersion, SafetyNumber};
use gasapp_types::{GasAppError, PublicKeyBytes};

uniffi::setup_scaffolding!();

pub mod backup;
pub mod channels;
pub mod keyboards;
pub mod messenger;
pub mod network;
pub mod notify;
pub mod tor;

/// Длина отпечатка identity-ключа в байтах.
const FINGERPRINT_LEN: usize = 30;

/// Ошибка, пересекающая границу FFI.
///
/// Варианты намеренно грубые. Различие между «неверный тег аутентификации»
/// и «неверная длина» — это оракул для атакующего, а сообщение об ошибке
/// попадает в системный лог платформы, который читается кем угодно.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
#[non_exhaustive]
pub enum FfiError {
    /// Ошибка ядра GasApp.
    #[error("gasapp error: {0}")]
    Core(GasAppError),

    /// 🔐 Сервер называет для собеседника не тот ключ, что известен.
    ///
    /// Отдельным вариантом, а не текстом внутри [`FfiError::Core`]:
    /// интерфейс показывает это как предупреждение о возможной
    /// подмене и ведёт к выбору ключа, а не как сбой отправки.
    /// Разбирать для этого строку ошибки значило бы завязать
    /// безопасность на формулировку.
    #[error("peer identity changed")]
    IdentityChanged,

    /// 🔐 Ключ собеседника не подтверждён вне сервера.
    ///
    /// Своим вариантом, как и [`FfiError::IdentityChanged`]: интерфейс
    /// ведёт к сверке safety number, а не показывает сбой.
    #[error("peer not confirmed")]
    PeerUnconfirmed,

    /// Входные данные не прошли валидацию на границе.
    #[error("invalid argument")]
    InvalidArgument,

    /// Имя занято другим аккаунтом.
    ///
    /// Своим вариантом: интерфейс ведёт обратно к полю имени, а не
    /// показывает сбой сети (см. [`GasAppError::UsernameTaken`]).
    #[error("username taken")]
    UsernameTaken,

    /// Строка не похожа на адрес почты.
    #[error("invalid email")]
    InvalidEmail,

    /// Код из письма не принят: неверный, истёкший или сгоревший.
    ///
    /// Своим вариантом: интерфейс ведёт обратно к полю кода.
    #[error("email code rejected")]
    EmailCodeRejected,

    /// На этот адрес почты уже зарегистрирован аккаунт.
    #[error("email taken")]
    EmailTaken,

    /// Действие доступно только с премиумом (создание канала) либо
    /// только владельцу (запись в канал).
    #[error("premium required")]
    PremiumRequired,

    /// В ядре произошла паника.
    ///
    /// Сообщение паники сознательно **не** передаётся: оно может содержать
    /// значения переменных, а значит потенциально — чувствительные данные.
    #[error("internal error")]
    Panic,
}

impl From<GasAppError> for FfiError {
    fn from(error: GasAppError) -> Self {
        match error {
            GasAppError::IdentityChanged => Self::IdentityChanged,
            GasAppError::PeerUnconfirmed => Self::PeerUnconfirmed,
            // Интерфейс показывает правило имени, а не сбой ядра.
            GasAppError::InvalidUsername => Self::InvalidArgument,
            GasAppError::UsernameTaken => Self::UsernameTaken,
            GasAppError::InvalidEmail => Self::InvalidEmail,
            GasAppError::EmailCodeRejected => Self::EmailCodeRejected,
            GasAppError::EmailTaken => Self::EmailTaken,
            GasAppError::Forbidden => Self::PremiumRequired,
            other => Self::Core(other),
        }
    }
}

/// Выполняет операцию ядра, не позволяя панике пересечь границу FFI.
///
/// # Почему это обязательно
///
/// Разворачивание стека Rust через C-ABI — неопределённое поведение.
/// Без этой обёртки паника в ядре означала бы аварийное завершение
/// приложения в лучшем случае и повреждение памяти в худшем (риск R17).
///
/// # Errors
///
/// [`FfiError::Panic`], если операция запаниковала; иначе — ошибка операции.
///
/// # Примеры
///
/// ```
/// use gasapp::guard;
///
/// let ok = guard(|| Ok(2 + 2));
/// assert_eq!(ok.unwrap(), 4);
///
/// let panicked: Result<i32, _> = guard(|| panic!("boom"));
/// assert!(panicked.is_err());
/// ```
pub fn guard<T, F>(operation: F) -> Result<T, FfiError>
where
    F: FnOnce() -> Result<T, GasAppError>,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        // Через `From`, а не `FfiError::Core`: смена ключа собеседника
        // обязана дойти до интерфейса своим вариантом.
        Ok(result) => result.map_err(FfiError::from),
        Err(_) => Err(FfiError::Panic),
    }
}

/// Версия ядра GasApp.
///
/// Клиент сверяет её с версией сгенерированных биндингов: несовпадение
/// означает, что в сборку попала библиотека от другой версии приложения.
#[uniffi::export]
#[must_use]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Версия протокола, которую использует это ядро.
#[uniffi::export]
#[must_use]
pub fn protocol_version() -> u8 {
    ProtocolVersion::CURRENT.as_u8()
}

/// Приводит введённое имя пользователя к каноничной форме.
///
/// 🔐 Одно правило на ядро, сервер и интерфейс: строчные латинские
/// буквы, цифры и `_`, с буквы, 3–32 символа. Интерфейс не держит своей
/// копии правила — копии расходятся, и тогда экран принимает имя,
/// которое ядро отвергнет.
///
/// # Errors
///
/// [`FfiError::InvalidArgument`] — имя не приводится к каноничной форме.
#[uniffi::export]
pub fn canonical_username(raw: String) -> Result<String, FfiError> {
    gasapp_types::canonical_username(&raw).map_err(FfiError::from)
}

/// Проверяет номер версии протокола из входящего сообщения.
///
/// Вынесено в публичный API намеренно: это позволяет платформенным
/// интеграционным тестам убедиться, что отказ от понижения версии
/// (ADR-021) действительно работает через границу FFI, а не только
/// внутри Rust.
///
/// # Errors
///
/// [`FfiError::Core`] с [`GasAppError::UnsupportedProtocolVersion`], если
/// версия ниже минимально поддерживаемой (попытка отключить пост-квантовый
/// ratchet) или выше текущей (неизвестная семантика).
#[uniffi::export]
pub fn check_protocol_version(raw: u8) -> Result<u8, FfiError> {
    guard(|| ProtocolVersion::parse(raw).map(ProtocolVersion::as_u8))
}

/// Форматирует safety number по двум отпечаткам identity-ключей.
///
/// Возвращает строку в раскладке ADR-022: 4 строки по 3 группы из 5 цифр.
///
/// # Errors
///
/// [`FfiError::InvalidArgument`], если длина любого из отпечатков
/// не равна 30 байтам.
#[uniffi::export]
pub fn format_safety_number(local: Vec<u8>, remote: Vec<u8>) -> Result<String, FfiError> {
    let local: [u8; FINGERPRINT_LEN] = local.try_into().map_err(|_| FfiError::InvalidArgument)?;
    let remote: [u8; FINGERPRINT_LEN] = remote.try_into().map_err(|_| FfiError::InvalidArgument)?;

    let number = SafetyNumber::new(
        &Fingerprint::from_bytes(local),
        &Fingerprint::from_bytes(remote),
    );

    Ok(number.to_display_block())
}

/// Вычисляет отпечаток identity-ключа.
///
/// Отпечаток — то, что превращается в safety number и сверяется
/// пользователем. Вычисление живёт в ядре: итеративный SHA-512
/// на 5200 раундов (раздел 6.6), и повторять его в Kotlin/Swift
/// значило бы завести вторую реализацию, которая разойдётся с первой.
///
/// # Errors
///
/// [`FfiError::InvalidArgument`], если ключ не равен 32 байтам.
#[uniffi::export]
pub fn compute_fingerprint(
    identity_key: Vec<u8>,
    identifier: Vec<u8>,
) -> Result<Vec<u8>, FfiError> {
    let key: [u8; 32] = identity_key
        .try_into()
        .map_err(|_| FfiError::InvalidArgument)?;

    let fingerprint = Fingerprint::compute(&PublicKeyBytes::new(key), &identifier);

    Ok(fingerprint.as_bytes().to_vec())
}

/// Создаёт новую пару identity-ключей и возвращает **публичную** часть.
///
/// # Почему возвращается только публичный ключ
///
/// Приватная часть не пересекает границу FFI никогда (правило 2 этого
/// крейта). Она остаётся в ядре и попадает в зашифрованное хранилище;
/// платформенному коду она не нужна — он не выполняет криптографию.
///
/// # Errors
///
/// [`FfiError::Core`] при сбое вывода публичного ключа.
#[uniffi::export]
pub fn generate_identity_public_key() -> Result<Vec<u8>, FfiError> {
    guard(|| {
        let identity = gasapp_protocol::prekeys::generate_identity(&mut rand_core::OsRng)?;

        Ok(identity.public().public().as_bytes().to_vec())
    })
}

/// Состояние блокировки в терминах UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LockStatus {
    /// Приложение не настроено: нет аккаунта и ключей.
    Uninitialized,
    /// Настроено, но заблокировано: нужен PIN или биометрия.
    Locked,
    /// Разблокировано и готово к работе.
    Unlocked,
}

impl From<gasapp_core::LockState> for LockStatus {
    fn from(state: gasapp_core::LockState) -> Self {
        match state {
            gasapp_core::LockState::Uninitialized => Self::Uninitialized,
            gasapp_core::LockState::Locked => Self::Locked,
            gasapp_core::LockState::Unlocked => Self::Unlocked,
        }
    }
}

/// Предупреждение безопасности для Security Center.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SecurityAlertKind {
    /// У контакта сменился identity-ключ.
    IdentityKeyChanged {
        /// Был ли контакт верифицирован до смены.
        was_verified: bool,
    },
    /// Аппаратное хранилище ключей недоступно.
    HardwareProtectionUnavailable,
    /// Резервная копия давно не обновлялась.
    BackupOverdue {
        /// Сколько дней прошло.
        days: u32,
    },
}

/// Решает, нужно ли предупредить о смене identity-ключа контакта.
///
/// Возвращает `None`, когда тревожиться не о чем: ключ прежний либо
/// контакт видится впервые.
///
/// # Про порог тревоги
///
/// Смена ключа у **неверифицированного** контакта — обычное дело
/// (переустановил приложение). Тревожить при каждой означало бы приучить
/// пользователя игнорировать предупреждения, а вместе с ними — настоящую
/// подмену.
///
/// # Errors
///
/// [`FfiError::InvalidArgument`], если предъявленный ключ пуст.
#[uniffi::export]
pub fn identity_change_alert(
    known_identity: Option<Vec<u8>>,
    presented_identity: Vec<u8>,
    was_verified: bool,
) -> Result<Option<SecurityAlertKind>, FfiError> {
    if presented_identity.is_empty() {
        return Err(FfiError::InvalidArgument);
    }

    let Some(known) = known_identity else {
        return Ok(None);
    };

    if known == presented_identity {
        return Ok(None);
    }

    Ok(Some(SecurityAlertKind::IdentityKeyChanged { was_verified }))
}

/// Можно ли отправлять сообщение контакту.
///
/// # 🔐 Блокировка отправки при смене ключа
///
/// Если у **верифицированного** контакта сменился identity-ключ,
/// отправка блокируется до повторной сверки safety number. Пользователь
/// лично подтвердил, что говорит с нужным человеком; молча продолжить
/// переписку после смены ключа означало бы обесценить эту проверку —
/// ровно в том случае, когда она важнее всего.
///
/// Для неверифицированного контакта отправка разрешена: он ничего
/// не подтверждал, и блокировка лишь помешала бы.
#[uniffi::export]
#[must_use]
pub fn can_send_to_contact(identity_changed: bool, was_verified: bool) -> bool {
    !(identity_changed && was_verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_passes_through_success() {
        assert_eq!(guard(|| Ok(42)).unwrap(), 42);
    }

    #[test]
    fn guard_converts_core_errors() {
        let result: Result<(), _> = guard(|| Err(GasAppError::Locked));
        assert!(matches!(result, Err(FfiError::Core(GasAppError::Locked))));
    }

    /// 🔐 Смена ключа собеседника доходит до интерфейса своим вариантом,
    /// а не строкой внутри `Core`, которую пришлось бы разбирать.
    #[test]
    fn identity_change_crosses_the_boundary_as_its_own_variant() {
        let result: Result<(), _> = guard(|| Err(GasAppError::IdentityChanged));
        assert!(matches!(result, Err(FfiError::IdentityChanged)));
    }

    /// Паника не должна пересекать границу FFI.
    #[test]
    fn guard_catches_panics() {
        let result: Result<(), _> = guard(|| panic!("secret value: hunter2"));
        assert!(matches!(result, Err(FfiError::Panic)));
    }

    /// Сообщение паники может содержать чувствительные данные,
    /// поэтому наружу оно не передаётся.
    #[test]
    fn panic_message_does_not_leak() {
        let result: Result<(), _> = guard(|| panic!("private key = 0xDEADBEEF"));
        let message = result.unwrap_err().to_string();

        assert_eq!(message, "internal error");
        assert!(!message.contains("DEADBEEF"));
    }

    #[test]
    fn core_version_is_reported() {
        assert!(!core_version().is_empty());
    }

    /// Отпечаток вычисляется и имеет нужную длину.
    #[test]
    fn fingerprint_is_computed() {
        let fingerprint = compute_fingerprint(vec![0x42; 32], b"alice".to_vec()).unwrap();

        assert_eq!(fingerprint.len(), FINGERPRINT_LEN);
    }

    /// Ключ неверной длины отвергается, а не паникует.
    #[test]
    fn fingerprint_rejects_malformed_key() {
        assert!(matches!(
            compute_fingerprint(vec![0x42; 31], Vec::new()),
            Err(FfiError::InvalidArgument)
        ));
    }

    /// 🔐 Разные ключи дают разные отпечатки.
    ///
    /// Иначе подмена identity-ключа не была бы видна пользователю
    /// при сверке safety number.
    #[test]
    fn fingerprint_distinguishes_keys() {
        let first = compute_fingerprint(vec![0x01; 32], b"id".to_vec()).unwrap();
        let second = compute_fingerprint(vec![0x02; 32], b"id".to_vec()).unwrap();

        assert_ne!(first, second);
    }

    /// Сгенерированный публичный ключ пригоден для вычисления отпечатка.
    #[test]
    fn generated_identity_is_usable() {
        let public = generate_identity_public_key().unwrap();

        assert_eq!(public.len(), 32);
        assert!(compute_fingerprint(public, b"id".to_vec()).is_ok());
    }

    /// Два вызова дают разные ключи.
    #[test]
    fn generated_identities_differ() {
        let first = generate_identity_public_key().unwrap();
        let second = generate_identity_public_key().unwrap();

        assert_ne!(first, second, "генератор вернул один и тот же ключ");
    }

    /// Первая встреча с контактом тревоги не вызывает.
    #[test]
    fn first_contact_raises_no_alert() {
        let alert = identity_change_alert(None, vec![1; 32], false).unwrap();

        assert!(alert.is_none());
    }

    /// Прежний ключ тревоги не вызывает.
    #[test]
    fn unchanged_identity_raises_no_alert() {
        let alert = identity_change_alert(Some(vec![7; 32]), vec![7; 32], true).unwrap();

        assert!(alert.is_none());
    }

    /// 🔐 Смена ключа даёт тревогу с пометкой о верификации.
    #[test]
    fn identity_change_is_reported_with_verification_state() {
        let alert = identity_change_alert(Some(vec![1; 32]), vec![2; 32], true)
            .unwrap()
            .expect("смена ключа обязана дать тревогу");

        assert_eq!(
            alert,
            SecurityAlertKind::IdentityKeyChanged { was_verified: true }
        );
    }

    /// 🔐 Отправка верифицированному контакту блокируется при смене ключа.
    ///
    /// Пользователь лично сверил safety number; молча продолжить переписку
    /// после смены ключа означало бы обесценить эту проверку ровно тогда,
    /// когда она важнее всего.
    #[test]
    fn sending_to_verified_contact_is_blocked_after_key_change() {
        assert!(!can_send_to_contact(true, true));
    }

    /// Неверифицированному контакту отправка разрешена.
    ///
    /// Он ничего не подтверждал, и блокировка лишь помешала бы: смена
    /// ключа у него — обычная переустановка приложения.
    #[test]
    fn sending_to_unverified_contact_is_allowed() {
        assert!(can_send_to_contact(true, false));
        assert!(can_send_to_contact(false, false));
        assert!(can_send_to_contact(false, true));
    }

    /// Пустой предъявленный ключ отвергается.
    #[test]
    fn empty_presented_identity_is_rejected() {
        assert!(matches!(
            identity_change_alert(Some(vec![1; 32]), Vec::new(), false),
            Err(FfiError::InvalidArgument)
        ));
    }

    /// Состояния блокировки переводятся из ядра без потерь.
    #[test]
    fn lock_states_map_across_the_boundary() {
        assert_eq!(
            LockStatus::from(gasapp_core::LockState::Uninitialized),
            LockStatus::Uninitialized
        );
        assert_eq!(
            LockStatus::from(gasapp_core::LockState::Locked),
            LockStatus::Locked
        );
        assert_eq!(
            LockStatus::from(gasapp_core::LockState::Unlocked),
            LockStatus::Unlocked
        );
    }

    #[test]
    fn protocol_version_is_current() {
        assert_eq!(protocol_version(), ProtocolVersion::CURRENT.as_u8());
    }

    /// ADR-021 через границу FFI: понижение отвергается.
    #[test]
    fn protocol_downgrade_is_rejected_across_ffi() {
        assert!(check_protocol_version(0).is_err());
        assert!(check_protocol_version(3).is_err());
        assert_eq!(check_protocol_version(2).unwrap(), 2);
        assert!(
            check_protocol_version(1).is_err(),
            "прежняя версия принята через FFI"
        );
    }

    #[test]
    fn safety_number_is_formatted_for_display() {
        let block = format_safety_number(vec![0x11; 30], vec![0x22; 30]).unwrap();
        let lines: Vec<&str> = block.lines().collect();

        assert_eq!(lines.len(), 4);
        for line in lines {
            assert_eq!(line.split(' ').count(), 3);
        }
    }

    /// Длина отпечатка приходит с платформы и является недоверенным вводом.
    #[test]
    fn safety_number_rejects_wrong_fingerprint_length() {
        assert!(matches!(
            format_safety_number(vec![0; 29], vec![0; 30]),
            Err(FfiError::InvalidArgument)
        ));
        assert!(matches!(
            format_safety_number(vec![0; 30], vec![0; 31]),
            Err(FfiError::InvalidArgument)
        ));
        assert!(matches!(
            format_safety_number(Vec::new(), Vec::new()),
            Err(FfiError::InvalidArgument)
        ));
    }
}

/// Растягивает PIN в ключ хранилища.
///
/// # Зачем это на границе FFI
///
/// Ключ базы выводится из PIN через `Argon2id` (m=64 МиБ, t=3, p=4).
/// Приложение вызывает это перед открытием хранилища и больше нигде:
/// сам PIN за пределы этого вызова не уходит.
///
/// # Про время
///
/// Порядка секунды на телефоне. Вызывать следует в фоновом потоке —
/// это не оптимизируемая задержка, а цена, которая делает перебор
/// изъятого устройства невозможным.
///
/// # Errors
///
/// [`FfiError::InvalidArgument`] — PIN короче шести символов либо
/// соль не 16 байт.
#[uniffi::export]
pub fn derive_storage_key(pin: Vec<u8>, salt: Vec<u8>) -> Result<Vec<u8>, FfiError> {
    let pin = pin_bytes(pin);
    let key = guard(|| gasapp_keystore::pin::derive_key(pin_text(&pin)?, &salt))?;

    Ok(key.expose_secret().to_vec())
}

/// Выводит ключ хранилища из PIN **и** аппаратного секрета.
///
/// # Чем отличается от [`derive_storage_key`]
///
/// [`derive_storage_key`] строит ключ из одного PIN. PIN шестизначный,
/// и `Argon2id` перебор растягивает, но не исключает: машина с 64
/// ядрами и 4 ГиБ памяти проходит весь миллион вариантов за пару
/// часов. То есть снятый с телефона файл базы вместе с солью
/// раскрывается за аренду в несколько долларов.
///
/// 🔐 `hardware_secret` — 32 байта, которые платформа хранит
/// зашифрованными ключом аппаратного хранилища (Android Keystore,
/// по возможности StrongBox). Ключ оттуда не извлекается, поэтому
/// скопировать секрет вместе с файлами нельзя, и у атакующего
/// нет половины входа. Это схема раздела 7.3 и ADR-017; до находки
/// P-5 внутреннего пентеста (раздел 23.6) её не существовало.
///
/// # Errors
///
/// [`FfiError::InvalidArgument`] — PIN короче шести символов, соль
/// не 16 байт либо секрет не 32 байта.
///
/// Принимает растянутый PIN ([`derive_storage_key`]), а не сам PIN:
/// при переходе со схемы v2 на v3 `Argon2id` считается один раз.
#[uniffi::export]
pub fn derive_storage_key_bound(
    stretched: Vec<u8>,
    salt: Vec<u8>,
    hardware_secret: Vec<u8>,
) -> Result<Vec<u8>, FfiError> {
    let stretched = stretched_array(stretched)?;
    let key = guard(|| gasapp_keystore::pin::bind_hardware(&stretched, &salt, &hardware_secret))?;

    Ok(key.expose_secret().to_vec())
}

/// 🔐 Ключ хранилища схемы v3: растянутый PIN и ответ Android Keystore
/// на него (цепочка HMAC невынимаемым ключом, см.
/// [`gasapp_keystore::pin::bind_tee`]).
///
/// # Errors
///
/// [`FfiError::InvalidArgument`] — растянутый PIN, соль или ответ
/// оборудования не той длины.
#[uniffi::export]
pub fn derive_storage_key_tee(
    stretched: Vec<u8>,
    salt: Vec<u8>,
    tee_mac: Vec<u8>,
) -> Result<Vec<u8>, FfiError> {
    let stretched = stretched_array(stretched)?;
    let key = guard(|| gasapp_keystore::pin::bind_tee(&stretched, &salt, &tee_mac))?;

    Ok(key.expose_secret().to_vec())
}

/// Растянутый PIN с границы FFI — затираемый массив ровной длины.
fn stretched_array(
    stretched: Vec<u8>,
) -> Result<zeroize::Zeroizing<[u8; gasapp_keystore::pin::KEY_LEN]>, FfiError> {
    let stretched = zeroize::Zeroizing::new(stretched);
    let array = <[u8; gasapp_keystore::pin::KEY_LEN]>::try_from(stretched.as_slice())
        .map_err(|_| FfiError::InvalidArgument)?;

    Ok(zeroize::Zeroizing::new(array))
}

/// 🔐 PIN приходит байтами и затирается при выходе из вызова.
///
/// Прежде PIN шёл через FFI строкой: `String` в Kotlin неизменяема,
/// затереть её нельзя, и дамп памяти запертого приложения на эмуляторе
/// показывал PIN в куче Java (2026-09-25). Байтовый массив платформа
/// обнуляет сама после вызова, здесь — `Zeroizing`.
pub(crate) fn pin_bytes(pin: Vec<u8>) -> zeroize::Zeroizing<Vec<u8>> {
    zeroize::Zeroizing::new(pin)
}

/// PIN как текст — заимствованием, без копии.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — байты не UTF-8 (у PIN из цифр так не бывает).
pub(crate) fn pin_text(pin: &[u8]) -> gasapp_types::Result<&str> {
    core::str::from_utf8(pin).map_err(|_| GasAppError::Malformed)
}

/// Длина аппаратного секрета в байтах.
///
/// Платформа генерирует секрет сама — ей нужно знать размер.
/// Константа отдаётся наружу, а не дублируется в Kotlin и Swift:
/// разойдясь, они дали бы отказ вывода ключа, который выглядит как
/// «неверный PIN».
#[uniffi::export]
#[must_use]
pub fn hardware_secret_len() -> u32 {
    u32::try_from(gasapp_keystore::pin::HARDWARE_SECRET_LEN).unwrap_or(0)
}

/// Генерирует соль для растягивания PIN.
///
/// Соль хранится рядом с базой в открытом виде: она защищает не от
/// того, кто получил устройство, а от заранее посчитанных таблиц —
/// с ней перебор нужно считать заново для каждого устройства.
#[uniffi::export]
#[must_use]
pub fn generate_storage_salt() -> Vec<u8> {
    gasapp_keystore::pin::generate_salt(&mut rand_core::OsRng).to_vec()
}

/// QR-код safety number.
///
/// Матрица модулей, а не картинка: отрисовка зависит от платформы,
/// а размер модуля — от экрана. Ядро не знает ни того, ни другого.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiQrMatrix {
    /// Сторона матрицы в модулях.
    pub size: u32,
    /// Модули построчно: `size * size` значений, `true` — чёрный.
    pub modules: Vec<bool>,
}

/// Строит QR-код для сверки safety number.
///
/// # Зачем это нужно
///
/// Сверка вручную проваливается там, где утомляет: шестьдесят цифр
/// читают невнимательно, сверяя края и пропуская середину. Атака
/// на этом и строится. QR убирает человека из сравнения — устройство
/// сверяет все цифры само.
///
/// # Errors
///
/// [`FfiError::InvalidArgument`] — строка содержит не только цифры.
/// Форматированный номер с пробелами сюда передавать нельзя: сканер
/// получит не то, что показывает второе устройство.
#[uniffi::export]
pub fn safety_number_qr(digits: String) -> Result<FfiQrMatrix, FfiError> {
    let matrix = guard(|| gasapp_protocol::qr::safety_number_qr(&digits))?;

    Ok(FfiQrMatrix {
        size: u32::try_from(matrix.size).map_err(|_| FfiError::InvalidArgument)?,
        modules: matrix.modules,
    })
}

/// Контакт, полученный по ссылке `gasapp://`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiContactLink {
    /// Identity-ключ контакта, 32 байта.
    pub identity: Vec<u8>,

    /// Хеш пост-квантовой половины identity, 32 байта.
    pub pq_identity_hash: Vec<u8>,

    /// Имя, предложенное владельцем ссылки.
    ///
    /// 🔐 Подсказка для интерфейса, не более: имя выбирает тот, кто
    /// сделал ссылку, и оно ничем не подтверждено. Показывать его
    /// следует как предложенное, а решение о доверии принимать
    /// по ключу.
    pub display_name: Option<String>,
}

/// Собирает ссылку на собственный профиль.
///
/// # Зачем
///
/// Обмен контактами без сервера-посредника: ключ, снятый с экрана
/// человека, стоящего рядом, не нужно принимать на веру у сервера.
///
/// # Errors
///
/// [`FfiError::Core`] — ключ не 32 байта либо имя слишком длинное
/// или содержит управляющие символы.
#[uniffi::export]
pub fn contact_link_uri(
    identity: Vec<u8>,
    pq_identity_hash: Vec<u8>,
    display_name: Option<String>,
) -> Result<String, FfiError> {
    guard(|| {
        let link = gasapp_protocol::contact_link::ContactLink {
            identity: identity_from_bytes(&identity)?,
            pq_identity_hash: pq_identity_hash
                .as_slice()
                .try_into()
                .map_err(|_| GasAppError::Malformed)?,
            display_name,
        };

        link.to_uri()
    })
}

/// Разбирает ссылку, полученную по QR или пересылкой.
///
/// # 🔐 Про доверие
///
/// Ссылка не подписана и подписана быть не может — подписывать нечем,
/// ключ как раз и передаётся. Успешный разбор означает только то,
/// что формат верен. Приложение обязано показать пользователю, кого
/// именно оно собирается добавить, до того как добавит.
///
/// # Errors
///
/// [`FfiError::Core`] — ссылка не соответствует формату: чужая схема,
/// лишние сегменты пути, неизвестные параметры, битый ключ.
#[uniffi::export]
pub fn parse_contact_link(uri: String) -> Result<FfiContactLink, FfiError> {
    let link = guard(|| gasapp_protocol::contact_link::ContactLink::parse(&uri))?;

    Ok(FfiContactLink {
        identity: link.identity.as_bytes().to_vec(),
        pq_identity_hash: link.pq_identity_hash.to_vec(),
        display_name: link.display_name,
    })
}

/// Строит QR-код готовой ссылки на контакт.
///
/// Принимает **саму ссылку**, а не ключ с именем, потому что рядом
/// с кодом почти всегда показан её текст: собери код заново из
/// разобранных частей — и пропущенное поле развело бы QR с текстом,
/// который пользователь видит и диктует.
///
/// Ссылка всё равно разбирается перед кодированием: в QR не должно
/// попасть то, что не является контактом.
///
/// Матрица модулей, а не картинка: отрисовка и размер модуля зависят
/// от платформы и экрана.
///
/// # Errors
///
/// [`FfiError::Core`] — ссылка не разбирается либо не помещается в код;
/// [`FfiError::InvalidArgument`] — матрица не представима на платформе.
#[uniffi::export]
pub fn contact_link_qr(uri: String) -> Result<FfiQrMatrix, FfiError> {
    let matrix = guard(|| {
        let link = gasapp_protocol::contact_link::ContactLink::parse(&uri)?;

        gasapp_protocol::contact_link::contact_qr(&link)
    })?;

    Ok(FfiQrMatrix {
        size: u32::try_from(matrix.size).map_err(|_| FfiError::InvalidArgument)?,
        modules: matrix.modules,
    })
}

/// Превращает байты с платформы в identity-ключ.
///
/// Длина проверяется здесь, а не в ядре: за границей FFI ключ — это
/// массив произвольной длины, и молчаливое дополнение нулями дало бы
/// ссылку на чужой ключ.
fn identity_from_bytes(bytes: &[u8]) -> gasapp_types::Result<gasapp_types::PublicKeyBytes> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| gasapp_types::GasAppError::Malformed)?;

    Ok(gasapp_types::PublicKeyBytes::new(array))
}

#[cfg(test)]
mod contact_link_tests {
    use super::*;

    fn identity() -> Vec<u8> {
        (0..32u8).collect()
    }

    #[test]
    fn link_round_trips_across_the_boundary() {
        let uri =
            contact_link_uri(identity(), vec![0x5A; 32], Some("Иван".to_owned())).expect("ссылка");
        let parsed = parse_contact_link(uri).expect("разбор");

        assert_eq!(parsed.identity, identity());
        assert_eq!(parsed.display_name.as_deref(), Some("Иван"));
    }

    #[test]
    fn link_without_name_round_trips() {
        let uri = contact_link_uri(identity(), vec![0x5A; 32], None).expect("ссылка");
        let parsed = parse_contact_link(uri).expect("разбор");

        assert_eq!(parsed.identity, identity());
        assert!(parsed.display_name.is_none());
    }

    /// 🔐 Ключ неверной длины отвергается, а не дополняется нулями.
    ///
    /// Дополнение дало бы ссылку на ключ, которого у пользователя нет.
    /// 🔐 В QR не попадает то, что не является контактом.
    #[test]
    fn qr_rejects_foreign_link() {
        assert!(contact_link_qr("https://evil.example/".to_owned()).is_err());
    }

    #[test]
    fn wrong_identity_length_is_rejected() {
        for length in [0usize, 31, 33, 64] {
            assert!(
                contact_link_uri(vec![0; length], vec![0x5A; 32], None).is_err(),
                "ключ длиной {length} принят"
            );
        }
    }

    /// 🔐 Чужая схема не проходит через границу.
    #[test]
    fn foreign_scheme_is_rejected_across_the_boundary() {
        assert!(matches!(
            parse_contact_link("https://evil.example/".to_owned()),
            Err(FfiError::Core(GasAppError::Malformed))
        ));
    }

    #[test]
    fn qr_is_built_for_profile() {
        let uri =
            contact_link_uri(identity(), vec![0x5A; 32], Some("Иван".to_owned())).expect("ссылка");
        let matrix = contact_link_qr(uri).expect("код");

        assert!(matrix.size >= 21);
        assert_eq!(
            matrix.modules.len(),
            (matrix.size as usize).saturating_mul(matrix.size as usize)
        );
    }
}
