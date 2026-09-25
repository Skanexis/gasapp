// SPDX-License-Identifier: Apache-2.0

//! File Vault: файлы под вторым фактором.
//!
//! # Что такое «второй фактор» здесь
//!
//! Разблокированного приложения для доступа к vault **недостаточно**.
//! Пользователь, уже введший PIN и читающий переписку, обязан
//! подтвердить себя ещё раз — биометрией или PIN — чтобы открыть
//! vault. Смысл в сценарии, который в модели угроз называется
//! «телефон разблокирован и отдан в чужие руки»: разговор показать
//! не жалко, паспорт — жалко.
//!
//! # Почему ключ не лежит в памяти постоянно
//!
//! 🔐 `K_vault` появляется в памяти в момент успешной повторной
//! аутентификации и исчезает при закрытии vault. Если бы он жил
//! рядом с ключом базы всё время работы приложения, второй фактор
//! защищал бы только кнопку в интерфейсе: дамп памяти
//! разблокированного приложения выдал бы содержимое vault наравне
//! с перепиской.
//!
//! Отсюда правило раздела 11.4: «`K_vault` хранится в RAM отдельно
//! от `K_db` и обнуляется раньше». Здесь оно выполняется тем, что
//! ключ живёт внутри [`VaultGuard`] и обнуляется при закрытии,
//! при уходе в фон и по бездействию.
//!
//! # Когда vault закрывается
//!
//! | Событие | Причина |
//! |---|---|
//! | 60 секунд бездействия | Телефон положили на стол открытым |
//! | Уход приложения в фон | Переключение задач, звонок, снимок экрана |
//! | Явное закрытие | Пользователь закончил |
//! | Блокировка приложения | Vault не может пережить блокировку |
//!
//! # Чего здесь нет
//!
//! Проверки биометрии. Её делает платформа: Android — через
//! `BiometricPrompt`, iOS — через `LocalAuthentication`. Ядро
//! получает уже готовый ответ «человек подтвердил себя» и по нему
//! открывает vault. Собственной проверки быть не может — ядро
//! не имеет доступа ни к датчику, ни к аппаратному хранилищу.

use aegis_keystore::KeyHierarchy;
use aegis_media::attachment::{self, AttachmentKey};
use aegis_storage::{Storage, VaultFileRow};
use aegis_types::{AegisError, MessageId, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Имя настройки с проверочным значением vault.
const VERIFIER_SETTING: &str = "vault_verifier";

/// Что заворачивается в ключ vault для проверки.
///
/// Значение не секретно: проверка держится на том, что развернуть
/// его может только верный ключ (AEAD).
const VERIFIER_PLAINTEXT: [u8; 32] = [0x5A; 32];

/// Выводит ключ vault из PIN: Argon2id — мастер-ключ, HKDF — ключ vault.
fn derive_vault_key(pin: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let master = aegis_keystore::pin::derive_key(pin, salt)?;
    let hierarchy = KeyHierarchy::from_master_key(*master.expose_secret())?;

    hierarchy.vault_key()
}

/// Разворачивается ли проверочное значение этим ключом.
fn verifier_matches(vault_key: &[u8; 32], stored: &str) -> bool {
    crate::client::unhex(stored)
        .ok()
        .and_then(|wrapped| aegis_keystore::unwrap_key(vault_key, wrapped.as_slice()).ok())
        .is_some_and(|plain| *plain.expose_secret() == VERIFIER_PLAINTEXT)
}

/// Размер ключа vault.
pub const KEY_LEN: usize = 32;

/// Через сколько бездействия vault закрывается сам.
///
/// 60 секунд — из раздела 11.4. Значение намеренно маленькое:
/// vault открывают, чтобы посмотреть один файл, а не чтобы держать
/// открытым весь сеанс работы.
pub const DEFAULT_IDLE_TIMEOUT_MILLIS: i64 = 60 * 1000;

/// Состояние vault.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VaultState {
    /// Закрыт: ключа в памяти нет.
    Sealed,
    /// Открыт: ключ в памяти, доступ разрешён.
    Open,
}

/// Хранитель состояния и ключа File Vault.
///
/// # Про `Debug`
///
/// Реализован вручную и печатает только состояние. Производный
/// `Debug` вывел бы байты ключа в лог при первом же `{:?}`
/// в отладочном коде (Правило 4).
pub struct VaultGuard {
    /// Ключ, пока vault открыт.
    ///
    /// [`Zeroizing`] обнуляет содержимое при уничтожении, поэтому
    /// закрытие vault — это присваивание `None`, после которого
    /// прежнее значение затирается.
    key: Option<Zeroizing<[u8; KEY_LEN]>>,
    /// Когда пользователь последний раз обращался к vault.
    last_activity: Timestamp,
    /// Через сколько бездействия закрывать.
    idle_timeout: i64,
}

// Поле `key` намеренно не печатается: это и есть смысл ручной
// реализации. `finish_non_exhaustive` вместо `finish` говорит об этом
// и читателю (в выводе появляется `..`), и clippy, который иначе
// требует перечислить все поля — то есть требует напечатать ключ.
impl core::fmt::Debug for VaultGuard {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VaultGuard")
            .field("open", &self.key.is_some())
            .field("idle_timeout", &self.idle_timeout)
            .finish_non_exhaustive()
    }
}

impl VaultGuard {
    /// Создаёт закрытый vault.
    #[must_use]
    pub const fn new(now: Timestamp) -> Self {
        Self {
            key: None,
            last_activity: now,
            idle_timeout: DEFAULT_IDLE_TIMEOUT_MILLIS,
        }
    }

    /// Задаёт таймаут бездействия.
    ///
    /// Ноль означает «закрывать сразу после каждой операции».
    pub const fn set_idle_timeout(&mut self, millis: i64) {
        self.idle_timeout = millis;
    }

    /// Открывает vault после успешной повторной аутентификации.
    ///
    /// `key` — `K_vault` из иерархии ключей
    /// (`KeyHierarchy::vault_key`). Ядро не выводит его само:
    /// мастер-ключ живёт в `aegis-keystore`, и протаскивать его
    /// сюда значило бы размножить точки, где он доступен.
    ///
    /// # Про повторное открытие
    ///
    /// Уже открытый vault открывается заново без ошибки — это просто
    /// продление сеанса. Прежний ключ при этом затирается: `Zeroizing`
    /// обнуляет старое значение, когда его вытесняет новое.
    pub fn open(&mut self, key: Zeroizing<[u8; KEY_LEN]>, now: Timestamp) {
        self.key = Some(key);
        self.last_activity = now;
    }

    /// Закрывает vault и обнуляет ключ.
    ///
    /// Идемпотентно: закрыть закрытый — не ошибка.
    pub fn seal(&mut self) {
        // Присваивание `None` уничтожает прежнее значение, а его
        // `Drop` затирает байты. Явного вызова `zeroize` не нужно —
        // и именно поэтому ключ обёрнут в `Zeroizing`, а не лежит
        // голым массивом: забыть затереть невозможно.
        self.key = None;
    }

    /// Текущее состояние с учётом бездействия.
    ///
    /// Как и автоблокировка приложения, закрытие по бездействию
    /// **вычисляется**, а не наступает по таймеру: ядро не владеет
    /// часами и не крутит фоновых задач (раздел 9.2 плана).
    ///
    /// ⚠️ Важное следствие: пока никто не спрашивает состояние,
    /// ключ физически остаётся в памяти. Поэтому платформа обязана
    /// звать [`VaultGuard::on_background`] при уходе в фон, а не
    /// полагаться на то, что таймаут «сработает сам».
    #[must_use]
    pub fn state(&self, now: Timestamp) -> VaultState {
        if self.key.is_none() {
            return VaultState::Sealed;
        }

        let idle = now
            .as_millis()
            .saturating_sub(self.last_activity.as_millis());

        if idle >= self.idle_timeout {
            VaultState::Sealed
        } else {
            VaultState::Open
        }
    }

    /// Возвращает ключ, если vault открыт, и продлевает сеанс.
    ///
    /// # Про побочный эффект
    ///
    /// Метод обновляет отметку активности — то есть обращение
    /// к файлу продлевает открытость vault. Это осознанно:
    /// пользователь, листающий файлы, не должен упираться в
    /// повторную аутентификацию посреди просмотра.
    ///
    /// # Errors
    ///
    /// [`AegisError::Locked`] — vault закрыт либо истёк по
    /// бездействию. Ошибка та же, что у заблокированного
    /// приложения: для вызывающего разница только в том, какую
    /// аутентификацию запросить.
    pub fn key(&mut self, now: Timestamp) -> Result<&[u8; KEY_LEN]> {
        // Проверка до выдачи: истёкший по бездействию vault обязан
        // закрыться в этот момент, а не просто ответить отказом, —
        // иначе ключ остался бы в памяти до следующего запроса.
        if self.state(now) == VaultState::Sealed {
            self.seal();

            return Err(AegisError::Locked);
        }

        self.last_activity = now;

        // `as_deref` даёт ссылку на содержимое `Zeroizing` без копии:
        // копия ключа была бы вторым экземпляром, который никто
        // не затрёт.
        self.key.as_deref().ok_or(AegisError::Locked)
    }

    /// Открыт ли vault прямо сейчас.
    #[must_use]
    pub fn is_open(&self, now: Timestamp) -> bool {
        self.state(now) == VaultState::Open
    }

    /// Реакция на уход приложения в фон.
    ///
    /// 🔐 Закрывает vault немедленно, не глядя на таймаут. Уход
    /// в фон — это момент, когда экран может попасть в снимок
    /// переключателя задач, а телефон — в чужие руки.
    pub fn on_background(&mut self) {
        self.seal();
    }

    /// Реакция на блокировку приложения.
    ///
    /// Vault не может пережить блокировку: она означает, что
    /// в памяти не должно остаться ничего, чем открываются данные.
    pub fn on_app_locked(&mut self) {
        self.seal();
    }
}
// --- File Vault (раздел 11.4) ---

/// Хранилище файлов под вторым фактором.
///
/// # Почему это отдельный тип, а не методы клиента
///
/// Vault держит собственный ключ и собственное состояние
/// блокировки. Смешать его с клиентом значило бы, что ключ vault
/// живёт ровно столько же, сколько ключ базы, — то есть весь сеанс
/// работы приложения. Тогда второй фактор не защищал бы ни от чего,
/// кроме случайного нажатия.
pub struct Vault<'a> {
    storage: &'a Storage,
    /// Хранитель ключа, живущий дольше самого `Vault`.
    ///
    /// Заимствуется, а не принадлежит: состояние vault обязано
    /// переживать отдельный вызов. Владей `Vault` хранителем,
    /// каждое обращение к файлу начиналось бы с закрытого vault,
    /// то есть с повторной аутентификации на каждый чих.
    guard: &'a mut VaultGuard,
}

impl core::fmt::Debug for Vault<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Vault")
            .field("guard", &self.guard)
            .finish_non_exhaustive()
    }
}

/// Файл, добавленный в vault: запись и шифроблоб.
///
/// Блоб возвращается вызывающему, а не пишется здесь: файловой
/// системы этот слой не касается — ровно как и с вложениями.
#[derive(Debug, Clone)]
pub struct SealedVaultFile {
    /// Идентификатор записи.
    pub file_id: MessageId,
    /// Шифроблоб — его записывает на диск платформа.
    pub ciphertext: Vec<u8>,
}

impl<'a> Vault<'a> {
    /// Собирает представление vault поверх хранилища и хранителя.
    #[must_use]
    pub const fn new(storage: &'a Storage, guard: &'a mut VaultGuard) -> Self {
        Self { storage, guard }
    }

    /// Открывает vault после повторной аутентификации.
    ///
    /// # 🔐 Почему PIN, а не готовый ключ
    ///
    /// Ключ vault не пересекает границу FFI ни в одну сторону
    /// (правило 2 крейта `aegis-ffi`). Платформа передаёт сюда PIN,
    /// подтверждённый повторно — вводом или биометрией, — а вывод
    /// `K_vault` целиком происходит здесь: Argon2id из PIN даёт
    /// мастер-ключ, HKDF по отдельной метке — ключ vault.
    /// Промежуточные значения обнуляются при выходе из функции.
    ///
    /// Повторность аутентификации обеспечивает платформа: ядро
    /// не может отличить «человек только что подтвердил себя»
    /// от «приложение помнит PIN с утра».
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — PIN короче допустимого либо соль
    /// не той длины;
    /// [`AegisError::Crypto`] — сбой вывода ключей.
    pub fn unlock(&mut self, pin: &str, salt: &[u8], now: Timestamp) -> Result<()> {
        let vault_key = derive_vault_key(pin, salt)?;

        // 🔐 Неверный PIN vault не открывает.
        //
        // Прежде здесь проверки не было вовсе: любой PIN длиной от шести
        // символов «открывал» vault. Содержимое файлов оставалось
        // недоступным — ключи файлов не разворачивались, — но список
        // имён отдавался, а удаление работало. Аудитор открыл чужой
        // vault PIN-ом 000000.
        match self.storage.setting_text(VERIFIER_SETTING)? {
            Some(stored) => {
                if !verifier_matches(&vault_key, &stored) {
                    return Err(AegisError::Crypto);
                }
            }
            // Проверочного значения ещё нет — база, заведённая до него.
            // Тогда ключ сверяется с ключом любого файла: верный ключ
            // vault его разворачивает, неверный — нет.
            None => {
                if let Some(file) = self.storage.list_vault_files(1)?.first() {
                    aegis_keystore::unwrap_key(&vault_key, &file.wrapped_key)
                        .map_err(|_| AegisError::Crypto)?;
                }
            }
        }

        self.guard.open(vault_key, now);

        Ok(())
    }

    /// Заводит проверочное значение vault по **заведомо верному** PIN.
    ///
    /// # Зачем отдельно от [`Self::unlock`]
    ///
    /// Верен ли PIN, ядро само узнать не может: ключ базы связан ещё
    /// и с секретом из аппаратного хранилища платформы. Заведомо верен
    /// PIN только в одном месте — когда база им только что открылась.
    /// Туда платформа и зовёт этот метод.
    ///
    /// Заводить значение при первом открытии vault было бы ошибкой:
    /// опечатка в этот момент навсегда привязала бы vault к ней.
    ///
    /// Заведённое значение не трогается и не пересчитывается: проверка
    /// идёт до вывода ключа, так что вход не платит лишнего Argon2id.
    /// Перенести его на другое устройство нельзя — резервная копия
    /// текстовых настроек не содержит.
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — сбой вывода ключа;
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn establish_verifier<R: RngCore + CryptoRng>(
        &mut self,
        pin: &str,
        salt: &[u8],
        rng: &mut R,
    ) -> Result<()> {
        if self.storage.setting_text(VERIFIER_SETTING)?.is_some() {
            return Ok(());
        }

        let vault_key = derive_vault_key(pin, salt)?;

        let wrapped = aegis_keystore::wrap_key(&vault_key, &VERIFIER_PLAINTEXT, rng)?;

        self.storage
            .set_setting_text(VERIFIER_SETTING, &crate::client::hex(&wrapped))
    }

    /// Закрывает vault и обнуляет ключ.
    pub fn seal(&mut self) {
        self.guard.seal();
    }

    /// Реакция на уход приложения в фон.
    pub fn on_background(&mut self) {
        self.guard.on_background();
    }

    /// Открыт ли vault.
    #[must_use]
    pub fn is_open(&self, now: Timestamp) -> bool {
        self.guard.is_open(now)
    }

    /// Сколько файлов в vault.
    ///
    /// Не требует открытого vault: закрытый экран показывает
    /// «в хранилище 3 файла», и это не выдаёт ничего сверх факта
    /// использования vault. Имена файлов — выдают, и за ними нужен
    /// открытый vault.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn file_count(&self) -> Result<u32> {
        self.storage.vault_file_count()
    }

    /// Перечисляет файлы vault.
    ///
    /// # Errors
    ///
    /// [`AegisError::Locked`] — vault закрыт;
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn files(&mut self, limit: u32, now: Timestamp) -> Result<Vec<VaultFileRow>> {
        // Обращение к ключу здесь не ради самого ключа, а ради
        // проверки и продления сеанса: список имён файлов —
        // это уже содержимое vault.
        self.guard.key(now)?;

        self.storage.list_vault_files(limit)
    }

    /// Кладёт файл в vault.
    ///
    /// `location` — путь, по которому платформа запишет шифроблоб.
    /// Сам блоб возвращается в [`SealedVaultFile::ciphertext`].
    ///
    /// # Что с чем шифруется
    ///
    /// Файл шифруется собственным случайным ключом; этот ключ
    /// заворачивается в `K_vault` и в таком виде ложится в базу.
    /// 🔐 Поэтому изъятая и даже расшифрованная база содержимого
    /// vault не выдаёт: развернуть ключ файла нечем, пока vault
    /// закрыт.
    ///
    /// # Errors
    ///
    /// [`AegisError::Locked`] — vault закрыт;
    /// [`AegisError::Crypto`] — сбой шифрования;
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn add_file<R: RngCore + CryptoRng>(
        &mut self,
        name: &str,
        plaintext: &[u8],
        location: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<SealedVaultFile> {
        let vault_key: [u8; 32] = *self.guard.key(now)?;

        let file_key = AttachmentKey::generate(rng);
        let mut ciphertext = Vec::new();

        for (index, chunk) in plaintext.chunks(attachment::CHUNK_SIZE).enumerate() {
            let index = u32::try_from(index).map_err(|_| AegisError::Malformed)?;
            ciphertext.extend_from_slice(&attachment::seal_chunk(&file_key, index, chunk)?);
        }

        let wrapped = aegis_keystore::wrap_key(&vault_key, file_key.expose(), rng)?;
        let file_id = MessageId::generate();

        self.storage.save_vault_file(&VaultFileRow {
            file_id,
            name: name.to_owned(),
            size: i64::try_from(plaintext.len()).map_err(|_| AegisError::Malformed)?,
            created_at: now,
            location: location.to_owned(),
            wrapped_key: wrapped,
        })?;

        Ok(SealedVaultFile {
            file_id,
            ciphertext,
        })
    }

    /// Достаёт файл из vault.
    ///
    /// `ciphertext` — содержимое блоба, прочитанное платформой
    /// по пути из [`VaultFileRow::location`].
    ///
    /// # Errors
    ///
    /// [`AegisError::Locked`] — vault закрыт;
    /// [`AegisError::SessionNotFound`] — записи о файле нет;
    /// [`AegisError::Crypto`] — ключ не разворачивается либо блоб
    /// подменён.
    pub fn open_file(
        &mut self,
        file_id: &MessageId,
        ciphertext: &[u8],
        now: Timestamp,
    ) -> Result<Vec<u8>> {
        let vault_key: [u8; 32] = *self.guard.key(now)?;

        let row = self
            .storage
            .vault_file(file_id)?
            .ok_or(AegisError::SessionNotFound)?;

        let file_key = aegis_keystore::unwrap_key(&vault_key, &row.wrapped_key)?;
        let file_key = AttachmentKey::from_bytes(*file_key.expose_secret());

        // 🔐 Длина шифроблоба однозначно следует из размера файла: чанки
        // по 64 КБ и тег на каждый. Без этой сверки блоб, обрезанный по
        // границе чанка (оборванная запись, подмена на диске), честно
        // расшифровывался бы — и отдавался как целый файл, только короче.
        let size = usize::try_from(row.size).map_err(|_| AegisError::Malformed)?;
        let chunks =
            usize::try_from(attachment::chunk_count(size)?).map_err(|_| AegisError::Malformed)?;
        let expected = chunks
            .checked_mul(attachment::TAG_LEN)
            .and_then(|tags| size.checked_add(tags))
            .ok_or(AegisError::Malformed)?;

        if ciphertext.len() != expected {
            return Err(AegisError::Crypto);
        }

        let mut plaintext = Vec::new();
        for (index, chunk) in ciphertext
            .chunks(attachment::ENCRYPTED_CHUNK_SIZE)
            .enumerate()
        {
            let index = u32::try_from(index).map_err(|_| AegisError::Malformed)?;
            plaintext.extend_from_slice(&attachment::open_chunk(&file_key, index, chunk)?);
        }

        Ok(plaintext)
    }

    /// Убирает файл из vault.
    ///
    /// Возвращает путь к блобу: стирает файл с диска платформа.
    ///
    /// # Errors
    ///
    /// [`AegisError::Locked`] — vault закрыт;
    /// [`AegisError::Storage`] — удаление не удалось.
    pub fn delete_file(&mut self, file_id: &MessageId, now: Timestamp) -> Result<Option<String>> {
        self.guard.key(now)?;

        self.storage.delete_vault_file(file_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_760_000_000_000)
    }

    fn later(offset: i64) -> Timestamp {
        Timestamp::from_millis(now().as_millis().saturating_add(offset))
    }

    fn key() -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new([0x42u8; KEY_LEN])
    }

    /// Новый vault закрыт.
    #[test]
    fn new_vault_is_sealed() {
        let vault = VaultGuard::new(now());

        assert_eq!(vault.state(now()), VaultState::Sealed);
        assert!(!vault.is_open(now()));
    }

    /// 🔐 Закрытый vault ключа не отдаёт.
    #[test]
    fn sealed_vault_refuses_the_key() {
        let mut vault = VaultGuard::new(now());

        assert!(matches!(vault.key(now()), Err(AegisError::Locked)));
    }

    /// После повторной аутентификации vault открывается.
    #[test]
    fn vault_opens_after_reauthentication() {
        let mut vault = VaultGuard::new(now());
        vault.open(key(), now());

        assert_eq!(vault.state(now()), VaultState::Open);
        assert_eq!(vault.key(now()).expect("ключ"), &[0x42u8; KEY_LEN]);
    }

    /// 🔐 Vault закрывается по бездействию.
    #[test]
    fn vault_seals_after_idle_timeout() {
        let mut vault = VaultGuard::new(now());
        vault.open(key(), now());

        assert_eq!(
            vault.state(later(DEFAULT_IDLE_TIMEOUT_MILLIS - 1)),
            VaultState::Open
        );
        assert_eq!(
            vault.state(later(DEFAULT_IDLE_TIMEOUT_MILLIS)),
            VaultState::Sealed
        );
    }

    /// 🔐 Истёкший vault не только отказывает, но и стирает ключ.
    ///
    /// Отказ без стирания оставил бы ключ в памяти до следующего
    /// обращения — а обращения может не быть вовсе.
    #[test]
    fn expired_vault_forgets_the_key() {
        let mut vault = VaultGuard::new(now());
        vault.open(key(), now());

        assert!(vault.key(later(DEFAULT_IDLE_TIMEOUT_MILLIS)).is_err());

        // Ключ забыт: даже возврат к «сейчас» vault не открывает.
        assert_eq!(vault.state(now()), VaultState::Sealed);
        assert!(vault.key(now()).is_err());
    }

    /// Обращение к файлу продлевает сеанс.
    #[test]
    fn access_extends_the_session() {
        let mut vault = VaultGuard::new(now());
        vault.open(key(), now());

        // Обращение почти на исходе таймаута.
        let touch = DEFAULT_IDLE_TIMEOUT_MILLIS - 1;
        assert!(vault.key(later(touch)).is_ok());

        // Отсчёт пошёл заново от момента обращения.
        assert_eq!(
            vault.state(later(touch + DEFAULT_IDLE_TIMEOUT_MILLIS - 1)),
            VaultState::Open
        );
        assert_eq!(
            vault.state(later(touch + DEFAULT_IDLE_TIMEOUT_MILLIS)),
            VaultState::Sealed
        );
    }

    /// 🔐 Уход в фон закрывает vault немедленно.
    #[test]
    fn background_seals_immediately() {
        let mut vault = VaultGuard::new(now());
        vault.open(key(), now());

        vault.on_background();

        assert_eq!(vault.state(now()), VaultState::Sealed);
    }

    /// 🔐 Блокировка приложения закрывает vault.
    #[test]
    fn app_lock_seals_the_vault() {
        let mut vault = VaultGuard::new(now());
        vault.open(key(), now());

        vault.on_app_locked();

        assert_eq!(vault.state(now()), VaultState::Sealed);
    }

    /// Закрытие идемпотентно.
    #[test]
    fn sealing_twice_is_not_an_error() {
        let mut vault = VaultGuard::new(now());
        vault.open(key(), now());

        vault.seal();
        vault.seal();

        assert_eq!(vault.state(now()), VaultState::Sealed);
    }

    /// Повторное открытие продлевает сеанс.
    #[test]
    fn reopening_extends_the_session() {
        let mut vault = VaultGuard::new(now());
        vault.open(key(), now());

        vault.open(key(), later(DEFAULT_IDLE_TIMEOUT_MILLIS - 1));

        assert_eq!(
            vault.state(later(2 * DEFAULT_IDLE_TIMEOUT_MILLIS - 2)),
            VaultState::Open
        );
    }

    /// Нулевой таймаут закрывает vault сразу.
    ///
    /// Допустимый выбор для параноидального режима: каждый файл
    /// требует отдельной аутентификации.
    #[test]
    fn zero_timeout_seals_at_once() {
        let mut vault = VaultGuard::new(now());
        vault.set_idle_timeout(0);
        vault.open(key(), now());

        assert_eq!(vault.state(now()), VaultState::Sealed);
    }

    /// 🔐 Debug не раскрывает ключ.
    #[test]
    fn debug_does_not_leak_the_key() {
        let mut vault = VaultGuard::new(now());
        vault.open(Zeroizing::new([0xABu8; KEY_LEN]), now());

        let text = format!("{vault:?}");

        assert!(text.contains("open: true"));
        assert!(!text.contains("171"), "байты ключа попали в Debug: {text}");
        assert!(!text.contains("ab"), "байты ключа попали в Debug: {text}");
    }
}

#[cfg(test)]
mod file_tests {
    use super::*;
    use rand_core::OsRng;

    /// Опознавательная строка содержимого файла.
    const FILE_CANARY: &[u8] = b"PASSPORT-SCAN-CANARY-DO-NOT-LEAK";

    /// PIN, которым открывается vault в тестах.
    const PIN: &str = "123456";

    /// Соль растягивания.
    const SALT: [u8; 16] = [0x33u8; 16];

    fn now() -> Timestamp {
        Timestamp::from_millis(1_760_000_000_000)
    }

    fn later(offset: i64) -> Timestamp {
        Timestamp::from_millis(now().as_millis().saturating_add(offset))
    }

    fn open_storage() -> (Storage, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("каталог");
        let path = directory
            .path()
            .join("aegis.db")
            .to_string_lossy()
            .into_owned();
        let storage = Storage::new(&path, &[0x5Au8; 32]).expect("база");

        (storage, directory)
    }

    /// Файл кладётся в vault и достаётся обратно.
    #[test]
    fn file_round_trips_through_the_vault() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        let sealed = vault
            .add_file("паспорт.pdf", FILE_CANARY, "vault/1.enc", now(), &mut OsRng)
            .expect("добавление");

        let plaintext = vault
            .open_file(&sealed.file_id, &sealed.ciphertext, now())
            .expect("чтение");

        assert_eq!(plaintext, FILE_CANARY);
    }

    /// 🔐 Блоб, обрезанный по границе чанка или дополненный, не
    /// выдаётся за целый файл.
    #[test]
    fn a_truncated_blob_is_not_a_shorter_file() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        // Три чанка: обрезка по границе второго оставляет валидные чанки.
        let content = vec![0x42u8; attachment::CHUNK_SIZE * 2 + 10];
        let sealed = vault
            .add_file("большой.bin", &content, "vault/3.enc", now(), &mut OsRng)
            .expect("добавление");

        let cut = sealed
            .ciphertext
            .get(..attachment::ENCRYPTED_CHUNK_SIZE * 2)
            .expect("два чанка");
        assert!(
            vault.open_file(&sealed.file_id, cut, now()).is_err(),
            "обрезанный принят"
        );

        let mut longer = sealed.ciphertext.clone();
        longer.push(0);
        assert!(
            vault.open_file(&sealed.file_id, &longer, now()).is_err(),
            "удлинённый принят"
        );

        assert_eq!(
            vault
                .open_file(&sealed.file_id, &sealed.ciphertext, now())
                .expect("целый"),
            content
        );
    }

    /// 🔐 Шифроблоб не содержит открытого содержимого.
    #[test]
    fn blob_hides_the_file_contents() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        let sealed = vault
            .add_file("паспорт.pdf", FILE_CANARY, "vault/1.enc", now(), &mut OsRng)
            .expect("добавление");

        assert!(
            !sealed
                .ciphertext
                .windows(FILE_CANARY.len())
                .any(|window| window == FILE_CANARY),
            "содержимое файла видно в шифроблобе"
        );
    }

    /// 🔐 Закрытый vault не отдаёт ни имён, ни содержимого.
    ///
    /// Это и есть второй фактор: разблокированного приложения
    /// для доступа к vault недостаточно.
    #[test]
    fn sealed_vault_refuses_everything_but_the_count() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        let sealed = vault
            .add_file("паспорт.pdf", FILE_CANARY, "vault/1.enc", now(), &mut OsRng)
            .expect("добавление");

        vault.seal();

        assert!(matches!(vault.files(10, now()), Err(AegisError::Locked)));
        assert!(matches!(
            vault.open_file(&sealed.file_id, &sealed.ciphertext, now()),
            Err(AegisError::Locked)
        ));
        assert!(matches!(
            vault.delete_file(&sealed.file_id, now()),
            Err(AegisError::Locked)
        ));
        assert!(matches!(
            vault.add_file("ещё.pdf", b"x", "vault/2.enc", now(), &mut OsRng),
            Err(AegisError::Locked)
        ));

        // Число файлов доступно и на закрытом vault: экран показывает
        // «в хранилище 1 файл», не раскрывая, какой именно.
        assert_eq!(vault.file_count().expect("счёт"), 1);
    }

    /// 🔐 Неверный PIN не открывает vault, и файл недоступен.
    ///
    /// ⚠️ Прежде этот тест утверждал обратное: «отдельной проверки PIN
    /// не существует», и неверный PIN здесь «открывал» vault — тест
    /// закреплял дефект как норму. Содержимое тогда не расшифровывалось,
    /// но список имён отдавался и удаление работало.
    #[test]
    fn wrong_pin_does_not_open_the_file() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        let sealed = vault
            .add_file("паспорт.pdf", FILE_CANARY, "vault/1.enc", now(), &mut OsRng)
            .expect("добавление");

        vault.seal();

        assert!(
            matches!(
                vault.unlock("999999", &SALT, now()),
                Err(AegisError::Crypto)
            ),
            "неверный PIN открыл vault"
        );
        assert!(matches!(
            vault.open_file(&sealed.file_id, &sealed.ciphertext, now()),
            Err(AegisError::Locked)
        ));
    }

    /// 🔐 Ключ файла в базе лежит завёрнутым.
    ///
    /// Проверяется прямо по строке хранилища: даже расшифрованная
    /// база не отдаёт ключ, которым зашифрован файл.
    #[test]
    fn file_key_is_wrapped_in_the_database() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        let sealed = vault
            .add_file("паспорт.pdf", FILE_CANARY, "vault/1.enc", now(), &mut OsRng)
            .expect("добавление");

        let row = storage
            .vault_file(&sealed.file_id)
            .expect("чтение")
            .expect("запись есть");

        assert_eq!(
            row.wrapped_key.len(),
            aegis_keystore::wrap::WRAPPED_LEN,
            "ключ файла лежит не завёрнутым"
        );
        // Развернуть его можно только ключом vault.
        assert!(aegis_keystore::unwrap_key(&[0u8; 32], &row.wrapped_key).is_err());
    }

    /// 🔐 Подменённый блоб отвергается, а не показывается.
    #[test]
    fn tampered_blob_is_rejected() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        let sealed = vault
            .add_file("паспорт.pdf", FILE_CANARY, "vault/1.enc", now(), &mut OsRng)
            .expect("добавление");

        let mut damaged = sealed.ciphertext.clone();
        if let Some(byte) = damaged.first_mut() {
            *byte ^= 0xFF;
        }

        assert!(vault.open_file(&sealed.file_id, &damaged, now()).is_err());
    }

    /// 🔐 Vault закрывается по бездействию посреди работы.
    #[test]
    fn vault_seals_itself_after_a_minute() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        let sealed = vault
            .add_file("паспорт.pdf", FILE_CANARY, "vault/1.enc", now(), &mut OsRng)
            .expect("добавление");

        // Минута спустя ключа в памяти уже нет.
        assert!(matches!(
            vault.open_file(
                &sealed.file_id,
                &sealed.ciphertext,
                later(DEFAULT_IDLE_TIMEOUT_MILLIS)
            ),
            Err(AegisError::Locked)
        ));
    }

    /// 🔐 Уход в фон закрывает vault немедленно.
    #[test]
    fn background_seals_the_vault() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        vault.on_background();

        assert!(!vault.is_open(now()));
        assert!(matches!(vault.files(10, now()), Err(AegisError::Locked)));
    }

    /// Список файлов виден при открытом vault.
    #[test]
    fn open_vault_lists_files() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        vault
            .add_file("паспорт.pdf", FILE_CANARY, "vault/1.enc", now(), &mut OsRng)
            .expect("добавление");

        let files = vault.files(10, now()).expect("список");

        assert_eq!(files.len(), 1);
        assert_eq!(
            files.first().map(|row| row.name.as_str()),
            Some("паспорт.pdf")
        );
        assert_eq!(
            files.first().map(|row| row.size),
            i64::try_from(FILE_CANARY.len()).ok()
        );
    }

    /// Удаление отдаёт путь к блобу и убирает запись.
    #[test]
    fn deleting_returns_the_blob_path() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        let sealed = vault
            .add_file("паспорт.pdf", FILE_CANARY, "vault/1.enc", now(), &mut OsRng)
            .expect("добавление");

        assert_eq!(
            vault.delete_file(&sealed.file_id, now()).expect("удаление"),
            Some("vault/1.enc".to_owned())
        );
        assert_eq!(vault.file_count().expect("счёт"), 0);
    }

    /// Файл длиннее одного чанка тоже проходит цикл.
    #[test]
    fn multi_chunk_file_round_trips() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        // Два с половиной чанка: проверяется и склейка, и хвост.
        let big = vec![0x7Bu8; attachment::CHUNK_SIZE * 2 + 1024];

        let sealed = vault
            .add_file("видео.mp4", &big, "vault/2.enc", now(), &mut OsRng)
            .expect("добавление");

        assert_eq!(
            vault
                .open_file(&sealed.file_id, &sealed.ciphertext, now())
                .expect("чтение"),
            big
        );
    }

    /// Каждый файл шифруется своим ключом.
    ///
    /// 🔐 Общий ключ означал бы, что раскрытие одного файла
    /// раскрывает все.
    #[test]
    fn each_file_gets_its_own_key() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        let first = vault
            .add_file("a.pdf", b"same contents", "vault/1.enc", now(), &mut OsRng)
            .expect("добавление");
        let second = vault
            .add_file("b.pdf", b"same contents", "vault/2.enc", now(), &mut OsRng)
            .expect("добавление");

        assert_ne!(
            first.ciphertext, second.ciphertext,
            "одинаковые файлы дали одинаковый шифротекст — ключ общий"
        );
    }

    /// Запись о файле, которого нет, даёт понятный отказ.
    #[test]
    fn missing_file_is_reported() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        assert!(matches!(
            vault.open_file(&MessageId::generate(), b"", now()),
            Err(AegisError::SessionNotFound)
        ));
    }

    /// Debug не раскрывает ключ vault.
    #[test]
    fn debug_does_not_leak_the_vault_key() {
        let (storage, _dir) = open_storage();
        let mut keeper = VaultGuard::new(now());
        let mut vault = Vault::new(&storage, &mut keeper);
        vault.unlock(PIN, &SALT, now()).expect("открытие");

        let text = format!("{vault:?}");

        assert!(text.contains("Vault"));
        assert!(!text.contains("key:"), "в Debug попал ключ: {text}");
    }
}
