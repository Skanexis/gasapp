// SPDX-License-Identifier: Apache-2.0

//! Double Ratchet — продвижение ключей при каждом сообщении.
//!
//! Два храповика, вложенные друг в друга:
//!
//! * **внешний (DH)** — при смене ratchet-ключа собеседника выполняется новый
//!   X25519 и обновляется корневой ключ. Даёт post-compromise security:
//!   после утечки состояния стороны восстанавливают секретность, как только
//!   пройдёт один полный обмен в обе стороны;
//! * **внутренний (симметричный)** — каждое сообщение продвигает цепочку
//!   на шаг вперёд. Даёт forward secrecy: старый ключ невозможно получить
//!   из нового, потому что HMAC необратим.
//!
//! # Почему цепочка на HMAC, а не на HKDF
//!
//! Шаг цепочки — это `HMAC(chain_key, константа)` с **разными** константами
//! для следующего звена цепочки и для message key ([`CHAIN_STEP`] и
//! [`MESSAGE_STEP`]). Именно различие констант делает message key и
//! следующий chain key независимыми: зная один, нельзя вычислить другой.
//! В первой редакции движка оба выводились через `HKDF` с одной и той же
//! меткой от разных входов, что связывало их и ломало forward secrecy
//! (раздел 23.0.1 мастер-плана).
//!
//! # Про nonce AEAD
//!
//! Nonce выводится из message key, а не из счётчика сообщений. Счётчик
//! обнуляется при каждом шаге DH-храповика, поэтому пара «ключ, nonce»
//! повторилась бы на первом сообщении каждой новой цепочки — а повтор пары
//! в AES-GCM раскрывает открытый текст обоих сообщений. Message key
//! уникален по построению, значит уникален и выведенный из него nonce.
//!
//! # Границы
//!
//! Модуль не выполняет ввод-вывод и не берёт время из системных часов:
//! отметка времени для TTL пропущенных ключей передаётся аргументом
//! (раздел 9.2 плана).

use std::collections::HashMap;

use aegis_types::{AegisError, Ciphertext, Plaintext, PublicKeyBytes, Result, Secret, Timestamp};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    keys::SessionState,
    spqr,
    x25519::{X25519PrivateKey, X25519PublicKey},
    MAX_SKIPPED_CHAINS, MAX_SKIPPED_MESSAGE_KEYS, SKIPPED_KEY_TTL_DAYS,
};

type HmacSha256 = Hmac<Sha256>;

/// Длина заголовка сообщения: ratchet-ключ (32) ‖ `previous_length` (4) ‖ номер (4).
const HEADER_LEN: usize = 40;

/// Константа шага цепочки: следующий chain key.
const CHAIN_STEP: &[u8] = &[0x02];

/// Константа шага цепочки: message key.
///
/// Отличается от [`CHAIN_STEP`] — на этом различии держится независимость
/// message key от следующего звена цепочки.
const MESSAGE_STEP: &[u8] = &[0x01];

/// Метка HKDF для обновления корневого ключа при шаге DH-храповика.
const ROOT_KDF_INFO: &[u8] = b"AEGIS_DR_v1_ROOT";

/// Метка HKDF для вывода nonce AEAD из message key.
const NONCE_KDF_INFO: &[u8] = b"AEGIS_DR_v1_NONCE";

/// Длина nonce AES-256-GCM.
const NONCE_LEN: usize = 12;

/// Время жизни пропущенного ключа в миллисекундах.
///
/// Вычисляется из [`SKIPPED_KEY_TTL_DAYS`] на этапе компиляции.
const SKIPPED_KEY_TTL_MILLIS: i64 = (SKIPPED_KEY_TTL_DAYS as i64) * 24 * 60 * 60 * 1000;

/// Заголовок сообщения — передаётся открыто и аутентифицируется как AAD.
///
/// # Почему заголовок обязан быть AAD
///
/// В заголовке лежат ratchet-ключ отправителя и номер сообщения. Получатель
/// выбирает по ним ключ расшифровки, то есть заголовок управляет разбором.
/// Не будь он аутентифицирован, посредник менял бы номер сообщения, заставляя
/// получателя вычислять и запоминать произвольное число пропущенных ключей —
/// и подмена не обнаружилась бы, потому что тег AEAD её не покрывает.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Header {
    /// Публичный ratchet-ключ отправителя.
    ratchet_key: PublicKeyBytes,
    /// Длина предыдущей цепочки отправителя — сколько сообщений он успел
    /// отправить до последнего шага DH-храповика.
    previous_length: u32,
    /// Номер сообщения в текущей цепочке, начиная с нуля.
    number: u32,
}

impl Header {
    /// Сериализует заголовок в 40 байт.
    fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let (key_part, counters) = out.split_at_mut(32);
        let (previous, number) = counters.split_at_mut(4);

        key_part.copy_from_slice(self.ratchet_key.as_bytes());
        previous.copy_from_slice(&self.previous_length.to_be_bytes());
        number.copy_from_slice(&self.number.to_be_bytes());

        out
    }

    /// Разбирает заголовок из недоверенных байт.
    fn parse(bytes: &[u8]) -> Result<Self> {
        let raw = bytes.get(..HEADER_LEN).ok_or(AegisError::Malformed)?;
        let (key_part, counters) = raw.split_at(32);
        let (previous, number) = counters.split_at(4);

        let key: [u8; 32] = key_part.try_into().map_err(|_| AegisError::Malformed)?;
        let previous: [u8; 4] = previous.try_into().map_err(|_| AegisError::Malformed)?;
        let number: [u8; 4] = number.try_into().map_err(|_| AegisError::Malformed)?;

        Ok(Self {
            ratchet_key: PublicKeyBytes::new(key),
            previous_length: u32::from_be_bytes(previous),
            number: u32::from_be_bytes(number),
        })
    }
}

/// Ключ, которым индексируется пропущенное сообщение.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct SkippedKeyId {
    ratchet_key: [u8; 32],
    number: u32,
}

/// Сохранённый ключ пропущенного сообщения.
struct SkippedKey {
    material: Secret<[u8; 32]>,
    stored_at: Timestamp,
}

/// Состояние сессии Double Ratchet.
///
/// Хранится в зашифрованном виде: все поля с ключевым материалом обёрнуты
/// в [`Secret`] и обнуляются при уничтожении.
pub struct RatchetState {
    /// Корневой ключ — обновляется на каждом шаге DH-храповика.
    root_key: Secret<[u8; 32]>,
    /// Ключ цепочки отправки. `None` у получателя до первого шага храповика.
    sending_chain: Option<Secret<[u8; 32]>>,
    /// Ключ цепочки приёма. `None` до получения первого сообщения.
    receiving_chain: Option<Secret<[u8; 32]>>,
    /// Наша текущая пара ratchet-ключей.
    our_ratchet: X25519PrivateKey,
    /// Публичный ratchet-ключ собеседника.
    their_ratchet: Option<X25519PublicKey>,
    /// Сколько сообщений отправлено в текущей цепочке.
    sent_count: u32,
    /// Сколько сообщений принято в текущей цепочке.
    received_count: u32,
    /// Длина предыдущей цепочки отправки.
    previous_sending_length: u32,
    /// Ключи пропущенных сообщений.
    skipped: HashMap<SkippedKeyId, SkippedKey>,
}

// Неполнота этого `Debug` — требование, а не упущение: поля с ключевым
// материалом не печатаются ни при каких условиях (правило 4 плана).
// Производный `Debug` раскрыл бы корневой ключ и ключи цепочек в логах.
#[allow(clippy::missing_fields_in_debug)]
impl core::fmt::Debug for RatchetState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Ни одного байта ключевого материала: вывод попадает в логи.
        f.debug_struct("RatchetState")
            .field("sent", &self.sent_count)
            .field("received", &self.received_count)
            .field("skipped", &self.skipped.len())
            .finish()
    }
}

impl RatchetState {
    /// Инициализирует состояние у инициатора сессии.
    ///
    /// Инициатор знает публичный ratchet-ключ получателя из prekey bundle
    /// (это подписанный предключ) и сразу делает первый шаг храповика,
    /// получая цепочку отправки.
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — сбой HKDF при выводе корневого ключа.
    pub fn initiate<R: RngCore + CryptoRng>(
        shared_secret: &[u8; 32],
        their_ratchet: &X25519PublicKey,
        rng: &mut R,
    ) -> Result<Self> {
        let our_ratchet = X25519PrivateKey::generate(rng);
        let dh = Zeroizing::new(our_ratchet.diffie_hellman(their_ratchet));
        let (root_key, sending_chain) = kdf_root(shared_secret, &dh)?;

        Ok(Self {
            root_key: Secret::new(root_key),
            sending_chain: Some(Secret::new(sending_chain)),
            receiving_chain: None,
            our_ratchet,
            their_ratchet: Some(*their_ratchet),
            sent_count: 0,
            received_count: 0,
            previous_sending_length: 0,
            skipped: HashMap::new(),
        })
    }

    /// Инициализирует состояние у получателя сессии.
    ///
    /// Получатель ещё не знает ratchet-ключа инициатора — он придёт
    /// в заголовке первого сообщения и вызовет шаг храповика. Своей парой
    /// ключей выступает та, чью публичную часть инициатор взял из bundle.
    #[must_use]
    pub fn accept(shared_secret: &[u8; 32], our_ratchet: X25519PrivateKey) -> Self {
        Self {
            root_key: Secret::new(*shared_secret),
            sending_chain: None,
            receiving_chain: None,
            our_ratchet,
            their_ratchet: None,
            sent_count: 0,
            received_count: 0,
            previous_sending_length: 0,
            skipped: HashMap::new(),
        }
    }

    /// Шифрует сообщение, продвигая цепочку отправки на один шаг.
    ///
    /// Message key уничтожается сразу после использования — он живёт внутри
    /// [`Zeroizing`] и не сохраняется нигде.
    ///
    /// # Errors
    ///
    /// * [`AegisError::Uninitialized`] — цепочка отправки ещё не создана.
    ///   У получателя это нормальное состояние до первого входящего
    ///   сообщения: отвечать нечем, пока не известен ratchet-ключ собеседника.
    /// * [`AegisError::Crypto`] — сбой AEAD или KDF.
    pub fn encrypt(&mut self, plaintext: &Plaintext) -> Result<Ciphertext> {
        self.encrypt_hybrid(plaintext, None)
    }

    /// Шифрует сообщение, подмешивая пост-квантовый секрет.
    ///
    /// Ключ сообщения выводится из **обеих** составляющих через
    /// [`spqr::combine`]. Это точка, где Double Ratchet становится Triple
    /// Ratchet: см. ADR-021 и модуль [`crate::spqr`].
    ///
    /// Передача `None` оставляет классическое поведение.
    ///
    /// ⚠️ Здесь прежде стояло «применяется только в тестах самого
    /// храповика». Это неправда: `aegis-core::session` зовёт [`Self::encrypt`],
    /// а тот передаёт `None` всегда. SPQR в сессии не подключён, и каждый
    /// ключ сообщения в продукте — классический (раздел 23.0.1, дефект #3
    /// переоткрыт).
    ///
    /// # Errors
    ///
    /// Те же, что у [`RatchetState::encrypt`], плюс сбой объединения ключей.
    pub fn encrypt_hybrid(
        &mut self,
        plaintext: &Plaintext,
        post_quantum: Option<&[u8; 32]>,
    ) -> Result<Ciphertext> {
        let chain = self
            .sending_chain
            .as_ref()
            .ok_or(AegisError::Uninitialized)?;

        let (next_chain, classic_key) = kdf_chain(chain.expose_secret())?;
        let message_key = mix(&classic_key, post_quantum)?;

        let header = Header {
            ratchet_key: self.our_ratchet.public_key().as_bytes(),
            previous_length: self.previous_sending_length,
            number: self.sent_count,
        };
        let header_bytes = header.to_bytes();

        let payload = seal(&message_key, plaintext.expose(), &header_bytes)?;

        // Состояние меняется только после успешного шифрования: при ошибке
        // цепочка не должна оказаться продвинутой.
        self.sending_chain = Some(Secret::new(next_chain));
        self.sent_count = self.sent_count.saturating_add(1);

        let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(payload.len()));
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&payload);

        Ok(Ciphertext::new(out))
    }

    /// Расшифровывает сообщение, продвигая состояние.
    ///
    /// Обрабатывает три случая: сообщение из уже пройденной цепочки (ключ
    /// лежит среди пропущенных), сообщение после смены ratchet-ключа
    /// (выполняется шаг DH-храповика) и обычное сообщение текущей цепочки.
    ///
    /// # Errors
    ///
    /// * [`AegisError::Malformed`] — сообщение короче заголовка.
    /// * [`AegisError::TooManySkippedMessages`] — номер сообщения требует
    ///   вычислить больше [`MAX_SKIPPED_MESSAGE_KEYS`] ключей. Без этой
    ///   проверки сообщение со счётчиком `u32::MAX` заняло бы клиент
    ///   миллиардами операций HMAC (раздел 6.3 плана).
    /// * [`AegisError::Crypto`] — тег AEAD не сошёлся либо сбой KDF.
    pub fn decrypt(&mut self, ciphertext: &Ciphertext, now: Timestamp) -> Result<Plaintext> {
        self.decrypt_hybrid(ciphertext, None, now)
    }

    /// Расшифровывает сообщение, подмешивая пост-квантовый секрет.
    ///
    /// Зеркало [`RatchetState::encrypt_hybrid`]: та же комбинация обеих
    /// составляющих. Расхождение в пост-квантовой половине приводит к отказу
    /// проверки тега AEAD, а не к тихой расшифровке неверным ключом.
    ///
    /// # Errors
    ///
    /// Те же, что у [`RatchetState::decrypt`], плюс сбой объединения ключей.
    pub fn decrypt_hybrid(
        &mut self,
        ciphertext: &Ciphertext,
        post_quantum: Option<&[u8; 32]>,
        now: Timestamp,
    ) -> Result<Plaintext> {
        let bytes = ciphertext.as_bytes();
        let header = Header::parse(bytes)?;
        let payload = bytes.get(HEADER_LEN..).ok_or(AegisError::Malformed)?;
        let header_bytes = header.to_bytes();

        self.expire_skipped(now);

        // Случай 1: ключ уже вычислен и отложен как пропущенный.
        if let Some(plaintext) = self.try_skipped(&header, payload, &header_bytes, post_quantum)? {
            return Ok(plaintext);
        }

        // Случай 2: собеседник сменил ratchet-ключ — шаг DH-храповика.
        // Пропущенный хвост прежней цепочки досчитывается до перехода.
        let their_ratchet = X25519PublicKey::from_bytes(header.ratchet_key)?;
        let is_new_ratchet = self
            .their_ratchet
            .as_ref()
            .is_none_or(|current| current.as_bytes() != header.ratchet_key);

        if is_new_ratchet {
            self.skip_to(header.previous_length, now)?;
            self.dh_ratchet(&their_ratchet, now)?;
        }

        // Случай 3: обычное сообщение текущей цепочки. Всё, что до него, —
        // пропущено и откладывается.
        self.skip_to(header.number, now)?;

        let chain = self
            .receiving_chain
            .as_ref()
            .ok_or(AegisError::SessionNotFound)?;
        let (next_chain, classic_key) = kdf_chain(chain.expose_secret())?;
        let message_key = mix(&classic_key, post_quantum)?;

        let plaintext = open(&message_key, payload, &header_bytes)?;

        self.receiving_chain = Some(Secret::new(next_chain));
        self.received_count = self.received_count.saturating_add(1);

        Ok(Plaintext::new(plaintext))
    }

    /// Число отложенных ключей пропущенных сообщений.
    #[must_use]
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    /// Сериализует состояние для записи в хранилище.
    ///
    /// # Формат
    ///
    /// ```text
    /// root_key(32) ‖ флаги(1) ‖ [sending_chain(32)] ‖ [receiving_chain(32)]
    ///   ‖ our_ratchet(32) ‖ [their_ratchet(32)]
    ///   ‖ sent(4) ‖ received(4) ‖ previous(4)
    ///   ‖ skipped_count(4) ‖ { ratchet_key(32) ‖ number(4) ‖ key(32) ‖ ts(8) }*
    /// ```
    ///
    /// Формат самоописывающийся: байт флагов сообщает, какие
    /// необязательные поля присутствуют, поэтому разбор не зависит
    /// от внешних предположений о длине.
    ///
    /// # Безопасность
    ///
    /// Результат содержит **весь** ключевой материал сессии. Хранилище
    /// обязано записывать его только в зашифрованном виде (раздел 11 плана) —
    /// поэтому он и обёрнут в [`Secret`] внутри [`SessionState`].
    #[must_use]
    pub fn serialize(&self) -> SessionState {
        let mut out: Vec<u8> = Vec::with_capacity(160);

        let flags = u8::from(self.sending_chain.is_some())
            | (u8::from(self.receiving_chain.is_some()) << 1)
            | (u8::from(self.their_ratchet.is_some()) << 2);

        out.extend_from_slice(self.root_key.expose_secret());
        out.push(flags);

        if let Some(chain) = self.sending_chain.as_ref() {
            out.extend_from_slice(chain.expose_secret());
        }
        if let Some(chain) = self.receiving_chain.as_ref() {
            out.extend_from_slice(chain.expose_secret());
        }

        out.extend_from_slice(self.our_ratchet.expose_secret().expose_secret());
        if let Some(their) = self.their_ratchet.as_ref() {
            out.extend_from_slice(their.as_bytes().as_bytes());
        }

        out.extend_from_slice(&self.sent_count.to_be_bytes());
        out.extend_from_slice(&self.received_count.to_be_bytes());
        out.extend_from_slice(&self.previous_sending_length.to_be_bytes());

        let skipped_count = u32::try_from(self.skipped.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&skipped_count.to_be_bytes());

        for (id, entry) in &self.skipped {
            out.extend_from_slice(&id.ratchet_key);
            out.extend_from_slice(&id.number.to_be_bytes());
            out.extend_from_slice(entry.material.expose_secret());
            out.extend_from_slice(&entry.stored_at.as_millis().to_be_bytes());
        }

        SessionState::from_serialized(Secret::new(out))
    }

    /// Восстанавливает состояние из сохранённого представления.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — данные короче ожидаемого либо повреждены.
    /// Собственная база — доверенный источник, но повреждение файла
    /// не должно приводить к панике.
    pub fn deserialize(state: &SessionState) -> Result<Self> {
        let bytes = state.serialized().expose_secret();
        let mut reader = Reader::new(bytes);

        let root_key = reader.take_array::<32>()?;
        let flags = reader.take_byte()?;

        let sending_chain = if flags & 0b001 != 0 {
            Some(Secret::new(reader.take_array::<32>()?))
        } else {
            None
        };
        let receiving_chain = if flags & 0b010 != 0 {
            Some(Secret::new(reader.take_array::<32>()?))
        } else {
            None
        };

        let our_ratchet = X25519PrivateKey::from_bytes(aegis_types::PrivateKeyBytes::new(
            reader.take_array::<32>()?,
        ))?;
        let their_ratchet = if flags & 0b100 != 0 {
            Some(X25519PublicKey::from_bytes(PublicKeyBytes::new(
                reader.take_array::<32>()?,
            ))?)
        } else {
            None
        };

        let sent_count = u32::from_be_bytes(reader.take_array::<4>()?);
        let received_count = u32::from_be_bytes(reader.take_array::<4>()?);
        let previous_sending_length = u32::from_be_bytes(reader.take_array::<4>()?);

        let skipped_count = u32::from_be_bytes(reader.take_array::<4>()?);
        let mut skipped = HashMap::new();
        for _ in 0..skipped_count {
            let ratchet_key = reader.take_array::<32>()?;
            let number = u32::from_be_bytes(reader.take_array::<4>()?);
            let material = Secret::new(reader.take_array::<32>()?);
            let stored_at = Timestamp::from_millis(i64::from_be_bytes(reader.take_array::<8>()?));

            skipped.insert(
                SkippedKeyId {
                    ratchet_key,
                    number,
                },
                SkippedKey {
                    material,
                    stored_at,
                },
            );
        }

        Ok(Self {
            root_key: Secret::new(root_key),
            sending_chain,
            receiving_chain,
            our_ratchet,
            their_ratchet,
            sent_count,
            received_count,
            previous_sending_length,
            skipped,
        })
    }

    /// Пытается расшифровать сообщение отложенным ключом.
    ///
    /// Ключ ищется по точному совпадению ratchet-ключа и номера — в отличие
    /// от первой редакции, где брался произвольный ключ из хранилища, и
    /// расшифровка зависела от порядка обхода `HashMap`.
    fn try_skipped(
        &mut self,
        header: &Header,
        payload: &[u8],
        aad: &[u8],
        post_quantum: Option<&[u8; 32]>,
    ) -> Result<Option<Plaintext>> {
        let id = SkippedKeyId {
            ratchet_key: *header.ratchet_key.as_bytes(),
            number: header.number,
        };

        let Some(entry) = self.skipped.get(&id) else {
            return Ok(None);
        };

        // Откладывается классическая половина: пост-квантовая подмешивается
        // здесь же, чтобы отложенный ключ подчинялся тому же правилу, что и
        // ключ обычного сообщения.
        let classic_key = Zeroizing::new(*entry.material.expose_secret());
        let message_key = mix(&classic_key, post_quantum)?;
        let plaintext = open(&message_key, payload, aad)?;

        // Ключ расходуется: повторное использование означало бы приём
        // одного и того же сообщения дважды.
        self.skipped.remove(&id);

        Ok(Some(Plaintext::new(plaintext)))
    }

    /// Досчитывает цепочку приёма до указанного номера, откладывая ключи.
    ///
    /// # Errors
    ///
    /// [`AegisError::TooManySkippedMessages`] — требуется больше
    /// [`MAX_SKIPPED_MESSAGE_KEYS`] шагов.
    fn skip_to(&mut self, target: u32, now: Timestamp) -> Result<()> {
        let Some(chain) = self.receiving_chain.as_ref() else {
            // Цепочки ещё нет — пропускать нечего.
            return Ok(());
        };

        let Some(gap) = target.checked_sub(self.received_count) else {
            // Номер меньше текущего: это либо повтор, либо сообщение,
            // чей ключ уже израсходован. Досчитывать нечего.
            return Ok(());
        };

        if gap > MAX_SKIPPED_MESSAGE_KEYS {
            return Err(AegisError::TooManySkippedMessages);
        }

        let Some(their_ratchet) = self.their_ratchet.as_ref() else {
            return Ok(());
        };
        let ratchet_key = *their_ratchet.as_bytes().as_bytes();

        let mut current = Zeroizing::new(*chain.expose_secret());

        for _ in 0..gap {
            let (next_chain, message_key) = kdf_chain(&current)?;

            self.skipped.insert(
                SkippedKeyId {
                    ratchet_key,
                    number: self.received_count,
                },
                SkippedKey {
                    material: Secret::new(*message_key),
                    stored_at: now,
                },
            );

            current = Zeroizing::new(next_chain);
            self.received_count = self.received_count.saturating_add(1);
        }

        self.receiving_chain = Some(Secret::new(*current));
        self.enforce_skipped_limit();

        Ok(())
    }

    /// Выполняет шаг внешнего (DH) храповика.
    ///
    /// Корневой ключ обновляется дважды: сначала выводится цепочка приёма
    /// на ключе собеседника, затем генерируется наша новая пара и выводится
    /// цепочка отправки. Именно двойное обновление даёт post-compromise
    /// security — утёкшее состояние перестаёт подходить, как только каждая
    /// сторона сделала по шагу.
    fn dh_ratchet(&mut self, their_ratchet: &X25519PublicKey, now: Timestamp) -> Result<()> {
        self.their_ratchet = Some(*their_ratchet);

        // Цепочка приёма — на нашем текущем ключе.
        let dh_receive = Zeroizing::new(self.our_ratchet.diffie_hellman(their_ratchet));
        let (root_key, receiving_chain) = kdf_root(self.root_key.expose_secret(), &dh_receive)?;
        self.root_key = Secret::new(root_key);
        self.receiving_chain = Some(Secret::new(receiving_chain));
        self.received_count = 0;

        // Наша новая пара и цепочка отправки на ней.
        //
        // Источник случайности здесь не инъектируется намеренно: шаг
        // храповика происходит внутри `decrypt`, у которого нет параметра
        // rng, а протаскивать его через всю цепочку вызовов ради одной
        // генерации значило бы усложнить контракт. Детерминизм тестов от
        // этого не страдает: проверяется совпадение расшифровки, а не
        // конкретное значение ключа.
        let new_ratchet = X25519PrivateKey::generate(&mut rand_core::OsRng);
        let dh_send = Zeroizing::new(new_ratchet.diffie_hellman(their_ratchet));
        let (root_key, sending_chain) = kdf_root(self.root_key.expose_secret(), &dh_send)?;

        self.root_key = Secret::new(root_key);
        self.sending_chain = Some(Secret::new(sending_chain));
        self.our_ratchet = new_ratchet;
        self.previous_sending_length = self.sent_count;
        self.sent_count = 0;

        self.expire_skipped(now);

        Ok(())
    }

    /// Удаляет пропущенные ключи, пережившие TTL.
    ///
    /// Ключ, для которого сообщение так и не пришло, уничтожается через
    /// [`SKIPPED_KEY_TTL_DAYS`] дней: хранить ключевой материал бесконечно
    /// означает бесконечно расширять окно компрометации.
    fn expire_skipped(&mut self, now: Timestamp) {
        self.skipped.retain(|_, entry| {
            let age = now.as_millis().saturating_sub(entry.stored_at.as_millis());

            age <= SKIPPED_KEY_TTL_MILLIS
        });
    }

    /// Ограничивает общий объём хранилища пропущенных ключей.
    ///
    /// Верхняя граница — [`MAX_SKIPPED_MESSAGE_KEYS`] × [`MAX_SKIPPED_CHAINS`].
    /// При переполнении удаляются самые старые записи: без этого собеседник,
    /// шлющий сообщения с растущими номерами, наращивал бы наше потребление
    /// памяти без предела.
    fn enforce_skipped_limit(&mut self) {
        let limit = (MAX_SKIPPED_MESSAGE_KEYS as usize).saturating_mul(MAX_SKIPPED_CHAINS as usize);

        if self.skipped.len() <= limit {
            return;
        }

        let mut entries: Vec<(SkippedKeyId, i64)> = self
            .skipped
            .iter()
            .map(|(id, entry)| (id.clone(), entry.stored_at.as_millis()))
            .collect();

        entries.sort_by_key(|(_, stored_at)| *stored_at);

        let excess = self.skipped.len().saturating_sub(limit);
        for (id, _) in entries.into_iter().take(excess) {
            self.skipped.remove(&id);
        }
    }
}

/// Шаг корневого ключа: `HKDF(root_key, dh)` → новый корень и ключ цепочки.
///
/// Прежний корень выступает солью, выход DH — входным материалом. Так новый
/// корень зависит и от всей истории сессии, и от свежего DH: компрометация
/// одного из двух не раскрывает результат.
fn kdf_root(root_key: &[u8; 32], dh: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh);
    let mut output = Zeroizing::new([0u8; 64]);

    hkdf.expand(ROOT_KDF_INFO, output.as_mut_slice())
        .map_err(|_| AegisError::Crypto)?;

    let (root, chain) = output.split_at(32);
    let root: [u8; 32] = root.try_into().map_err(|_| AegisError::Crypto)?;
    let chain: [u8; 32] = chain.try_into().map_err(|_| AegisError::Crypto)?;

    Ok((root, chain))
}

/// Шаг цепочки: возвращает следующий chain key и message key.
///
/// Обе величины выводятся из одного chain key, но **разными** константами,
/// поэтому знание message key не даёт следующего chain key и наоборот.
fn kdf_chain(chain_key: &[u8; 32]) -> Result<([u8; 32], Zeroizing<[u8; 32]>)> {
    let next = hmac_step(chain_key, CHAIN_STEP)?;
    let message = hmac_step(chain_key, MESSAGE_STEP)?;

    Ok((*next, message))
}

/// Одно применение HMAC-SHA-256 к ключу цепочки.
fn hmac_step(key: &[u8; 32], step: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    // `new_from_slice` отказывает только на ключе неподходящей длины,
    // а здесь длина фиксирована типом.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| AegisError::Crypto)?;
    mac.update(step);

    let output: [u8; 32] = mac
        .finalize()
        .into_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| AegisError::Crypto)?;

    Ok(Zeroizing::new(output))
}

/// Последовательное чтение из буфера с проверкой границ.
///
/// Существует, чтобы разбор сериализованного состояния не индексировал срез
/// напрямую: правило 4.2 запрещает индексацию, потому что выход за границу —
/// это паника, а повреждённый файл базы не должен ронять приложение.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Считывает `N` байт, продвигая позицию.
    fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.offset.checked_add(N).ok_or(AegisError::Malformed)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(AegisError::Malformed)?;

        self.offset = end;

        slice.try_into().map_err(|_| AegisError::Malformed)
    }

    /// Считывает один байт.
    fn take_byte(&mut self) -> Result<u8> {
        Ok(self.take_array::<1>()?.into_iter().next().unwrap_or(0))
    }
}

/// Подмешивает пост-квантовую составляющую к классическому ключу.
///
/// Без неё (`None`) возвращается классический ключ — так ведёт себя
/// Double Ratchet сам по себе. С ней ключ выводится из обеих половин
/// через [`spqr::combine`], и сообщение становится защищённым гибридно
/// (ADR-021).
fn mix(classic: &[u8; 32], post_quantum: Option<&[u8; 32]>) -> Result<Zeroizing<[u8; 32]>> {
    match post_quantum {
        Some(pq) => spqr::combine(classic, pq),
        None => Ok(Zeroizing::new(*classic)),
    }
}

/// Выводит nonce AEAD из message key.
///
/// Не из счётчика: счётчик обнуляется на каждом шаге DH-храповика, и пара
/// «ключ, nonce» повторилась бы на первом сообщении каждой новой цепочки.
fn derive_nonce(message_key: &[u8; 32]) -> Result<[u8; NONCE_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(None, message_key);
    let mut nonce = [0u8; NONCE_LEN];

    hkdf.expand(NONCE_KDF_INFO, &mut nonce)
        .map_err(|_| AegisError::Crypto)?;

    Ok(nonce)
}

/// Шифрует открытый текст, аутентифицируя заголовок как AAD.
fn seal(message_key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(message_key).map_err(|_| AegisError::Crypto)?;
    let nonce = derive_nonce(message_key)?;

    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AegisError::Crypto)
}

/// Расшифровывает и проверяет тег вместе с заголовком.
fn open(message_key: &[u8; 32], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(message_key).map_err(|_| AegisError::Crypto)?;
    let nonce = derive_nonce(message_key)?;

    cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: payload, aad })
        .map_err(|_| AegisError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    /// Миллисекунд в сутках.
    const DAY_MILLIS: i64 = 24 * 60 * 60 * 1000;

    fn later(days: i64) -> Timestamp {
        let offset = days.saturating_mul(DAY_MILLIS);

        Timestamp::from_millis(now().as_millis().saturating_add(offset))
    }

    /// Поднимает пару связанных сессий.
    ///
    /// Общий секрет приходит из PQXDH; здесь он задан напрямую, потому что
    /// проверяется ratchet, а не обмен.
    fn session_pair() -> (RatchetState, RatchetState) {
        let shared = [7u8; 32];
        let bob_ratchet = X25519PrivateKey::generate(&mut OsRng);
        let bob_public = bob_ratchet.public_key();

        let alice = RatchetState::initiate(&shared, &bob_public, &mut OsRng).unwrap();
        let bob = RatchetState::accept(&shared, bob_ratchet);

        (alice, bob)
    }

    fn encrypt(state: &mut RatchetState, text: &[u8]) -> Ciphertext {
        state.encrypt(&Plaintext::new(text.to_vec())).unwrap()
    }

    /// Копия состояния — то, что получает атакующий при компрометации.
    ///
    /// Отложенные ключи намеренно не копируются: проверяется стойкость
    /// самого храповика, а не то, что вместе с состоянием утекли готовые
    /// message key.
    fn snapshot(state: &RatchetState) -> RatchetState {
        RatchetState {
            root_key: Secret::new(*state.root_key.expose_secret()),
            sending_chain: state
                .sending_chain
                .as_ref()
                .map(|chain| Secret::new(*chain.expose_secret())),
            receiving_chain: state
                .receiving_chain
                .as_ref()
                .map(|chain| Secret::new(*chain.expose_secret())),
            our_ratchet: X25519PrivateKey::from_bytes(state.our_ratchet.expose_secret()).unwrap(),
            their_ratchet: state.their_ratchet,
            sent_count: state.sent_count,
            received_count: state.received_count,
            previous_sending_length: state.previous_sending_length,
            skipped: HashMap::new(),
        }
    }

    #[test]
    fn message_round_trips() {
        let (mut alice, mut bob) = session_pair();

        let ciphertext = encrypt(&mut alice, b"attack at dawn");
        let plaintext = bob.decrypt(&ciphertext, now()).unwrap();

        assert_eq!(plaintext.expose(), b"attack at dawn");
    }

    /// Диалог в обе стороны: каждый ответ вызывает шаг DH-храповика.
    #[test]
    fn conversation_flows_both_ways() {
        let (mut alice, mut bob) = session_pair();

        for round in 0..5u8 {
            let from_alice = encrypt(&mut alice, &[round; 16]);
            assert_eq!(
                bob.decrypt(&from_alice, now()).unwrap().expose(),
                &[round; 16]
            );

            let from_bob = encrypt(&mut bob, &[round.wrapping_add(100); 8]);
            assert_eq!(
                alice.decrypt(&from_bob, now()).unwrap().expose(),
                &[round.wrapping_add(100); 8]
            );
        }
    }

    /// 🔐 Forward secrecy: ключ каждого сообщения свой.
    ///
    /// Два одинаковых открытых текста дают разные шифротексты, потому что
    /// цепочка продвинулась. Совпадение означало бы, что ключ не меняется.
    #[test]
    fn each_message_uses_a_fresh_key() {
        let (mut alice, _bob) = session_pair();

        let first = encrypt(&mut alice, b"same text");
        let second = encrypt(&mut alice, b"same text");

        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    /// 🔐 Сообщения, пришедшие не по порядку, расшифровываются.
    #[test]
    fn out_of_order_delivery_is_handled() {
        let (mut alice, mut bob) = session_pair();

        let first = encrypt(&mut alice, b"one");
        let second = encrypt(&mut alice, b"two");
        let third = encrypt(&mut alice, b"three");

        // Приходит третье, затем первое, затем второе.
        assert_eq!(bob.decrypt(&third, now()).unwrap().expose(), b"three");
        assert_eq!(bob.decrypt(&first, now()).unwrap().expose(), b"one");
        assert_eq!(bob.decrypt(&second, now()).unwrap().expose(), b"two");

        assert_eq!(bob.skipped_count(), 0, "все отложенные ключи израсходованы");
    }

    /// Пропущенные сообщения предыдущей цепочки доходят после смены ключа.
    #[test]
    fn messages_from_previous_chain_still_decrypt() {
        let (mut alice, mut bob) = session_pair();

        let stale = encrypt(&mut alice, b"lost in transit");
        let delivered = encrypt(&mut alice, b"arrived first");

        assert_eq!(
            bob.decrypt(&delivered, now()).unwrap().expose(),
            b"arrived first"
        );

        // Боб отвечает — храповик проворачивается.
        let reply = encrypt(&mut bob, b"reply");
        assert_eq!(alice.decrypt(&reply, now()).unwrap().expose(), b"reply");

        // Отставшее сообщение прежней цепочки всё ещё расшифровывается.
        assert_eq!(
            bob.decrypt(&stale, now()).unwrap().expose(),
            b"lost in transit"
        );
    }

    /// 🔐 Повторное воспроизведение сообщения отвергается.
    ///
    /// Ключ расходуется при первом успешном приёме, поэтому второй раз
    /// то же сообщение расшифровать нечем.
    #[test]
    fn replayed_message_is_rejected() {
        let (mut alice, mut bob) = session_pair();

        let first = encrypt(&mut alice, b"one");
        let second = encrypt(&mut alice, b"two");

        // Принимаем второе — ключ первого откладывается.
        bob.decrypt(&second, now()).unwrap();
        // Принимаем первое — отложенный ключ расходуется.
        bob.decrypt(&first, now()).unwrap();

        assert!(
            bob.decrypt(&first, now()).is_err(),
            "повтор должен отвергаться"
        );
    }

    /// 🔐 `counter = u32::MAX` не вызывает OOM.
    ///
    /// Задача раздела 6.3: без лимита получатель попытался бы вычислить
    /// четыре миллиарда ключей по одному пакету.
    #[test]
    fn huge_counter_is_rejected_without_allocating() {
        let (mut alice, mut bob) = session_pair();

        let mut ciphertext = encrypt(&mut alice, b"payload").into_bytes();
        // Переписываем номер сообщения в заголовке на u32::MAX.
        let number = ciphertext.get_mut(36..40).unwrap();
        number.copy_from_slice(&u32::MAX.to_be_bytes());

        let result = bob.decrypt(&Ciphertext::new(ciphertext), now());

        assert!(matches!(result, Err(AegisError::TooManySkippedMessages)));
        assert_eq!(bob.skipped_count(), 0, "ключи не должны накапливаться");
    }

    /// Лимит пропущенных ключей соблюдается на границе.
    #[test]
    fn skipping_up_to_the_limit_is_allowed() {
        let (mut alice, mut bob) = session_pair();

        // Отправляем ровно столько, чтобы разрыв уперся в лимит.
        let mut last = encrypt(&mut alice, b"first");
        for _ in 0..MAX_SKIPPED_MESSAGE_KEYS {
            last = encrypt(&mut alice, b"filler");
        }

        assert_eq!(bob.decrypt(&last, now()).unwrap().expose(), b"filler");
        assert_eq!(bob.skipped_count(), MAX_SKIPPED_MESSAGE_KEYS as usize);
    }

    /// 🔐 Подмена заголовка отвергается: он аутентифицирован как AAD.
    #[test]
    fn tampered_header_is_rejected() {
        let (mut alice, mut bob) = session_pair();

        let mut ciphertext = encrypt(&mut alice, b"payload").into_bytes();
        // Меняем поле previous_length, не трогая тело сообщения.
        let previous = ciphertext.get_mut(32..36).unwrap();
        previous.copy_from_slice(&7u32.to_be_bytes());

        assert!(matches!(
            bob.decrypt(&Ciphertext::new(ciphertext), now()),
            Err(AegisError::Crypto)
        ));
    }

    /// 🔐 Подмена тела сообщения отвергается тегом AEAD.
    #[test]
    fn tampered_payload_is_rejected() {
        let (mut alice, mut bob) = session_pair();

        let mut ciphertext = encrypt(&mut alice, b"payload").into_bytes();
        let last = ciphertext.len().saturating_sub(1);
        *ciphertext.get_mut(last).unwrap() ^= 0x01;

        assert!(matches!(
            bob.decrypt(&Ciphertext::new(ciphertext), now()),
            Err(AegisError::Crypto)
        ));
    }

    /// Слишком короткое сообщение отвергается, а не паникует.
    #[test]
    fn truncated_message_is_rejected() {
        let (_alice, mut bob) = session_pair();

        assert!(matches!(
            bob.decrypt(&Ciphertext::new(vec![0u8; 12]), now()),
            Err(AegisError::Malformed)
        ));
    }

    /// 🔐 Пропущенные ключи уничтожаются по истечении TTL.
    #[test]
    fn skipped_keys_expire_after_ttl() {
        let (mut alice, mut bob) = session_pair();

        let stale = encrypt(&mut alice, b"never arrives on time");
        let delivered = encrypt(&mut alice, b"arrives");

        bob.decrypt(&delivered, now()).unwrap();
        assert_eq!(bob.skipped_count(), 1);

        // Спустя TTL + сутки ключ уничтожен, сообщение уже не расшифровать.
        let expired_at = later(i64::from(SKIPPED_KEY_TTL_DAYS) + 1);

        assert!(bob.decrypt(&stale, expired_at).is_err());
        assert_eq!(bob.skipped_count(), 0);
    }

    /// Ключ, не доживший до TTL, продолжает работать.
    #[test]
    fn skipped_key_survives_within_ttl() {
        let (mut alice, mut bob) = session_pair();

        let stale = encrypt(&mut alice, b"late but valid");
        let delivered = encrypt(&mut alice, b"first");

        bob.decrypt(&delivered, now()).unwrap();

        let still_valid = later(i64::from(SKIPPED_KEY_TTL_DAYS) - 1);

        assert_eq!(
            bob.decrypt(&stale, still_valid).unwrap().expose(),
            b"late but valid"
        );
    }

    /// Получатель не может отправлять до первого входящего сообщения.
    ///
    /// Это не ошибка использования, а состояние протокола: ratchet-ключ
    /// собеседника ещё неизвестен, выводить цепочку отправки не из чего.
    #[test]
    fn responder_cannot_send_before_first_message() {
        let (_alice, mut bob) = session_pair();

        assert!(matches!(
            bob.encrypt(&Plaintext::new(b"too early".to_vec())),
            Err(AegisError::Uninitialized)
        ));
    }

    /// 🔐 Forward secrecy: захват состояния не раскрывает прошлые сообщения.
    ///
    /// Слепок состояния получателя снимается **после** приёма сообщения.
    /// Атакующий с этим слепком не может расшифровать перехваченный ранее
    /// шифротекст: ключ израсходован и уничтожен, а цепочка необратима —
    /// HMAC не обращается.
    #[test]
    fn compromised_state_does_not_reveal_past_messages() {
        let (mut alice, mut bob) = session_pair();

        let intercepted = encrypt(&mut alice, b"secret from the past");
        bob.decrypt(&intercepted, now()).unwrap();

        // Слепок состояния Боба после приёма — это всё, что получает атакующий.
        let mut captured = snapshot(&bob);

        assert!(
            captured.decrypt(&intercepted, now()).is_err(),
            "прошлое сообщение не должно расшифровываться захваченным состоянием"
        );
    }

    /// 🔐 Post-compromise security: после утечки секретность восстанавливается.
    ///
    /// Атакующий снимает слепок состояния Боба и с этого момента только
    /// наблюдает. Излечение наступает не мгновенно, а когда **обе** стороны
    /// сменили ratchet-ключ: Боб — отвечая, Алиса — приняв его ответ и
    /// отправив следующее сообщение уже на новом ключе. Слепок к этому
    /// моменту содержит приватный ключ, которого нет ни в одном из двух
    /// свежих DH, и расшифровать сообщение им нельзя.
    ///
    /// Тест проверяет обе фазы: до завершения обмена слепок ещё работает
    /// (это не дефект, а определение PCS — окно уязвимости длиной в один
    /// круг), после — уже нет.
    #[test]
    fn state_compromise_heals_after_a_full_round_trip() {
        let (mut alice, mut bob) = session_pair();

        let first = encrypt(&mut alice, b"before compromise");
        bob.decrypt(&first, now()).unwrap();

        // Слепок состояния Боба в момент компрометации. В нём — приватный
        // ratchet-ключ, который Боб сгенерировал, принимая первое сообщение.
        let mut captured = snapshot(&bob);

        // Круг 1. Боб отвечает — на том самом ключе, что попал в слепок.
        // Алиса принимает ответ и проворачивает храповик. Секретность ещё
        // не восстановлена: ключ Боба атакующему известен.
        let from_bob = encrypt(&mut bob, b"bob replies");
        alice.decrypt(&from_bob, now()).unwrap();

        let alice_reply = encrypt(&mut alice, b"still within the window");
        assert!(
            snapshot(&captured).decrypt(&alice_reply, now()).is_ok(),
            "пока Боб не сменил ключ, слепок актуален — это окно PCS"
        );

        // Круг 2. Боб принимает сообщение Алисы и на этом шаге генерирует
        // **новый** ratchet-ключ, которого в слепке нет. Круг замкнулся.
        bob.decrypt(&alice_reply, now()).unwrap();

        let from_bob_healed = encrypt(&mut bob, b"bob on a fresh key");
        alice.decrypt(&from_bob_healed, now()).unwrap();

        let after_healing = encrypt(&mut alice, b"after healing");
        assert_eq!(
            bob.decrypt(&after_healing, now()).unwrap().expose(),
            b"after healing"
        );

        // Слепок устарел: сообщение выведено из DH на ключе, которого в нём нет.
        assert!(
            captured.decrypt(&after_healing, now()).is_err(),
            "после полного обмена компрометация должна быть излечена"
        );
    }

    /// 🔐 Гибридный режим: сообщение расшифровывается только с тем же
    /// пост-квантовым секретом.
    ///
    /// Это проверка того, что SPQR действительно участвует в выводе ключа
    /// сообщения, а не лежит рядом без дела — ровно тот дефект, из-за
    /// которого первая редакция Triple Ratchet не была гибридной.
    #[test]
    fn hybrid_message_requires_matching_pq_secret() {
        let (mut alice, mut bob) = session_pair();
        let pq = [0x5Au8; 32];

        let ciphertext = alice
            .encrypt_hybrid(&Plaintext::new(b"hybrid payload".to_vec()), Some(&pq))
            .unwrap();

        // С верным пост-квантовым секретом — расшифровывается.
        let mut bob_ok = snapshot(&bob);
        assert_eq!(
            bob_ok
                .decrypt_hybrid(&ciphertext, Some(&pq), now())
                .unwrap()
                .expose(),
            b"hybrid payload"
        );

        // С другим — тег AEAD не сходится.
        let wrong = [0x5Bu8; 32];
        assert!(
            bob.decrypt_hybrid(&ciphertext, Some(&wrong), now())
                .is_err(),
            "чужой PQ-секрет не должен подходить"
        );
    }

    /// 🔐 Классического ключа недостаточно в гибридном режиме.
    ///
    /// Противник, сломавший X25519 и получивший классическую половину,
    /// без пост-квантовой половины сообщение не прочитает.
    #[test]
    fn classic_only_cannot_open_hybrid_message() {
        let (mut alice, mut bob) = session_pair();
        let pq = [0x77u8; 32];

        let ciphertext = alice
            .encrypt_hybrid(&Plaintext::new(b"needs both halves".to_vec()), Some(&pq))
            .unwrap();

        assert!(
            bob.decrypt_hybrid(&ciphertext, None, now()).is_err(),
            "без PQ-половины сообщение не должно открываться"
        );
    }

    /// Гибридный режим переживает доставку не по порядку.
    ///
    /// Отложенные ключи хранят классическую половину, а пост-квантовая
    /// подмешивается при использовании — проверяем, что это согласовано.
    #[test]
    fn hybrid_survives_out_of_order_delivery() {
        let (mut alice, mut bob) = session_pair();
        let pq = [0x33u8; 32];

        let first = alice
            .encrypt_hybrid(&Plaintext::new(b"one".to_vec()), Some(&pq))
            .unwrap();
        let second = alice
            .encrypt_hybrid(&Plaintext::new(b"two".to_vec()), Some(&pq))
            .unwrap();
        let third = alice
            .encrypt_hybrid(&Plaintext::new(b"three".to_vec()), Some(&pq))
            .unwrap();

        assert_eq!(
            bob.decrypt_hybrid(&third, Some(&pq), now())
                .unwrap()
                .expose(),
            b"three"
        );
        assert_eq!(
            bob.decrypt_hybrid(&first, Some(&pq), now())
                .unwrap()
                .expose(),
            b"one"
        );
        assert_eq!(
            bob.decrypt_hybrid(&second, Some(&pq), now())
                .unwrap()
                .expose(),
            b"two"
        );
    }

    /// 🔐 Полный Triple Ratchet: связка Double Ratchet и SPQR в диалоге.
    ///
    /// Пост-квантовый храповик проворачивается посреди переписки, и обе
    /// стороны продолжают понимать друг друга уже на новом PQ-секрете.
    #[test]
    fn triple_ratchet_conversation_with_pq_step() {
        use crate::spqr::PqRatchet;

        let (mut alice, mut bob) = session_pair();
        let initial_pq = [0x11u8; 32];
        let mut alice_pq = PqRatchet::new(initial_pq);
        let mut bob_pq = PqRatchet::new(initial_pq);

        // Обмен на начальном пост-квантовом секрете.
        let message = alice
            .encrypt_hybrid(
                &Plaintext::new(b"before pq step".to_vec()),
                Some(alice_pq.secret()),
            )
            .unwrap();
        assert_eq!(
            bob.decrypt_hybrid(&message, Some(bob_pq.secret()), now())
                .unwrap()
                .expose(),
            b"before pq step"
        );

        // Пост-квантовый шаг: Алиса объявляет эпоху, Боб отвечает.
        let key_chunks = alice_pq.begin_epoch(&mut OsRng).unwrap();
        let mut ciphertext_chunks = None;
        for chunk in &key_chunks {
            if let Some(reply) = bob_pq.accept_key_chunk(chunk, &mut OsRng).unwrap() {
                ciphertext_chunks = Some(reply);
            }
        }
        for chunk in &ciphertext_chunks.unwrap() {
            alice_pq.accept_ciphertext_chunk(chunk).unwrap();
        }

        assert_eq!(alice_pq.secret(), bob_pq.secret(), "PQ-секреты сошлись");
        assert_ne!(*alice_pq.secret(), initial_pq, "PQ-секрет продвинулся");

        // Переписка продолжается уже на новом пост-квантовом секрете.
        let after = alice
            .encrypt_hybrid(
                &Plaintext::new(b"after pq step".to_vec()),
                Some(alice_pq.secret()),
            )
            .unwrap();
        assert_eq!(
            bob.decrypt_hybrid(&after, Some(bob_pq.secret()), now())
                .unwrap()
                .expose(),
            b"after pq step"
        );

        // Старый пост-квантовый секрет больше не подходит.
        let stale = alice
            .encrypt_hybrid(
                &Plaintext::new(b"stale pq".to_vec()),
                Some(alice_pq.secret()),
            )
            .unwrap();
        assert!(
            bob.decrypt_hybrid(&stale, Some(&initial_pq), now())
                .is_err(),
            "устаревший PQ-секрет не должен подходить"
        );
    }

    /// Состояние переживает сохранение и загрузку.
    ///
    /// Сессия должна продолжаться после перезапуска приложения: сообщение,
    /// зашифрованное восстановленным состоянием, обязано расшифровываться.
    #[test]
    fn state_survives_serialization() {
        let (mut alice, mut bob) = session_pair();

        // Немного продвигаем состояние, чтобы сохранялись не нули.
        let warmup = encrypt(&mut alice, b"warm up");
        bob.decrypt(&warmup, now()).unwrap();

        let saved = alice.serialize();
        let mut restored = RatchetState::deserialize(&saved).unwrap();

        let ciphertext = encrypt(&mut restored, b"after reload");

        assert_eq!(
            bob.decrypt(&ciphertext, now()).unwrap().expose(),
            b"after reload"
        );
    }

    /// Отложенные ключи переживают сохранение.
    ///
    /// Иначе после перезапуска пропущенные сообщения перестали бы
    /// расшифровываться — они хранятся именно в состоянии.
    #[test]
    fn skipped_keys_survive_serialization() {
        let (mut alice, mut bob) = session_pair();

        let stale = encrypt(&mut alice, b"delayed");
        let delivered = encrypt(&mut alice, b"first");
        bob.decrypt(&delivered, now()).unwrap();
        assert_eq!(bob.skipped_count(), 1);

        let saved = bob.serialize();
        let mut restored = RatchetState::deserialize(&saved).unwrap();

        assert_eq!(restored.skipped_count(), 1);
        assert_eq!(
            restored.decrypt(&stale, now()).unwrap().expose(),
            b"delayed"
        );
    }

    /// Повреждённое состояние отвергается, а не паникует.
    #[test]
    fn truncated_state_is_rejected() {
        let (alice, _bob) = session_pair();
        let saved = alice.serialize();

        let mut bytes = saved.serialized().expose_secret().clone();
        bytes.truncate(20);
        let damaged = SessionState::from_serialized(Secret::new(bytes));

        assert!(matches!(
            RatchetState::deserialize(&damaged),
            Err(AegisError::Malformed)
        ));
    }

    /// 🔐 Шаг цепочки необратим и разводит ключи.
    ///
    /// Message key и следующий chain key выводятся разными константами:
    /// совпадение означало бы, что знание одного даёт другой.
    #[test]
    fn chain_step_separates_message_and_chain_keys() {
        let chain_key = [3u8; 32];

        let (next_chain, message_key) = kdf_chain(&chain_key).unwrap();

        assert_ne!(next_chain, *message_key);
        assert_ne!(next_chain, chain_key);
        assert_ne!(*message_key, chain_key);
    }

    /// Nonce выводится из message key, а не из счётчика.
    ///
    /// Разные ключи обязаны давать разные nonce — иначе на первом сообщении
    /// каждой новой цепочки повторилась бы пара «ключ, nonce».
    #[test]
    fn nonce_depends_on_message_key() {
        let first = derive_nonce(&[1u8; 32]).unwrap();
        let second = derive_nonce(&[2u8; 32]).unwrap();

        assert_ne!(first, second);
    }

    /// Состояние не печатает ключевой материал.
    #[test]
    fn state_debug_is_redacted() {
        let (alice, _bob) = session_pair();
        let rendered = format!("{alice:?}");

        assert!(rendered.contains("RatchetState"));
        assert!(!rendered.contains("Secret"));
        assert!(
            !rendered.contains('7'),
            "корневой ключ [7u8; 32] не должен просачиваться"
        );
    }
}

/// Property-based тесты инвариантов храповика.
///
/// Здесь проверяются свойства, которые обязаны держаться при **любом**
/// порядке доставки и любом содержимом сообщений, — то, что примерами
/// покрывается лишь выборочно.
#[cfg(test)]
// Арифметика в генераторах тестовых данных работает на заведомо малых
// числах (длины и индексы из ограниченных диапазонов). Послабления
// `allow-*-in-tests` из `clippy.toml` на это правило не распространяются.
#[allow(clippy::arithmetic_side_effects)]
mod properties {
    use super::*;
    use proptest::prelude::*;
    use rand_core::OsRng;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn session_pair() -> (RatchetState, RatchetState) {
        let shared = [7u8; 32];
        let bob_ratchet = X25519PrivateKey::generate(&mut OsRng);
        let bob_public = bob_ratchet.public_key();

        let alice = RatchetState::initiate(&shared, &bob_public, &mut OsRng).unwrap();
        let bob = RatchetState::accept(&shared, bob_ratchet);

        (alice, bob)
    }

    proptest! {
        /// Сообщение любого содержимого проходит туда и обратно без искажений.
        #[test]
        fn any_payload_round_trips(payload in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let (mut alice, mut bob) = session_pair();

            let ciphertext = alice.encrypt(&Plaintext::new(payload.clone())).unwrap();
            let decrypted = bob.decrypt(&ciphertext, now()).unwrap();

            prop_assert_eq!(decrypted.expose(), payload.as_slice());
        }

        /// Доставка в произвольном порядке не теряет ни одного сообщения.
        ///
        /// Это главный инвариант обработки out-of-order: сколько отправлено,
        /// столько и прочитано, причём содержимое каждого совпадает
        /// с исходным независимо от того, когда оно пришло.
        #[test]
        fn arbitrary_delivery_order_preserves_all_messages(
            count in 1usize..12,
            rotation in 0usize..12,
        ) {
            let (mut alice, mut bob) = session_pair();

            let messages: Vec<Vec<u8>> = (0..count)
                .map(|i| vec![u8::try_from(i % 251).unwrap(); i + 1])
                .collect();

            let mut ciphertexts: Vec<(usize, Ciphertext)> = messages
                .iter()
                .enumerate()
                .map(|(i, payload)| {
                    (i, alice.encrypt(&Plaintext::new(payload.clone())).unwrap())
                })
                .collect();

            ciphertexts.rotate_left(rotation % count);

            for (index, ciphertext) in &ciphertexts {
                let decrypted = bob.decrypt(ciphertext, now()).unwrap();
                prop_assert_eq!(decrypted.expose(), messages[*index].as_slice());
            }

            // Все отложенные ключи израсходованы: ни одного лишнего
            // не осталось висеть в памяти.
            prop_assert_eq!(bob.skipped_count(), 0);
        }

        /// Каждое сообщение шифруется своим ключом.
        ///
        /// Одинаковый открытый текст, отправленный много раз, обязан давать
        /// попарно различные шифротексты — иначе цепочка не продвигается.
        #[test]
        fn repeated_plaintext_yields_distinct_ciphertexts(count in 2usize..16) {
            let (mut alice, _bob) = session_pair();

            let mut seen: Vec<Vec<u8>> = Vec::with_capacity(count);
            for _ in 0..count {
                let ciphertext = alice
                    .encrypt(&Plaintext::new(b"identical".to_vec()))
                    .unwrap();
                seen.push(ciphertext.into_bytes());
            }

            let mut sorted = seen.clone();
            sorted.sort_unstable();
            sorted.dedup();

            prop_assert_eq!(sorted.len(), seen.len(), "шифротексты повторились");
        }

        /// Порча любого байта сообщения обнаруживается.
        ///
        /// Проверяются и заголовок, и тело, и тег: тег AEAD покрывает
        /// сообщение целиком, поэтому ни одна позиция не должна
        /// проходить незамеченной.
        #[test]
        fn any_single_byte_corruption_is_detected(position in 0usize..64, flip in 1u8..=255) {
            let (mut alice, mut bob) = session_pair();

            let ciphertext = alice
                .encrypt(&Plaintext::new(b"integrity matters".to_vec()))
                .unwrap();
            let mut bytes = ciphertext.into_bytes();

            let index = position % bytes.len();
            if let Some(byte) = bytes.get_mut(index) {
                *byte ^= flip;
            }

            prop_assert!(bob.decrypt(&Ciphertext::new(bytes), now()).is_err());
        }

        /// Расшифровка никогда не паникует на произвольном входе.
        ///
        /// Шифротекст приходит из сети: любая последовательность байт
        /// обязана дать ошибку, а не панику.
        #[test]
        fn decrypt_never_panics_on_arbitrary_input(
            bytes in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let (_alice, mut bob) = session_pair();

            let _ = bob.decrypt(&Ciphertext::new(bytes), now());
        }

        /// Гибридный режим сохраняет свойства при любом порядке доставки.
        ///
        /// Отложенные ключи хранят классическую половину, а пост-квантовая
        /// подмешивается при использовании: свойство обязано держаться
        /// и когда сообщения приходят вразнобой.
        #[test]
        fn hybrid_survives_any_delivery_order(
            count in 1usize..10,
            rotation in 0usize..10,
            pq in any::<[u8; 32]>(),
        ) {
            let (mut alice, mut bob) = session_pair();

            let messages: Vec<Vec<u8>> = (0..count)
                .map(|i| vec![u8::try_from(i % 251).unwrap(); i + 1])
                .collect();

            let mut ciphertexts: Vec<(usize, Ciphertext)> = messages
                .iter()
                .enumerate()
                .map(|(i, payload)| {
                    let ciphertext = alice
                        .encrypt_hybrid(&Plaintext::new(payload.clone()), Some(&pq))
                        .unwrap();
                    (i, ciphertext)
                })
                .collect();

            ciphertexts.rotate_left(rotation % count);

            for (index, ciphertext) in &ciphertexts {
                let decrypted = bob
                    .decrypt_hybrid(ciphertext, Some(&pq), now())
                    .unwrap();
                prop_assert_eq!(decrypted.expose(), messages[*index].as_slice());
            }
        }
    }
}
