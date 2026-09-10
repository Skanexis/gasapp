// SPDX-License-Identifier: Apache-2.0

//! Sealed sender: сокрытие отправителя от сервера (раздел 15.2).
//!
//! # Что видит сервер сейчас и что изменится
//!
//! ```text
//! Без sealed sender:
//!     TO=bob  [конверт]
//!             └─ у первого сообщения сессии внутри лежит
//!                identity_key отправителя ОТКРЫТЫМ ТЕКСТОМ:
//!                без него получатель не проведёт PQXDH.
//!
//! С sealed sender:
//!     TO=bob  [эфемерный ключ][шум]
//!                              └─ внутри: сертификат отправителя
//!                                 и обычный конверт, зашифрованные
//!                                 на identity-ключ получателя.
//! ```
//!
//! 🔐 Ровно это и было утечкой: `Envelope::Initial` несёт
//! `identity_key` открытым, потому что получателю он нужен **до**
//! расшифровки — это половина PQXDH. Сервер, читая его, строит
//! социальный граф, не расшифровав ни одного сообщения.
//!
//! # Как разрывается замкнутый круг
//!
//! Отправитель шифрует конверт **вторым, внешним слоем** — простым
//! ECIES на X25519: эфемерная пара, DH с identity-ключом получателя,
//! HKDF, AEAD. Получатель разворачивает внешний слой своим приватным
//! identity-ключом, достаёт оттуда и сертификат отправителя, и
//! обычный конверт, и дальше всё идёт как прежде.
//!
//! Внешний слой не даёт ни forward secrecy, ни защиты после
//! компрометации — он и не должен: за это отвечает Double Ratchet
//! внутри. Его единственная задача — убрать имя отправителя с
//! конверта, который читает сервер.
//!
//! # Сертификат отправителя
//!
//! Внутри слоя лежит [`SenderCertificate`] — подписанное сервером
//! утверждение «этот identity-ключ принадлежит этому аккаунту».
//! Он нужен по двум причинам:
//!
//! * получатель обязан знать, **кто** написал. Без сертификата
//!   sealed sender превращает переписку в анонимную, а это не то же
//!   самое, что приватная;
//! * жалоба на спам (раздел 15.2) состоит именно в предъявлении
//!   сертификата: получатель раскрывает его серверу, и сервер
//!   получает доказательство, которого сам добыть не мог.
//!
//! ⚠️ Сертификат подписывает сервер, поэтому сервер может выписать
//! поддельный и выдать чужое сообщение за ваше. Защита от этого —
//! не сертификат, а safety number: он считается по identity-ключам
//! и подделку сервером не переживает. Сертификат отвечает на вопрос
//! «какому аккаунту принадлежит ключ», а не «можно ли доверять
//! собеседнику».
//!
//! # Чего sealed sender НЕ скрывает
//!
//! IP-адрес отправителя и время отправки. Это записано в разделе 15.5
//! честно и здесь повторяется, потому что обещание, понятое шире,
//! чем оно есть, опаснее отсутствия обещания. От IP защищает Tor
//! или прокси (ADR-024), а не этот модуль.

use aegis_types::{AegisError, PublicKeyBytes, Result, Secret};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::aead::{hkdf_sha256, KEY_LEN};
use crate::x25519::{X25519PrivateKey, X25519PublicKey};
use crate::xeddsa;

/// Первый байт запечатанного конверта: метка формата вместе с версией.
///
/// # Почему не просто `1`
///
/// Получатель обязан отличить запечатанный конверт от обычного **до**
/// разбора. Обычный начинается с `ENVELOPE_VERSION`, равной единице;
/// совпадение меток означало бы пробовать оба разбора подряд — DH
/// и AEAD на каждом обычном конверте — и надеяться, что тег AEAD
/// разрешит неоднозначность.
///
/// Сервер различие видит и так: конверты приходят по разным маршрутам.
/// Отдельная метка поэтому не сообщает ему ничего нового.
pub const SEALED_VERSION: u8 = 0xA1;

// Совпадение меток сломало бы различение молча, поэтому оно
// запрещено на этапе компиляции, а не тестом.
const _: () = assert!(
    SEALED_VERSION != crate::envelope::ENVELOPE_VERSION,
    "метка запечатанного конверта совпала с версией обычного"
);

/// Запечатан ли конверт.
///
/// Проверяется только метка: подлинность выясняется при
/// разворачивании, и отвечать «да» здесь не значит доверять.
#[must_use]
pub fn is_sealed(raw: &[u8]) -> bool {
    raw.first() == Some(&SEALED_VERSION)
}

/// Версия формата сертификата отправителя.
pub const CERTIFICATE_VERSION: u8 = 1;

/// Длина идентификатора: UUID.
const ID_LEN: usize = 16;

/// Длина публичного ключа X25519.
const KEY_BYTES: usize = 32;

/// Метка HKDF для ключа внешнего слоя.
const INFO_SEAL: &[u8] = b"AEGIS_SEALED_SENDER_v1";

/// Предел размера запечатанного конверта.
///
/// 🔐 Разбор начинается с чтения из сети. Предел не даёт объявленной
/// длине превратиться в попытку выделить гигабайты.
pub const MAX_SEALED_LEN: usize = 1 << 21;

/// Сколько сертификат считается действительным по умолчанию.
///
/// Сутки — из раздела 15.2. Короткий срок означает, что украденный
/// сертификат бесполезен назавтра; длинный избавил бы от ежедневного
/// похода на сервер. Сутки — компромисс, при котором клиент
/// обновляет сертификат раз в день в фоне.
pub const DEFAULT_VALIDITY_MILLIS: i64 = 24 * 60 * 60 * 1000;

/// Сертификат отправителя, подписанный сервером.
///
/// # Что он утверждает
///
/// «Ключ `identity_key` принадлежит аккаунту `account_id`, устройству
/// `device_id`, и это верно до `expires_at`.» Больше ничего: ни имени
/// пользователя, ни списка контактов, ни прав.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderCertificate {
    /// Аккаунт отправителя.
    pub account_id: [u8; ID_LEN],
    /// Устройство отправителя.
    pub device_id: [u8; ID_LEN],
    /// Identity-ключ, которому выдан сертификат.
    pub identity_key: PublicKeyBytes,
    /// Момент истечения в миллисекундах.
    pub expires_at_millis: i64,
    /// Подпись сервера над всем, что выше.
    pub signature: [u8; xeddsa::SIGNATURE_LEN],
}

impl SenderCertificate {
    /// Собирает байты, которые подписывает сервер.
    ///
    /// Отдельная функция, а не часть [`Self::to_bytes`]: подписываемое
    /// и передаваемое обязаны совпадать байт в байт, и держать их
    /// в двух местах значит однажды разойтись.
    #[must_use]
    pub fn signed_payload(
        account_id: &[u8; ID_LEN],
        device_id: &[u8; ID_LEN],
        identity_key: &PublicKeyBytes,
        expires_at_millis: i64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + ID_LEN + ID_LEN + KEY_BYTES + 8);

        // Версия входит в подпись: иначе сертификат следующей версии
        // с другим смыслом полей прошёл бы проверку этой.
        out.push(CERTIFICATE_VERSION);
        out.extend_from_slice(account_id);
        out.extend_from_slice(device_id);
        out.extend_from_slice(identity_key.as_bytes());
        out.extend_from_slice(&expires_at_millis.to_be_bytes());

        out
    }

    /// Проверяет подпись сервера и срок действия.
    ///
    /// # Errors
    ///
    /// [`AegisError::InvalidSignature`] — подпись не сходится;
    /// [`AegisError::Malformed`] — сертификат просрочен.
    pub fn verify(&self, server_key: &PublicKeyBytes, now_millis: i64) -> Result<()> {
        let payload = Self::signed_payload(
            &self.account_id,
            &self.device_id,
            &self.identity_key,
            self.expires_at_millis,
        );

        xeddsa::montgomery::verify(server_key, &payload, &self.signature)
            .map_err(|_| AegisError::InvalidSignature)?;

        // 🔐 Срок проверяется после подписи: иначе «просрочен»
        // отличалось бы по времени ответа от «подделан», и это
        // говорило бы атакующему, попал ли он в формат.
        if now_millis >= self.expires_at_millis {
            return Err(AegisError::Malformed);
        }

        Ok(())
    }

    /// Сериализует сертификат.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Self::signed_payload(
            &self.account_id,
            &self.device_id,
            &self.identity_key,
            self.expires_at_millis,
        );
        out.extend_from_slice(&self.signature);

        out
    }

    /// Разбирает сертификат.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — незнакомая версия, неверная длина
    /// либо лишний хвост.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let expected = 1 + ID_LEN + ID_LEN + KEY_BYTES + 8 + xeddsa::SIGNATURE_LEN;

        if raw.len() != expected {
            return Err(AegisError::Malformed);
        }

        let mut offset = 0usize;

        if take(raw, &mut offset, 1)?.first() != Some(&CERTIFICATE_VERSION) {
            return Err(AegisError::Malformed);
        }

        let account_id = take_array::<ID_LEN>(raw, &mut offset)?;
        let device_id = take_array::<ID_LEN>(raw, &mut offset)?;
        let identity_key = PublicKeyBytes::new(take_array::<KEY_BYTES>(raw, &mut offset)?);
        let expires_at_millis = i64::from_be_bytes(take_array::<8>(raw, &mut offset)?);
        let signature = take_array::<{ xeddsa::SIGNATURE_LEN }>(raw, &mut offset)?;

        Ok(Self {
            account_id,
            device_id,
            identity_key,
            expires_at_millis,
            signature,
        })
    }
}

/// Что лежит внутри запечатанного конверта после расшифровки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedContents {
    /// Сертификат отправителя.
    pub certificate: SenderCertificate,
    /// Обычный конверт — тот же, что ходил бы без sealed sender.
    pub envelope: Vec<u8>,
}

/// Запечатывает конверт на identity-ключ получателя.
///
/// # Что получает сервер
///
/// Эфемерный публичный ключ и шифротекст. Эфемерный ключ случаен
/// и меняется на каждом сообщении, поэтому связать два сообщения
/// одного отправителя по нему нельзя.
///
/// # Errors
///
/// [`AegisError::Malformed`] — конверт длиннее допустимого;
/// [`AegisError::Crypto`] — сбой вывода ключа или шифрования.
pub fn seal<R: RngCore + CryptoRng>(
    recipient_identity: &PublicKeyBytes,
    certificate: &SenderCertificate,
    envelope: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let recipient = X25519PublicKey::from_bytes(*recipient_identity)?;

    // Эфемерная пара на каждое сообщение: постоянная связала бы
    // сообщения одного отправителя между собой, и sealed sender
    // скрывал бы имя, но не сам факт «это опять он».
    let ephemeral = X25519PrivateKey::generate(rng);
    let ephemeral_public = ephemeral.public_key().as_bytes();

    let shared = Zeroizing::new(ephemeral.diffie_hellman(&recipient));
    let key = derive_key(&shared, &ephemeral_public, recipient_identity)?;

    let mut plaintext = Vec::new();
    let certificate_bytes = certificate.to_bytes();
    let length =
        u32::try_from(certificate_bytes.len()).map_err(|_| AegisError::Malformed)?;
    plaintext.extend_from_slice(&length.to_be_bytes());
    plaintext.extend_from_slice(&certificate_bytes);
    plaintext.extend_from_slice(envelope);

    // AAD — эфемерный ключ: он лежит открытым, и без привязки его
    // можно было бы подменить, оставив шифротекст прежним.
    let ciphertext = crate::aead::seal_with_key(
        key.expose_secret(),
        &nonce_from(&ephemeral_public),
        &plaintext,
        ephemeral_public.as_bytes(),
    )?;

    // Ёмкость считается с насыщением: это подсказка аллокатору,
    // и переполнение здесь не должно ронять отправку.
    let capacity = ciphertext
        .len()
        .saturating_add(KEY_BYTES)
        .saturating_add(1);
    let mut out = Vec::with_capacity(capacity);
    out.push(SEALED_VERSION);
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&ciphertext);

    if out.len() > MAX_SEALED_LEN {
        return Err(AegisError::Malformed);
    }

    Ok(out)
}

/// Разворачивает запечатанный конверт приватным identity-ключом.
///
/// Возвращает сертификат и внутренний конверт. **Подпись сертификата
/// здесь не проверяется** — это делает вызывающий, у которого есть
/// ключ сервера и часы: см. [`SenderCertificate::verify`].
///
/// # Errors
///
/// [`AegisError::Malformed`] — незнакомая версия, обрыв данных
/// либо неразбираемый сертификат;
/// [`AegisError::Crypto`] — тег не сходится: конверт не нам либо
/// изменён.
pub fn unseal(recipient_private: &X25519PrivateKey, raw: &[u8]) -> Result<SealedContents> {
    if raw.len() > MAX_SEALED_LEN {
        return Err(AegisError::Malformed);
    }

    let mut offset = 0usize;

    if take(raw, &mut offset, 1)?.first() != Some(&SEALED_VERSION) {
        return Err(AegisError::Malformed);
    }

    let ephemeral_public = PublicKeyBytes::new(take_array::<KEY_BYTES>(raw, &mut offset)?);
    let ciphertext = raw.get(offset..).ok_or(AegisError::Malformed)?;

    let ephemeral = X25519PublicKey::from_bytes(ephemeral_public)?;
    let recipient_public = recipient_private.public_key().as_bytes();

    let shared = Zeroizing::new(recipient_private.diffie_hellman(&ephemeral));
    let key = derive_key(&shared, &ephemeral_public, &recipient_public)?;

    let plaintext = crate::aead::open_with_key(
        key.expose_secret(),
        &nonce_from(&ephemeral_public),
        ciphertext,
        ephemeral_public.as_bytes(),
    )?;

    let mut inner = 0usize;
    let length = usize::try_from(u32::from_be_bytes(take_array::<4>(&plaintext, &mut inner)?))
        .map_err(|_| AegisError::Malformed)?;

    let certificate_bytes = take(&plaintext, &mut inner, length)?;
    let certificate = SenderCertificate::from_bytes(certificate_bytes)?;
    let envelope = plaintext.get(inner..).ok_or(AegisError::Malformed)?.to_vec();

    Ok(SealedContents {
        certificate,
        envelope,
    })
}

/// Выводит ключ внешнего слоя.
///
/// 🔐 В HKDF входит не только общий секрет, но и оба публичных
/// ключа. Без этого один и тот же секрет давал бы один ключ в
/// разных контекстах, и шифротекст, снятый с одного получателя,
/// можно было бы переадресовать другому.
fn derive_key(
    shared: &[u8; 32],
    ephemeral_public: &PublicKeyBytes,
    recipient_public: &PublicKeyBytes,
) -> Result<Secret<[u8; KEY_LEN]>> {
    let mut salt = Vec::with_capacity(KEY_BYTES * 2);
    salt.extend_from_slice(ephemeral_public.as_bytes());
    salt.extend_from_slice(recipient_public.as_bytes());

    let mut key = [0u8; KEY_LEN];
    hkdf_sha256(Some(&salt), shared, INFO_SEAL, &mut key)?;

    Ok(Secret::new(key))
}

/// Выводит nonce из эфемерного ключа.
///
/// 🔐 Пара «ключ, nonce» уникальна по построению: ключ выводится
/// из эфемерной пары, которая своя у каждого сообщения. Брать nonce
/// случайным было бы не хуже, но лишний источник случайности —
/// лишнее место, где можно ошибиться.
fn nonce_from(ephemeral_public: &PublicKeyBytes) -> [u8; crate::aead::NONCE_LEN] {
    let mut nonce = [0u8; crate::aead::NONCE_LEN];

    // Первые 12 байт эфемерного ключа: он случаен целиком, поэтому
    // любая его часть случайна.
    if let Some(head) = ephemeral_public.as_bytes().get(..crate::aead::NONCE_LEN) {
        nonce.copy_from_slice(head);
    }

    nonce
}

/// Читает `count` байт, двигая смещение.
fn take<'a>(raw: &'a [u8], offset: &mut usize, count: usize) -> Result<&'a [u8]> {
    let end = offset.checked_add(count).ok_or(AegisError::Malformed)?;
    let slice = raw.get(*offset..end).ok_or(AegisError::Malformed)?;
    *offset = end;

    Ok(slice)
}

/// Читает массив фиксированной длины.
fn take_array<const N: usize>(raw: &[u8], offset: &mut usize) -> Result<[u8; N]> {
    take(raw, offset, N)?
        .try_into()
        .map_err(|_| AegisError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Опознавательная строка внутреннего конверта.
    const ENVELOPE_CANARY: &[u8] = b"INNER-ENVELOPE-CANARY";

    /// Сообщение вектора совместимости с сервером.
    const COMPAT_MESSAGE: &[u8] = b"AEGIS-XEDDSA-COMPAT-VECTOR";

    /// Публичный ключ вектора: X25519 от приватного `[0x42; 32]`.
    const COMPAT_PUBLIC: &str =
        "132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472";

    /// Подпись вектора, посчитанная обеими реализациями.
    const COMPAT_SIGNATURE: &str = concat!(
        "ceae352e11a23afc289a10bf73dc429921f32a13c3bf7c358309ab273fb0d8d9",
        "97a46641a0abd6c77cd64f571dc6d81c4778eb0fb07f29edfb5214184942380e",
    );

    /// Разбирает hex-строку вектора в массив.
    fn hex_to_array<const N: usize>(text: &str) -> Option<[u8; N]> {
        let bytes = hex::decode(text).ok()?;

        <[u8; N]>::try_from(bytes.as_slice()).ok()
    }

    fn server_key() -> (aegis_types::PrivateKeyBytes, PublicKeyBytes) {
        let private = X25519PrivateKey::generate(&mut OsRng);
        let public = xeddsa::montgomery::public_key(&private.expose_secret()).expect("ключ");

        (private.expose_secret(), public)
    }

    fn certificate_for(
        identity: &PublicKeyBytes,
        server_private: &aegis_types::PrivateKeyBytes,
        expires_at_millis: i64,
    ) -> SenderCertificate {
        let account_id = [7u8; ID_LEN];
        let device_id = [9u8; ID_LEN];

        let payload = SenderCertificate::signed_payload(
            &account_id,
            &device_id,
            identity,
            expires_at_millis,
        );
        let signature = xeddsa::montgomery::sign(server_private, &payload).expect("подпись");

        SenderCertificate {
            account_id,
            device_id,
            identity_key: *identity,
            expires_at_millis,
            signature,
        }
    }

    fn now() -> i64 {
        1_760_000_000_000
    }

    /// Запечатанный конверт разворачивается получателем.
    #[test]
    fn sealed_envelope_round_trips() {
        let (server_private, server_public) = server_key();
        let sender = X25519PrivateKey::generate(&mut OsRng);
        let recipient = X25519PrivateKey::generate(&mut OsRng);

        let certificate = certificate_for(
            &sender.public_key().as_bytes(),
            &server_private,
            now() + DEFAULT_VALIDITY_MILLIS,
        );

        let sealed = seal(
            &recipient.public_key().as_bytes(),
            &certificate,
            ENVELOPE_CANARY,
            &mut OsRng,
        )
        .expect("запечатывание");

        let opened = unseal(&recipient, &sealed).expect("разворачивание");

        assert_eq!(opened.envelope, ENVELOPE_CANARY);
        assert_eq!(opened.certificate, certificate);
        opened
            .certificate
            .verify(&server_public, now())
            .expect("сертификат действителен");
    }

    /// 🔐 Главное свойство: identity-ключ отправителя не виден в сети.
    ///
    /// Ровно эта утечка и была: `Envelope::Initial` несёт его
    /// открытым текстом, потому что получателю он нужен до
    /// расшифровки.
    #[test]
    fn sender_identity_is_not_visible_on_the_wire() {
        let (server_private, _) = server_key();
        let sender = X25519PrivateKey::generate(&mut OsRng);
        let recipient = X25519PrivateKey::generate(&mut OsRng);
        let sender_identity = sender.public_key().as_bytes();

        let certificate = certificate_for(
            &sender_identity,
            &server_private,
            now() + DEFAULT_VALIDITY_MILLIS,
        );

        // Внутренний конверт намеренно содержит identity-ключ
        // отправителя — так выглядит `Envelope::Initial`.
        let mut inner = Vec::new();
        inner.extend_from_slice(sender_identity.as_bytes());
        inner.extend_from_slice(ENVELOPE_CANARY);

        let sealed = seal(
            &recipient.public_key().as_bytes(),
            &certificate,
            &inner,
            &mut OsRng,
        )
        .expect("запечатывание");

        assert!(
            !sealed
                .windows(KEY_BYTES)
                .any(|window| window == sender_identity.as_bytes()),
            "identity-ключ отправителя виден серверу"
        );
        assert!(
            !sealed
                .windows(ENVELOPE_CANARY.len())
                .any(|window| window == ENVELOPE_CANARY),
            "внутренний конверт виден серверу"
        );
    }

    /// 🔐 Чужой получатель конверт не развернёт.
    #[test]
    fn a_foreign_recipient_cannot_unseal() {
        let (server_private, _) = server_key();
        let sender = X25519PrivateKey::generate(&mut OsRng);
        let recipient = X25519PrivateKey::generate(&mut OsRng);
        let stranger = X25519PrivateKey::generate(&mut OsRng);

        let certificate = certificate_for(
            &sender.public_key().as_bytes(),
            &server_private,
            now() + DEFAULT_VALIDITY_MILLIS,
        );

        let sealed = seal(
            &recipient.public_key().as_bytes(),
            &certificate,
            ENVELOPE_CANARY,
            &mut OsRng,
        )
        .expect("запечатывание");

        assert!(matches!(
            unseal(&stranger, &sealed),
            Err(AegisError::Crypto)
        ));
    }

    /// 🔐 Два сообщения одного отправителя не связываются между собой.
    ///
    /// Эфемерная пара своя у каждого: постоянная скрывала бы имя,
    /// но оставляла бы признак «это опять он».
    #[test]
    fn two_messages_are_not_linkable() {
        let (server_private, _) = server_key();
        let sender = X25519PrivateKey::generate(&mut OsRng);
        let recipient = X25519PrivateKey::generate(&mut OsRng);

        let certificate = certificate_for(
            &sender.public_key().as_bytes(),
            &server_private,
            now() + DEFAULT_VALIDITY_MILLIS,
        );

        let first = seal(
            &recipient.public_key().as_bytes(),
            &certificate,
            ENVELOPE_CANARY,
            &mut OsRng,
        )
        .expect("запечатывание");
        let second = seal(
            &recipient.public_key().as_bytes(),
            &certificate,
            ENVELOPE_CANARY,
            &mut OsRng,
        )
        .expect("запечатывание");

        assert_ne!(first, second, "два конверта совпали — эфемерный ключ не случаен");

        // Совпадать не должны и эфемерные ключи, которые лежат открыто.
        assert_ne!(
            first.get(1..1 + KEY_BYTES),
            second.get(1..1 + KEY_BYTES),
            "эфемерный ключ повторился"
        );
    }

    /// 🔐 Порча любого байта обнаруживается.
    #[test]
    fn any_flipped_byte_is_detected() {
        let (server_private, _) = server_key();
        let sender = X25519PrivateKey::generate(&mut OsRng);
        let recipient = X25519PrivateKey::generate(&mut OsRng);

        let certificate = certificate_for(
            &sender.public_key().as_bytes(),
            &server_private,
            now() + DEFAULT_VALIDITY_MILLIS,
        );

        let sealed = seal(
            &recipient.public_key().as_bytes(),
            &certificate,
            ENVELOPE_CANARY,
            &mut OsRng,
        )
        .expect("запечатывание");

        for position in 0..sealed.len() {
            let mut damaged = sealed.clone();
            if let Some(byte) = damaged.get_mut(position) {
                *byte ^= 0xFF;
            }

            assert!(
                unseal(&recipient, &damaged).is_err(),
                "порча байта {position} осталась незамеченной"
            );
        }
    }

    /// 🔐 Сертификат, подписанный не сервером, отвергается.
    #[test]
    fn certificate_signed_by_an_impostor_is_rejected() {
        let (_, server_public) = server_key();
        let (impostor_private, _) = server_key();
        let sender = X25519PrivateKey::generate(&mut OsRng);

        let certificate = certificate_for(
            &sender.public_key().as_bytes(),
            &impostor_private,
            now() + DEFAULT_VALIDITY_MILLIS,
        );

        assert!(matches!(
            certificate.verify(&server_public, now()),
            Err(AegisError::InvalidSignature)
        ));
    }

    /// 🔐 Просроченный сертификат отвергается.
    ///
    /// В этом и состоит ротация: украденный сертификат бесполезен
    /// назавтра.
    #[test]
    fn expired_certificate_is_rejected() {
        let (server_private, server_public) = server_key();
        let sender = X25519PrivateKey::generate(&mut OsRng);

        let certificate =
            certificate_for(&sender.public_key().as_bytes(), &server_private, now());

        // Ровно в момент истечения он уже недействителен.
        assert!(matches!(
            certificate.verify(&server_public, now()),
            Err(AegisError::Malformed)
        ));
        assert!(certificate.verify(&server_public, now() - 1).is_ok());
    }

    /// 🔐 Подмена любого поля ломает подпись.
    #[test]
    fn tampering_with_any_field_breaks_the_signature() {
        let (server_private, server_public) = server_key();
        let sender = X25519PrivateKey::generate(&mut OsRng);
        let valid = certificate_for(
            &sender.public_key().as_bytes(),
            &server_private,
            now() + DEFAULT_VALIDITY_MILLIS,
        );

        let with_other_account = SenderCertificate {
            account_id: [8u8; ID_LEN],
            ..valid.clone()
        };
        let with_other_key = SenderCertificate {
            identity_key: PublicKeyBytes::new([0x33u8; KEY_BYTES]),
            ..valid.clone()
        };
        let with_longer_life = SenderCertificate {
            expires_at_millis: valid.expires_at_millis + 1,
            ..valid.clone()
        };

        for forged in [with_other_account, with_other_key, with_longer_life] {
            assert!(
                matches!(
                    forged.verify(&server_public, now()),
                    Err(AegisError::InvalidSignature)
                ),
                "подмена поля прошла проверку"
            );
        }
    }

    /// Сертификат переживает сериализацию.
    #[test]
    fn certificate_round_trips() {
        let (server_private, _) = server_key();
        let sender = X25519PrivateKey::generate(&mut OsRng);
        let certificate = certificate_for(
            &sender.public_key().as_bytes(),
            &server_private,
            now() + DEFAULT_VALIDITY_MILLIS,
        );

        let encoded = certificate.to_bytes();

        assert_eq!(
            SenderCertificate::from_bytes(&encoded).expect("разбор"),
            certificate
        );
    }

    /// Сертификат неверной длины отвергается.
    #[test]
    fn certificate_of_wrong_length_is_rejected() {
        let (server_private, _) = server_key();
        let sender = X25519PrivateKey::generate(&mut OsRng);
        let mut encoded = certificate_for(
            &sender.public_key().as_bytes(),
            &server_private,
            now() + DEFAULT_VALIDITY_MILLIS,
        )
        .to_bytes();

        encoded.push(0);

        assert!(matches!(
            SenderCertificate::from_bytes(&encoded),
            Err(AegisError::Malformed)
        ));
    }

    /// Незнакомая версия сертификата отвергается.
    #[test]
    fn unknown_certificate_version_is_rejected() {
        let (server_private, _) = server_key();
        let sender = X25519PrivateKey::generate(&mut OsRng);
        let mut encoded = certificate_for(
            &sender.public_key().as_bytes(),
            &server_private,
            now() + DEFAULT_VALIDITY_MILLIS,
        )
        .to_bytes();

        if let Some(version) = encoded.first_mut() {
            *version = 99;
        }

        assert!(matches!(
            SenderCertificate::from_bytes(&encoded),
            Err(AegisError::Malformed)
        ));
    }

    /// Обрубок запечатанного конверта не приводит к панике.
    #[test]
    fn truncated_sealed_envelope_never_panics() {
        let (server_private, _) = server_key();
        let sender = X25519PrivateKey::generate(&mut OsRng);
        let recipient = X25519PrivateKey::generate(&mut OsRng);

        let certificate = certificate_for(
            &sender.public_key().as_bytes(),
            &server_private,
            now() + DEFAULT_VALIDITY_MILLIS,
        );
        let sealed = seal(
            &recipient.public_key().as_bytes(),
            &certificate,
            ENVELOPE_CANARY,
            &mut OsRng,
        )
        .expect("запечатывание");

        for length in 0..sealed.len() {
            let slice = sealed.get(..length).expect("срез");

            assert!(unseal(&recipient, slice).is_err(), "обрубок {length} разобрался");
        }
    }

    /// 🔐 Вектор совместимости с сервером.
    ///
    /// Сервер подписывает сертификаты собственной реализацией XEdDSA:
    /// связать серверный workspace (AGPL-3.0) с клиентским
    /// (Apache-2.0) зависимостью нельзя (ADR-006). Две независимые
    /// реализации одного алгоритма расходятся молча, и расхождение
    /// здесь означало бы, что **ни один** сертификат не проверяется,
    /// то есть sealed sender перестаёт работать целиком.
    ///
    /// Тот же вектор проверяется на серверной стороне
    /// (`certificate::tests::client_vector_verifies`). Подпись
    /// детерминированная, поэтому вектор устойчив.
    #[test]
    fn server_compatibility_vector_verifies() {
        let public = PublicKeyBytes::new(
            hex_to_array::<32>(COMPAT_PUBLIC).expect("вектор ключа"),
        );
        let signature = hex_to_array::<64>(COMPAT_SIGNATURE).expect("вектор подписи");

        xeddsa::montgomery::verify(&public, COMPAT_MESSAGE, &signature)
            .expect("подпись сервера обязана проверяться клиентом");
    }

    /// Тот же вектор не проходит по другому сообщению.
    #[test]
    fn compatibility_vector_is_bound_to_its_message() {
        let public = PublicKeyBytes::new(
            hex_to_array::<32>(COMPAT_PUBLIC).expect("вектор ключа"),
        );
        let signature = hex_to_array::<64>(COMPAT_SIGNATURE).expect("вектор подписи");

        assert!(xeddsa::montgomery::verify(&public, b"another message", &signature).is_err());
    }

    /// Обычный конверт не принимается за запечатанный, и наоборот.
    #[test]
    fn plain_and_sealed_envelopes_are_distinguishable() {
        let (server_private, _) = server_key();
        let sender = X25519PrivateKey::generate(&mut OsRng);
        let recipient = X25519PrivateKey::generate(&mut OsRng);

        let plain = crate::envelope::Envelope::Message {
            payload: ENVELOPE_CANARY.to_vec(),
        }
        .to_bytes()
        .expect("конверт");

        let certificate = certificate_for(
            &sender.public_key().as_bytes(),
            &server_private,
            now() + DEFAULT_VALIDITY_MILLIS,
        );
        let sealed = seal(
            &recipient.public_key().as_bytes(),
            &certificate,
            &plain,
            &mut OsRng,
        )
        .expect("запечатывание");

        assert!(!is_sealed(&plain), "обычный конверт принят за запечатанный");
        assert!(is_sealed(&sealed), "запечатанный конверт не опознан");
        assert!(!is_sealed(&[]));
    }

    /// Мусор вместо конверта отвергается, а не разбирается.
    #[test]
    fn garbage_is_rejected() {
        let recipient = X25519PrivateKey::generate(&mut OsRng);

        assert!(unseal(&recipient, b"").is_err());
        assert!(unseal(&recipient, b"not a sealed envelope at all").is_err());
    }
}
