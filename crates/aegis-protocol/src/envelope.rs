// SPDX-License-Identifier: Apache-2.0

//! Формат конверта: то, что реально уходит на сервер.
//!
//! # Зачем отдельный слой поверх шифротекста ратчета
//!
//! Шифротекст Double Ratchet самодостаточен — он несёт собственный
//! заголовок с публичным ключом храповика и счётчиками. Но **первое**
//! сообщение новой сессии получателю расшифровать нечем: он ещё не
//! проводил PQXDH и не знает ни эфемерного ключа отправителя, ни
//! шифротекста ML-KEM, ни того, какие предключи были израсходованы.
//!
//! Конверт добавляет ровно эти данные и ничего больше.
//!
//! # Что видит сервер
//!
//! Сервер видит байты конверта целиком, поэтому всё, что здесь лежит
//! открытым текстом, — это метаданные, доступные оператору. Их состав
//! намеренно минимален: эфемерный ключ, шифротекст KEM и номера
//! предключей. Ни отправителя, ни темы, ни длины исходного текста
//! (её маскирует паддинг уровнем ниже) отсюда получить нельзя.
//!
//! Identity-ключ отправителя передаётся в конверте инициации, потому
//! что без него получатель не может провести свою половину PQXDH. Это
//! неизбежно: получатель обязан знать, с кем устанавливает сессию,
//! иначе аутентификации не существует.
//!
//! # Почему формат ручной, а не serde
//!
//! Разбор идёт над данными из сети, то есть над тем, что полностью
//! контролирует атакующий. Ручной разбор с явной проверкой каждой
//! длины делает поверхность атаки видимой глазами и покрывается
//! фаззингом; производный код serde такой проверки не показывает.

use aegis_types::{AegisError, PublicKeyBytes, Result};

use crate::keys::PreKeyId;

/// Версия формата конверта.
///
/// Первый байт каждого конверта. Получатель, встретивший незнакомую
/// версию, обязан отказаться, а не пытаться разобрать: молчаливый
/// разбор чужого формата — путь к рассинхронизации сессий.
pub const ENVELOPE_VERSION: u8 = 1;

/// Тип конверта: инициация сессии.
const KIND_INITIAL: u8 = 1;

/// Тип конверта: сообщение в установленной сессии.
const KIND_MESSAGE: u8 = 2;

/// Длина X25519-ключа.
const KEY_LEN: usize = 32;

/// Верхняя граница длины шифротекста ML-KEM-1024.
///
/// Настоящий размер фиксирован (1568 байт), но проверка идёт по
/// границе: запас позволяет пережить смену параметров KEM, а защита
/// от переполнения памяти остаётся.
const MAX_KEM_CIPHERTEXT: usize = 4096;

/// Верхняя граница полезной нагрузки.
///
/// Больше этого сообщение не бывает: длинные вложения уходят
/// отдельным каналом чанками. Граница нужна, чтобы конверт с
/// объявленной длиной в четыре гигабайта не приводил к попытке
/// выделить эту память.
const MAX_PAYLOAD: usize = 1 << 20;

/// Конверт, готовый к отправке.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Envelope {
    /// Первое сообщение: несёт данные для PQXDH.
    Initial {
        /// Identity-ключ отправителя: без него получатель не проведёт
        /// свою половину обмена.
        identity_key: PublicKeyBytes,
        /// Эфемерный публичный ключ отправителя.
        ephemeral_key: PublicKeyBytes,
        /// Шифротекст ML-KEM.
        kem_ciphertext: Vec<u8>,
        /// Израсходованный одноразовый предключ X25519, если он был.
        one_time_pre_key_id: Option<PreKeyId>,
        /// Использованный пост-квантовый предключ.
        kem_pre_key_id: PreKeyId,
        /// Был ли использован одноразовый пост-квантовый предключ.
        ///
        /// Отличает одноразовый предключ от подписанного: получатель
        /// ищет приватную часть в разных пулах, и перепутать их значит
        /// не расшифровать сообщение.
        kem_one_time: bool,
        /// Шифротекст Double Ratchet.
        payload: Vec<u8>,
    },
    /// Сообщение в уже установленной сессии.
    Message {
        /// Шифротекст Double Ratchet.
        payload: Vec<u8>,
    },
}

impl Envelope {
    /// Сериализует конверт в байты для отправки.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — поле длиннее допустимого предела.
    /// Отказ на своей стороне лучше, чем отправка конверта, который
    /// получатель обязан отвергнуть.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = vec![ENVELOPE_VERSION];

        match self {
            Self::Initial {
                identity_key,
                ephemeral_key,
                kem_ciphertext,
                one_time_pre_key_id,
                kem_pre_key_id,
                kem_one_time,
                payload,
            } => {
                if kem_ciphertext.len() > MAX_KEM_CIPHERTEXT || payload.len() > MAX_PAYLOAD {
                    return Err(AegisError::Malformed);
                }

                out.push(KIND_INITIAL);
                out.extend_from_slice(identity_key.as_bytes());
                out.extend_from_slice(ephemeral_key.as_bytes());

                // Длины пишутся как u32 в big-endian: сетевой порядок
                // байтов, одинаковый на всех платформах.
                out.extend_from_slice(&u32_len(kem_ciphertext.len())?.to_be_bytes());
                out.extend_from_slice(kem_ciphertext);

                // Признак наличия одноразового предключа отдельным байтом:
                // ноль как «отсутствует» не годится, потому что ноль —
                // допустимый идентификатор.
                match one_time_pre_key_id {
                    Some(id) => {
                        out.push(1);
                        out.extend_from_slice(&id.as_u32().to_be_bytes());
                    }
                    None => out.push(0),
                }

                out.extend_from_slice(&kem_pre_key_id.as_u32().to_be_bytes());
                out.push(u8::from(*kem_one_time));

                out.extend_from_slice(&u32_len(payload.len())?.to_be_bytes());
                out.extend_from_slice(payload);
            }
            Self::Message { payload } => {
                if payload.len() > MAX_PAYLOAD {
                    return Err(AegisError::Malformed);
                }

                out.push(KIND_MESSAGE);
                out.extend_from_slice(&u32_len(payload.len())?.to_be_bytes());
                out.extend_from_slice(payload);
            }
        }

        Ok(out)
    }

    /// Разбирает конверт, пришедший из сети.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — неизвестная версия, неизвестный тип,
    /// обрыв данных или длина, выходящая за границы. Все случаи дают
    /// одну ошибку намеренно: подробный разбор причины отказа
    /// подсказывал бы атакующему, как подобрать корректный конверт.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);

        if reader.take_u8()? != ENVELOPE_VERSION {
            return Err(AegisError::Malformed);
        }

        match reader.take_u8()? {
            KIND_INITIAL => {
                let identity_key = PublicKeyBytes::new(reader.take_array::<KEY_LEN>()?);
                let ephemeral_key = PublicKeyBytes::new(reader.take_array::<KEY_LEN>()?);

                let kem_len = reader.take_u32()? as usize;
                if kem_len > MAX_KEM_CIPHERTEXT {
                    return Err(AegisError::Malformed);
                }
                let kem_ciphertext = reader.take_slice(kem_len)?.to_vec();

                let one_time_pre_key_id = match reader.take_u8()? {
                    0 => None,
                    1 => Some(PreKeyId::new(reader.take_u32()?)),
                    _ => return Err(AegisError::Malformed),
                };

                let kem_pre_key_id = PreKeyId::new(reader.take_u32()?);

                let kem_one_time = match reader.take_u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(AegisError::Malformed),
                };

                let payload_len = reader.take_u32()? as usize;
                if payload_len > MAX_PAYLOAD {
                    return Err(AegisError::Malformed);
                }
                let payload = reader.take_slice(payload_len)?.to_vec();

                // Хвост после объявленных полей означает, что конверт
                // собран не нашим кодом: разбирать его дальше нельзя.
                reader.expect_end()?;

                Ok(Self::Initial {
                    identity_key,
                    ephemeral_key,
                    kem_ciphertext,
                    one_time_pre_key_id,
                    kem_pre_key_id,
                    kem_one_time,
                    payload,
                })
            }
            KIND_MESSAGE => {
                let payload_len = reader.take_u32()? as usize;
                if payload_len > MAX_PAYLOAD {
                    return Err(AegisError::Malformed);
                }
                let payload = reader.take_slice(payload_len)?.to_vec();
                reader.expect_end()?;

                Ok(Self::Message { payload })
            }
            _ => Err(AegisError::Malformed),
        }
    }
}

/// Переводит длину в `u32`, отказывая при переполнении.
fn u32_len(len: usize) -> Result<u32> {
    u32::try_from(len).map_err(|_| AegisError::Malformed)
}

/// Курсор по входным байтам с проверкой границ на каждом шаге.
///
/// Отдельный тип, а не индексация по срезу: `indexing_slicing` запрещён
/// линтами именно потому, что выход за границу на данных из сети — это
/// паника, то есть отказ в обслуживании.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(len).ok_or(AegisError::Malformed)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(AegisError::Malformed)?;

        self.offset = end;

        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8> {
        self.take_slice(1)?
            .first()
            .copied()
            .ok_or(AegisError::Malformed)
    }

    fn take_u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self
            .take_slice(4)?
            .try_into()
            .map_err(|_| AegisError::Malformed)?;

        Ok(u32::from_be_bytes(bytes))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take_slice(N)?
            .try_into()
            .map_err(|_| AegisError::Malformed)
    }

    fn expect_end(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(AegisError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initial() -> Envelope {
        Envelope::Initial {
            identity_key: PublicKeyBytes::new([0x11u8; KEY_LEN]),
            ephemeral_key: PublicKeyBytes::new([0x22u8; KEY_LEN]),
            kem_ciphertext: vec![0x33; 1568],
            one_time_pre_key_id: Some(PreKeyId::new(42)),
            kem_pre_key_id: PreKeyId::new(7),
            kem_one_time: true,
            payload: vec![0x44; 128],
        }
    }

    #[test]
    fn initial_envelope_round_trips() {
        let envelope = initial();
        let bytes = envelope.to_bytes().expect("сериализуется");

        assert_eq!(Envelope::from_bytes(&bytes).expect("разбирается"), envelope);
    }

    #[test]
    fn message_envelope_round_trips() {
        let envelope = Envelope::Message {
            payload: vec![0x55; 64],
        };
        let bytes = envelope.to_bytes().expect("сериализуется");

        assert_eq!(Envelope::from_bytes(&bytes).expect("разбирается"), envelope);
    }

    #[test]
    fn missing_one_time_pre_key_round_trips() {
        let Envelope::Initial {
            identity_key,
            ephemeral_key,
            kem_ciphertext,
            kem_pre_key_id,
            payload,
            ..
        } = initial()
        else {
            unreachable!("initial() возвращает Initial");
        };

        // Исчерпанный пул — штатный случай, а не ошибка: конверт без
        // одноразового предключа обязан ходить туда и обратно.
        let envelope = Envelope::Initial {
            identity_key,
            ephemeral_key,
            kem_ciphertext,
            one_time_pre_key_id: None,
            kem_pre_key_id,
            kem_one_time: false,
            payload,
        };

        let bytes = envelope.to_bytes().expect("сериализуется");

        assert_eq!(Envelope::from_bytes(&bytes).expect("разбирается"), envelope);
    }

    #[test]
    fn unknown_version_is_rejected() {
        let mut bytes = initial().to_bytes().expect("сериализуется");
        bytes[0] = ENVELOPE_VERSION.wrapping_add(1);

        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(AegisError::Malformed)
        ));
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let bytes = vec![ENVELOPE_VERSION, 99, 0, 0, 0, 0];

        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(AegisError::Malformed)
        ));
    }

    /// 🔐 Обрыв на любой позиции даёт ошибку, а не панику.
    ///
    /// Обрезанный конверт — самый дешёвый способ уронить клиента:
    /// его может прислать кто угодно, а паника в разборе означает
    /// отказ в обслуживании.
    #[test]
    fn truncation_at_any_offset_is_an_error() {
        let full = initial().to_bytes().expect("сериализуется");

        for cut in 0..full.len() {
            let truncated = full.get(..cut).expect("срез в границах");

            assert!(
                Envelope::from_bytes(truncated).is_err(),
                "обрезка до {cut} байт разобралась вместо отказа"
            );
        }
    }

    /// Лишние байты в хвосте отвергаются.
    ///
    /// Иначе один и тот же конверт имел бы бесконечно много допустимых
    /// представлений, и подпись над ним перестала бы что-либо значить.
    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = initial().to_bytes().expect("сериализуется");
        bytes.push(0);

        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(AegisError::Malformed)
        ));
    }

    #[test]
    fn oversized_length_is_rejected_without_allocating() {
        // Объявленная длина в четыре гигабайта при пустом теле:
        // разбор обязан отказать по границе, а не пытаться выделить
        // память под неё.
        let mut bytes = vec![ENVELOPE_VERSION, KIND_MESSAGE];
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());

        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(AegisError::Malformed)
        ));
    }

    #[test]
    fn invalid_boolean_flags_are_rejected() {
        let mut bytes = initial().to_bytes().expect("сериализуется");

        // Байт признака одноразового предключа: допустимы только 0 и 1.
        // Позиция — после версии, типа и двух ключей и длины KEM.
        let flag_offset = 1 + 1 + KEY_LEN + KEY_LEN + 4 + 1568;
        bytes[flag_offset] = 2;

        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(AegisError::Malformed)
        ));
    }
}
