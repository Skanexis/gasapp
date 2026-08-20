// SPDX-License-Identifier: Apache-2.0

//! Прогон фаззинг-таргетов на стабильном компиляторе.
//!
//! # Зачем это нужно
//!
//! Настоящий фаззинг (`cargo-fuzz`, libFuzzer) требует nightly и запускается
//! в CI по ночам. На стабильном компиляторе таргеты только **собираются**,
//! то есть их логика не выполняется вообще — а собранный, но ни разу
//! не запущенный таргет не отличим от неработающего.
//!
//! Этот файл прогоняет ту же логику детерминированным псевдослучайным
//! генератором. Он не заменяет фаззинг: покрытие несопоставимо, обратной
//! связи по путям исполнения нет. Но он даёт три вещи, которых иначе нет
//! до первого ночного прогона:
//!
//! * таргеты проверены на самих себе — если разбор паникует на простом
//!   мусоре, это видно сразу, а не через сутки;
//! * найденные паники воспроизводятся по номеру итерации, без корпуса;
//! * регрессия ловится в обычном `cargo test`, то есть на каждом коммите.
//!
//! # Про генератор
//!
//! Используется xorshift с фиксированным seed. Криптографического качества
//! он не имеет и не должен: задача — обойти как можно больше форм входа
//! воспроизводимо, а не быть непредсказуемым.

// Арифметика генератора работает по модулю заведомо ненулевых величин
// и на wrapping-операциях: это часть самого xorshift, а не недосмотр.
#![allow(clippy::arithmetic_side_effects)]

use aegis_protocol::{
    double_ratchet::RatchetState,
    keys::{
        IdentityKey, KemPublicKey, PreKeyBundle, PreKeyId, SessionState, SignedKemPreKey,
        SignedPreKey,
    },
    pqxdh,
    spqr::{Chunk, ChunkAssembler, EpochId},
    x25519::X25519PrivateKey,
    SafetyNumber,
};
use aegis_types::{Ciphertext, DeviceId, PublicKeyBytes, Secret, Timestamp};
use rand_core::OsRng;

/// Число итераций на таргет.
///
/// Подобрано так, чтобы весь файл укладывался в пару секунд: это тест,
/// который идёт на каждом коммите, а не ночной прогон.
const ITERATIONS: usize = 2_000;

/// Детерминированный генератор псевдослучайных байт (xorshift64*).
struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        // Ноль — неподвижная точка xorshift, поэтому исключается.
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;

        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Буфер длиной до `max` байт включительно.
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = usize::try_from(self.next_u64()).unwrap_or(0) % max.saturating_add(1);

        (0..len)
            .map(|_| u8::try_from(self.next_u64() & 0xFF).unwrap_or(0))
            .collect()
    }
}

/// Таргет `chunk_reassembly`: сборщик чанков SPQR.
///
/// Чанки приходят из сети и полностью подконтрольны отправителю.
#[test]
fn chunk_reassembly_never_panics() {
    let mut rng = Rng::new(0x0BAD_C0DE);
    let mut assembler = ChunkAssembler::new();

    for _ in 0..ITERATIONS {
        let chunk = Chunk {
            epoch: EpochId::from_u32(u32::try_from(rng.next_u64() & 0xFFFF_FFFF).unwrap_or(0)),
            index: u16::try_from(rng.next_u64() & 0xFFFF).unwrap_or(0),
            total: u16::try_from(rng.next_u64() & 0xFFFF).unwrap_or(0),
            payload: rng.bytes(256),
        };

        // Важен не результат, а отсутствие паники и сохранение
        // согласованности состояния для следующей итерации.
        let _ = assembler.accept(&chunk);
    }
}

/// Таргет `chunk_reassembly` на правдоподобных входах.
///
/// Полностью случайные поля почти всегда отвергаются проверкой границ,
/// поэтому отдельно прогоняются чанки с корректными `total` и `index`:
/// они доходят до самой сборки, а не отсеиваются на входе.
#[test]
fn chunk_reassembly_survives_plausible_input() {
    let mut rng = Rng::new(0xC0FF_EE01);
    let mut assembler = ChunkAssembler::new();

    for _ in 0..ITERATIONS {
        let total = u16::try_from(rng.next_u64() % 32).unwrap_or(0).max(1);
        let index = u16::try_from(rng.next_u64() % u64::from(total)).unwrap_or(0);
        let epoch = u32::try_from(rng.next_u64() % 4).unwrap_or(0);

        let chunk = Chunk {
            epoch: EpochId::from_u32(epoch),
            index,
            total,
            payload: rng.bytes(128),
        };

        let _ = assembler.accept(&chunk);
    }
}

/// Таргет `parse_message`: разбор входящего сообщения.
#[test]
fn message_parsing_never_panics() {
    let mut rng = Rng::new(0xDEAD_BEEF);
    let shared = [0x11u8; 32];
    let our_ratchet = X25519PrivateKey::generate(&mut OsRng);
    let mut state = RatchetState::accept(&shared, our_ratchet);

    for _ in 0..ITERATIONS {
        let bytes = rng.bytes(128);

        let result = state.decrypt(&Ciphertext::new(bytes), Timestamp::from_millis(0));

        // Случайные байты не могут пройти проверку тега AEAD.
        assert!(result.is_err(), "случайные байты приняты как сообщение");
    }
}

/// Таргет `parse_session_state`: разбор сохранённого состояния.
///
/// Источник доверенный (собственная база), но повреждение файла не должно
/// ронять приложение.
#[test]
fn session_state_parsing_never_panics() {
    let mut rng = Rng::new(0xFEED_FACE);

    for _ in 0..ITERATIONS {
        let session = SessionState::from_serialized(Secret::new(rng.bytes(512)));

        if let Ok(state) = RatchetState::deserialize(&session) {
            // Разобранное состояние обязано быть пригодным к использованию.
            let _ = state.skipped_count();
            let _ = state.serialize();
        }
    }
}

/// Таргет `decrypt_session`: расшифровка со случайным состоянием.
///
/// Проверяет согласованность разбора состояния и разбора сообщения:
/// неправдоподобные счётчики в состоянии не должны приводить к панике
/// при подсчёте пропущенных ключей.
#[test]
fn decrypt_with_arbitrary_state_never_panics() {
    let mut rng = Rng::new(0x1234_5678);

    for _ in 0..ITERATIONS {
        let session = SessionState::from_serialized(Secret::new(rng.bytes(256)));

        let Ok(mut state) = RatchetState::deserialize(&session) else {
            continue;
        };

        let _ = state.decrypt(&Ciphertext::new(rng.bytes(128)), Timestamp::from_millis(0));
    }
}

/// Таргет `parse_prekey_bundle`: проверка bundle с сервера.
///
/// Сервер недоверенный: bundle со случайной подписью обязан отвергаться
/// **всегда**. Успех означал бы подделку подписи.
#[test]
fn prekey_bundle_with_random_signature_is_always_rejected() {
    let mut rng = Rng::new(0xABCD_EF01);

    for _ in 0..ITERATIONS {
        let mut identity = [0u8; 32];
        let mut signed = [0u8; 32];
        for byte in &mut identity {
            *byte = u8::try_from(rng.next_u64() & 0xFF).unwrap_or(0);
        }
        for byte in &mut signed {
            *byte = u8::try_from(rng.next_u64() & 0xFF).unwrap_or(0);
        }

        let bundle = PreKeyBundle {
            device_id: DeviceId::generate(),
            identity_key: IdentityKey::new(PublicKeyBytes::new(identity)),
            signed_pre_key: SignedPreKey {
                id: PreKeyId::new(1),
                public: PublicKeyBytes::new(signed),
                signature: rng.bytes(64),
            },
            one_time_pre_key: None,
            signed_kem_pre_key: SignedKemPreKey {
                id: PreKeyId::new(2),
                public: KemPublicKey::new(rng.bytes(1568)),
                signature: rng.bytes(64),
            },
            one_time_kem_pre_key: None,
        };

        assert!(
            pqxdh::verify_bundle(&bundle).is_err(),
            "bundle со случайной подписью принят"
        );
    }
}

/// Таргет `parse_safety_number`: разбор ввода пользователя.
///
/// Safety number вводит человек — с опечатками, обрезками и посторонними
/// символами. Паника здесь означала бы, что экран верификации падает.
#[test]
fn safety_number_parsing_never_panics() {
    let mut rng = Rng::new(0x5AFE_0000);

    // Случайные байты как текст.
    for _ in 0..ITERATIONS {
        let bytes = rng.bytes(96);
        let Ok(text) = core::str::from_utf8(&bytes) else {
            continue;
        };

        let _ = SafetyNumber::parse(text);
    }

    // Отдельно — строки из цифр и разделителей: они доходят до самой
    // логики разбора, а не отсеиваются на первом же нецифровом символе.
    for _ in 0..ITERATIONS {
        let len = usize::try_from(rng.next_u64() % 80).unwrap_or(0);
        let text: String = (0..len)
            .map(|_| {
                let value = rng.next_u64() % 12;
                match value {
                    10 => ' ',
                    11 => '\n',
                    digit => char::from_digit(u32::try_from(digit).unwrap_or(0), 10).unwrap_or('0'),
                }
            })
            .collect();

        if let Ok(number) = SafetyNumber::parse(&text) {
            // Разобранное число обязано переживать обратный разбор.
            let rendered = number.to_display_block();
            assert!(
                SafetyNumber::parse(&rendered).is_ok(),
                "отображённое число не разбирается обратно"
            );
        }
    }
}
