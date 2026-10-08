// SPDX-License-Identifier: Apache-2.0

//! Зеркало фаззинг-таргета `backup_restore` на стабильном компиляторе.
//!
//! # Зачем зеркало
//!
//! Настоящий фаззинг (`fuzz/fuzz_targets/backup_restore.rs`) требует
//! nightly и libFuzzer и идёт ночью в CI; на Windows он не запускается
//! вовсе. До этого файла разбор копии не проверялся ни одним прогоном,
//! который гоняется на каждом PR, — при том что файл копии пишет
//! кто угодно, у кого он в руках, а заголовок читается **до** проверки
//! тега (соль и параметры нужны, чтобы вывести ключ).
//!
//! Здесь те же три входа, что у таргета, на случайных байтах
//! и на мутациях настоящих файлов. Проверяется одно: разбор отвечает
//! ошибкой, а не паникой, и не пытается выделить память по числу
//! из файла.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // Генератор намеренно режет 64-битное слово до байта и индекса.
    clippy::cast_possible_truncation
)]

use gasapp_backup::archive::ArchiveHeader;
use gasapp_backup::bundle::{BackupBundle, ContactRecord, MessageRecord, ID_LEN};
use gasapp_backup::{kdf, BackupChain, KdfParams, RecoveryKey};
use rand_core::OsRng;

/// Детерминированный генератор: упавший прогон воспроизводится.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }

    /// Портит 1–4 байта и иногда обрезает хвост.
    fn mutate(&mut self, original: &[u8]) -> Vec<u8> {
        let mut data = original.to_vec();

        for _ in 0..=self.below(4) {
            let at = self.below(data.len());
            data[at] = self.next() as u8;
        }

        if self.below(4) == 0 {
            data.truncate(self.below(data.len() + 1));
        }

        data
    }
}

fn populated() -> BackupBundle {
    BackupBundle {
        account_id: Some([0x33; ID_LEN]),
        username: Some("alice".to_owned()),
        created_at_millis: 1_760_000_000_000,
        messages: (1..=3)
            .map(|id| MessageRecord {
                id: [id; ID_LEN],
                chat_id: [0x11; ID_LEN],
                sender_id: [0x22; ID_LEN],
                timestamp_millis: 1_760_000_000_000,
                content: vec![id; 48],
                status: 1,
                message_type: 0,
                expires_at_millis: None,
            })
            .collect(),
        contacts: vec![ContactRecord {
            account_id: [0x44; ID_LEN],
            identity_key: vec![0x55; 32],
            username: Some("bob".to_owned()),
            chat_id: Some([0x11; ID_LEN]),
            verified: true,
            added_at_millis: Some(1_759_000_000_000),
        }],
        ..BackupBundle::default()
    }
}

fn cheap() -> KdfParams {
    KdfParams {
        memory_kib: kdf::MIN_MEMORY_KIB,
        iterations: kdf::MIN_ITERATIONS,
        parallelism: 1,
    }
}

/// Случайные байты: ни заголовок, ни бандл не паникуют.
#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(0x0BAC_0001);

    for _ in 0..20_000 {
        let len = rng.below(2_048);
        let data = rng.bytes(len);

        let _ = ArchiveHeader::from_bytes(&data);

        if let Ok(bundle) = BackupBundle::from_bytes(&data) {
            let _ = bundle.validate();
        }
    }
}

/// Мутации настоящего бандла — путь после успешной расшифровки.
///
/// Случайные байты почти никогда не проходят первую проверку формата;
/// мутации настоящей записи доходят до глубоких веток разбора —
/// длин полей и числа записей.
#[test]
fn mutated_bundles_never_panic() {
    let original = populated().to_bytes().expect("бандл кодируется");
    let mut rng = Rng(0x0BAC_0002);

    for _ in 0..20_000 {
        let data = rng.mutate(&original);

        if let Ok(bundle) = BackupBundle::from_bytes(&data) {
            let _ = bundle.validate();
            let _ = bundle.to_bytes();
        }
    }
}

/// 🔐 Мутации настоящего файла копии: заголовок и восстановление.
///
/// Восстановление ведёт Argon2id на каждый вызов, поэтому его
/// прогонов меньше — зато ключ настоящий, и испорченный файл обязан
/// отвергаться целиком, а не восстанавливаться частично.
#[test]
fn mutated_archives_never_panic_and_never_restore() {
    let key = RecoveryKey::from_bytes([0x42; 32]);
    let mut chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");
    let original = chain
        .seal_full(&populated(), Some("pixel"), &mut OsRng)
        .expect("файл копии");

    assert!(
        BackupChain::restore(&key, std::slice::from_ref(&original)).is_ok(),
        "заготовка теста: нетронутый файл не восстанавливается"
    );

    let mut rng = Rng(0x0BAC_0003);

    for _ in 0..20_000 {
        let _ = ArchiveHeader::from_bytes(&rng.mutate(&original));
    }

    for round in 0..40 {
        let data = rng.mutate(&original);

        if data == original {
            continue;
        }

        assert!(
            BackupChain::restore(&key, &[data]).is_err(),
            "испорченный файл восстановился (прогон {round})"
        );
    }
}
