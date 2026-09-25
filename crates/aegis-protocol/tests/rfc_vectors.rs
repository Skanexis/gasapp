// SPDX-License-Identifier: Apache-2.0

//! Сверка с официальными тестовыми векторами.
//!
//! # Чем это отличается от остальных тестов
//!
//! Все прочие тесты проверяют реализацию **саму на себе**: зашифровали —
//! расшифровали, получили то же. Такая проверка не ловит ошибку,
//! симметрично допущенную в обеих ветках кода: если и шифрование, и
//! расшифровка одинаково перепутают порядок аргументов KDF, round-trip
//! пройдёт, а совместимость с любой другой реализацией будет потеряна.
//!
//! Векторы приходят **извне** — из опубликованных RFC. Совпадение с ними
//! означает, что реализация делает то же, что эталон, а не то же, что
//! она сама.
//!
//! # Что покрыто здесь
//!
//! HKDF-SHA-256 (RFC 5869) — примитив, на котором держится вывод ключей
//! во всех четырёх криптографических модулях: `pqxdh`, `double_ratchet`,
//! `spqr` и `aegis-keystore`. До этих векторов он не был сверен ни с одним
//! внешним источником.
//!
//! X25519 (RFC 7748) и Ed25519 (RFC 8032) сверены в модульных тестах
//! соответствующих файлов, ML-KEM (FIPS 203) — в `mlkem.rs`.
//!
//! # Чего здесь нет
//!
//! Векторов самого протокола — PQXDH, Double Ratchet, SPQR. Их источник
//! один: эталонная реализация libsignal, а её нельзя ни линковать, ни
//! копировать (AGPL-3.0, ADR-005). Векторы генерируются из неё в
//! изолированном контейнере и коммитятся как **данные**; эта работа
//! остаётся открытой в M2.

// Паника здесь — правильное поведение: векторы заданы константами в этом
// файле, и невозможность их разобрать означает опечатку при переносе
// из RFC. Тест обязан остановиться, а не продолжить на пустых данных.
// Послабления `allow-panic-in-tests` из `clippy.toml` на интеграционные
// тесты не распространяются, поэтому снимается точечно.
#![allow(clippy::panic)]

use hkdf::Hkdf;
use sha2::Sha256;

/// Разбирает hex-строку. Пустая строка даёт пустой вектор.
///
/// Векторы — константы в этом файле, а не внешний вход, поэтому
/// некорректная строка означает опечатку при переносе из RFC. Такая
/// опечатка обязана останавливать тест, а не молча давать пустой результат.
fn hex(input: &str) -> Vec<u8> {
    assert!(
        input.len().is_multiple_of(2),
        "нечётная длина hex: {}",
        input.len()
    );

    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).unwrap_or("");

            u8::from_str_radix(text, 16).unwrap_or_else(|_| panic!("не hex: {text:?}"))
        })
        .collect()
}

/// Один вектор RFC 5869.
struct Vector {
    case: &'static str,
    ikm: &'static str,
    salt: &'static str,
    info: &'static str,
    length: usize,
    prk: &'static str,
    okm: &'static str,
}

/// Векторы из RFC 5869, Appendix A — случаи с SHA-256.
///
/// Значения перенесены из текста RFC. Случаи A.4–A.7 опущены: они
/// используют SHA-1, который в проекте не применяется.
const VECTORS: &[Vector] = &[
    // A.1. Basic test case with SHA-256.
    Vector {
        case: "A.1",
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "000102030405060708090a0b0c",
        info: "f0f1f2f3f4f5f6f7f8f9",
        length: 42,
        prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    },
    // A.2. Test with SHA-256 and longer inputs/outputs.
    Vector {
        case: "A.2",
        ikm: concat!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "404142434445464748494a4b4c4d4e4f",
        ),
        salt: concat!(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        ),
        info: concat!(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        ),
        length: 82,
        prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        okm: concat!(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c",
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71",
            "cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
    },
    // A.3. Test with SHA-256 and zero-length salt/info.
    //
    // Самый значимый случай для AEGIS: пустая соль трактуется как строка
    // нулей длиной с выход хеша, а не как её отсутствие. Реализация,
    // путающая эти два поведения, даст другой PRK — и разойдётся со всеми
    // остальными.
    Vector {
        case: "A.3",
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "",
        info: "",
        length: 42,
        prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    },
];

/// 🔐 HKDF-SHA-256 совпадает с RFC 5869 на всех векторах SHA-256.
///
/// Проверяются обе фазы: extract (PRK) и expand (OKM). Расхождение
/// в любой из них означает, что ключи AEGIS не совпадут с ключами любой
/// другой корректной реализации.
#[test]
fn hkdf_sha256_matches_rfc5869() {
    for vector in VECTORS {
        let ikm = hex(vector.ikm);
        let salt = hex(vector.salt);
        let info = hex(vector.info);

        // Пустая соль передаётся как `Some(&[])`, а не `None`: RFC требует
        // трактовать её как строку нулей, и это разные вещи.
        let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);

        assert_eq!(
            prk.as_slice(),
            hex(vector.prk).as_slice(),
            "PRK разошёлся с RFC 5869, случай {}",
            vector.case
        );

        let mut okm = vec![0u8; vector.length];
        hkdf.expand(&info, &mut okm)
            .unwrap_or_else(|_| panic!("expand не удался, случай {}", vector.case));

        assert_eq!(
            okm,
            hex(vector.okm),
            "OKM разошёлся с RFC 5869, случай {}",
            vector.case
        );
    }
}

/// Пустая соль и её отсутствие — разные вещи.
///
/// Регрессионный тест на трактовку `None` против `Some(&[])`. RFC 5869
/// определяет пустую соль как строку нулей длиной с выход хеша; `None`
/// в крейте `hkdf` означает ровно это же, поэтому результаты обязаны
/// совпасть. Если поведение крейта когда-нибудь изменится, тест это
/// поймает — а молчаливое расхождение сломало бы совместимость.
#[test]
fn empty_salt_equals_absent_salt() {
    let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

    let (with_empty, _) = Hkdf::<Sha256>::extract(Some(&[]), &ikm);
    let (with_none, _) = Hkdf::<Sha256>::extract(None, &ikm);

    assert_eq!(
        with_empty.as_slice(),
        with_none.as_slice(),
        "трактовка пустой соли разошлась с RFC 5869"
    );

    // И то, и другое обязано совпасть с вектором A.3.
    assert_eq!(
        with_empty.as_slice(),
        hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04").as_slice()
    );
}

/// Выход HKDF зависит от `info`.
///
/// На этом свойстве держится доменное разделение во всём проекте: PQXDH,
/// корневой ключ ratchet, nonce AEAD и гибридное объединение SPQR
/// различаются **только** меткой `info`. Совпадение выходов при разных
/// метках означало бы, что разделение доменов не работает.
#[test]
fn different_info_yields_different_output() {
    let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);

    let mut first = [0u8; 32];
    let mut second = [0u8; 32];

    hkdf.expand(b"AEGIS_PQXDH_v1_X25519_MLKEM1024", &mut first)
        .expect("длина в пределах лимита");
    hkdf.expand(b"AEGIS_TripleRatchet_v1", &mut second)
        .expect("длина в пределах лимита");

    assert_ne!(first, second, "разные метки info дали один выход");
}

/// Отпечатки не меняются между сборками.
///
/// # Чем этот тест отличается от векторов RFC выше
///
/// Значения получены **нашей же реализацией** и зафиксированы, чтобы
/// поймать непреднамеренное изменение алгоритма: правку числа раундов,
/// порядка конкатенации, префикса версии или поведения зависимости.
///
/// Совместимости с другими реализациями он **не доказывает**: ошибку,
/// присутствовавшую с самого начала, такой тест зафиксирует, а не
/// обнаружит. Это разные виды проверки, и путать их нельзя.
///
/// Значения дублируются в
/// `docs/protocol/test-vectors/fingerprint/aegis-self.txt` — там же
/// записано, почему они не эталонные.
#[test]
fn fingerprints_are_stable_across_builds() {
    use aegis_protocol::Fingerprint;
    use aegis_types::PublicKeyBytes;

    let cases: &[(u8, &str, &str)] = &[
        (
            0x00,
            "",
            "2c6da5b8fb647fef1248f03b24bb572e9467cec4e4db35c93cc58e4536e3",
        ),
        (
            0x01,
            "alice",
            "12ddb11d0524d288ce5e2cde00f84a65043948890f01635a4e20ca54ce42",
        ),
        (
            0xFF,
            "bob",
            "d9becace747e5a37cc8f88c1da53073916093a36b717491aec20f283aefc",
        ),
    ];

    for (key_byte, identifier, expected) in cases {
        let key = PublicKeyBytes::new([*key_byte; 32]);
        let fingerprint = Fingerprint::compute(&key, identifier.as_bytes());

        assert_eq!(
            fingerprint.as_bytes().as_slice(),
            hex(expected).as_slice(),
            "отпечаток изменился: ключ {key_byte:02x}, identifier {identifier:?}"
        );
    }
}

// --- HMAC-SHA256, RFC 4231 -------------------------------------------------

/// HMAC-SHA256 совпадает с RFC 4231 (случаи 1, 2, 3, 6, 7).
///
/// HMAC — основа KDF цепочек Double Ratchet. Случаи 6 и 7 — ключ
/// длиннее блока: такой ключ HMAC сначала хеширует, и ошибка именно
/// в этой ветке не видна на обычных ключах.
#[test]
fn hmac_sha256_matches_rfc4231() {
    let long_key = vec![0xaa_u8; 131];
    let cases: &[(Vec<u8>, Vec<u8>, &str)] = &[
        (
            vec![0x0b; 20],
            b"Hi There".to_vec(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            b"Jefe".to_vec(),
            b"what do ya want for nothing?".to_vec(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        (
            vec![0xaa; 20],
            vec![0xdd; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        ),
        (
            long_key.clone(),
            b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        ),
        (
            long_key,
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        ),
    ];

    for (index, (key, data, expected)) in cases.iter().enumerate() {
        let mac = aegis_protocol::aead::hmac_sha256(key, data).expect("HMAC");
        assert_eq!(
            mac.as_slice(),
            hex(expected).as_slice(),
            "RFC 4231, случай {index}"
        );
    }
}

// --- AES-256-GCM, спецификация GCM (McGrew, Viega), NIST SP 800-38D ---------

/// AES-256-GCM совпадает с тест-кейсами 13, 14 и 16 спецификации GCM.
///
/// Проверяются и шифртекст, и тег; 16-й — с AAD и открытым текстом
/// не кратным блоку. Обратный путь — расшифровка того же вектора
/// и отказ при изменённом теге.
#[test]
fn aes256_gcm_matches_the_gcm_specification() {
    use aegis_protocol::aead::{open_with_key, seal_with_key};

    struct Case {
        key: &'static str,
        iv: &'static str,
        plaintext: &'static str,
        aad: &'static str,
        ciphertext: &'static str,
        tag: &'static str,
    }

    let cases = [
        // Тест-кейс 13: нулевой ключ, пустой текст.
        Case {
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            iv: "000000000000000000000000",
            plaintext: "",
            aad: "",
            ciphertext: "",
            tag: "530f8afbc74536b9a963b4f1c4cb738b",
        },
        // Тест-кейс 14: нулевой ключ, один нулевой блок.
        Case {
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            iv: "000000000000000000000000",
            plaintext: "00000000000000000000000000000000",
            aad: "",
            ciphertext: "cea7403d4d606b6e074ec5d3baf39d18",
            tag: "d0d1c8a799996bf0265b98b5d48ab919",
        },
        // Тест-кейс 16: AAD и 60 байт текста.
        Case {
            key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            iv: "cafebabefacedbaddecaf888",
            plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            ciphertext: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            tag: "76fc6ece0f4e1768cddf8853bb2d551b",
        },
    ];

    for (index, case) in cases.iter().enumerate() {
        let key: [u8; 32] = hex(case.key).try_into().expect("ключ 32 байта");
        let iv: [u8; 12] = hex(case.iv).try_into().expect("nonce 12 байт");
        let mut expected = hex(case.ciphertext);
        expected.extend(hex(case.tag));

        let sealed =
            seal_with_key(&key, &iv, &hex(case.plaintext), &hex(case.aad)).expect("шифрование");
        assert_eq!(sealed, expected, "GCM, вектор {index}: шифртекст или тег");

        let opened = open_with_key(&key, &iv, &sealed, &hex(case.aad)).expect("расшифровка");
        assert_eq!(opened.as_slice(), hex(case.plaintext).as_slice());

        let mut forged = sealed.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(
            open_with_key(&key, &iv, &forged, &hex(case.aad)).is_err(),
            "GCM, вектор {index}: изменённый тег принят"
        );
    }
}

// --- ML-KEM (FIPS 203): seed → открытый ключ --------------------------------

/// ML-KEM-768 и ML-KEM-1024 из seed 00..3f дают эталонный открытый ключ.
///
/// Эталон — примеры черновика IETF LAMPS «ML-KEM in X.509»
/// (`ML-KEM-*-seed.priv` → `ML-KEM-*.pub`); сверяется SHA-256 сырого
/// ключа из `SubjectPublicKeyInfo`. Хранилище держит только seed
/// (`from_seed`), поэтому детерминированное развёртывание — ровно то,
/// что должно совпадать с чужой реализацией.
#[test]
fn ml_kem_keys_from_seed_match_the_lamps_examples() {
    use aegis_protocol::{MlKem1024PrivateKey, MlKem768PrivateKey};
    use sha2::Digest as _;

    let mut seed = [0u8; 64];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = u8::try_from(index).expect("индекс < 64");
    }

    let public768 = MlKem768PrivateKey::from_seed(seed).public_key().as_bytes();
    assert_eq!(public768.len(), 1184);
    assert_eq!(
        Sha256::digest(&public768).as_slice(),
        hex("0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9").as_slice(),
        "ML-KEM-768: открытый ключ из seed не совпал с эталоном"
    );

    let public1024 = MlKem1024PrivateKey::from_seed(seed).public_key().as_bytes();
    assert_eq!(public1024.len(), 1568);
    assert_eq!(
        Sha256::digest(&public1024).as_slice(),
        hex("c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530").as_slice(),
        "ML-KEM-1024: открытый ключ из seed не совпал с эталоном"
    );
}
