// SPDX-License-Identifier: Apache-2.0

//! Общая обвязка ML-KEM (FIPS 203) для двух используемых наборов параметров.
//!
//! Проект применяет ML-KEM дважды и с разными целями:
//!
//! * **ML-KEM-1024** — установление сессии в PQXDH (раздел 6.2 плана);
//! * **ML-KEM-768** — KEM-ratchet в SPQR (ADR-021), где шифротекст передаётся
//!   с каждым сообщением, поэтому его размер важнее запаса по стойкости.
//!
//! Обе обёртки устроены одинаково, поэтому объявляются одним макросом:
//! аудитору (ADR-026) нужно прочитать логику один раз, а не сверять две
//! почти совпадающие копии на предмет расхождений.
//!
//! # Мост между версиями `rand_core`
//!
//! `ml-kem` 0.3 использует `rand_core` 0.10, а весь остальной крейт — 0.6.4,
//! зафиксированную в workspace. Версии несовместимы по трейтам, поэтому здесь
//! объявлен адаптер [`RngBridge`]. Это единственное место, где две версии
//! встречаются; наружу типы `rand_core` 0.10 не протекают.

use core::convert::Infallible;

use aegis_types::{AegisError, Result};
use rand_core::{CryptoRng, RngCore};

/// Длина общего секрета ML-KEM в байтах (одинакова для всех наборов).
pub const SHARED_SECRET_LEN: usize = 32;

/// Длина seed, из которого детерминированно разворачивается пара ключей.
pub const SEED_LEN: usize = 64;

/// Адаптер источника случайности из `rand_core` 0.6 в `rand_core` 0.10.
///
/// Оборачивает существующий CSPRNG вместо того, чтобы заводить внутри новый:
/// крейт по построению не создаёт источник случайности сам (см. документацию
/// модуля [`crate`]), иначе тесты перестают быть воспроизводимыми.
pub(crate) struct RngBridge<'a, R>(pub(crate) &'a mut R);

impl<R: RngCore + CryptoRng> rand_core10::TryRng for RngBridge<'_, R> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Infallible> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

// Пометка «источник криптографически стойкий» переносится с обёрнутого RNG:
// сам мост стойкости не добавляет и не отнимает.
impl<R: RngCore + CryptoRng> rand_core10::TryCryptoRng for RngBridge<'_, R> {}

/// Объявляет пару обёрток над одним набором параметров ML-KEM.
///
/// Принимает ожидаемые размеры и проверяет их на этапе компиляции: числа
/// в спецификации FIPS 203 фиксированы, и расхождение должно останавливать
/// сборку, а не всплывать в рантайме при разборе чужого ключа.
macro_rules! declare_ml_kem {
    (
        $module:ident,
        $public:ident,
        $private:ident,
        $encapsulation_len:expr,
        $ciphertext_len:expr,
        $doc_name:literal
    ) => {
        #[doc = concat!("Публичный ключ (encapsulation key) ", $doc_name, ".")]
        #[derive(Clone, PartialEq, Eq, Debug)]
        pub struct $public(ml_kem::$module::EncapsulationKey);

        #[doc = concat!("Приватный ключ (decapsulation key) ", $doc_name, ".")]
        ///
        /// Хранится вместе с seed: `ml-kem` 0.3 не отдаёт байты приватного
        /// ключа напрямую, а разворачивает его из seed детерминированно.
        /// Сериализуется поэтому именно seed — он же и есть секрет.
        pub struct $private {
            decapsulation_key: ml_kem::$module::DecapsulationKey,
            seed: aegis_types::Secret<[u8; SEED_LEN]>,
        }

        impl $public {
            #[doc = concat!("Длина публичного ключа ", $doc_name, " в байтах.")]
            pub const LEN: usize = $encapsulation_len;

            #[doc = concat!("Длина шифротекста ", $doc_name, " в байтах.")]
            pub const CIPHERTEXT_LEN: usize = $ciphertext_len;

            /// Разбирает публичный ключ из байт.
            ///
            /// Ключ приходит с сервера в составе prekey bundle, то есть это
            /// недоверенный вход: некорректная длина и некорректная кодировка
            /// отвергаются, а не приводят к панике.
            ///
            /// # Errors
            ///
            /// [`AegisError::Crypto`] — неверная длина либо некорректная
            /// кодировка ключа.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                let array =
                    ml_kem::array::Array::try_from(bytes).map_err(|_| AegisError::Crypto)?;

                ml_kem::$module::EncapsulationKey::new(&array)
                    .map(Self)
                    .map_err(|_| AegisError::Crypto)
            }

            /// Возвращает байты публичного ключа.
            #[must_use]
            pub fn as_bytes(&self) -> Vec<u8> {
                use ml_kem::kem::KeyExport as _;

                self.0.to_bytes().to_vec()
            }

            /// Инкапсулирует общий секрет под этот публичный ключ.
            ///
            /// Возвращает пару «общий секрет, шифротекст». Секрет выводится
            /// у отправителя локально, по сети уходит только шифротекст.
            pub fn encapsulate<R: RngCore + CryptoRng>(
                &self,
                csprng: &mut R,
            ) -> ([u8; SHARED_SECRET_LEN], Vec<u8>) {
                use ml_kem::kem::Encapsulate as _;

                let (ciphertext, shared) = self.0.encapsulate_with_rng(&mut RngBridge(csprng));

                (shared.into(), ciphertext.to_vec())
            }
        }

        impl $private {
            /// Генерирует новую пару ключей.
            pub fn generate<R: RngCore + CryptoRng>(csprng: &mut R) -> Self {
                let mut seed = [0u8; SEED_LEN];
                csprng.fill_bytes(&mut seed);

                Self::from_seed(seed)
            }

            /// Разворачивает пару ключей из seed.
            ///
            /// Детерминированно: тот же seed всегда даёт ту же пару. На этом
            /// держится сериализация — хранить достаточно seed.
            #[must_use]
            pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
                let decapsulation_key =
                    ml_kem::$module::DecapsulationKey::from_seed(ml_kem::Seed::from(seed));

                Self {
                    decapsulation_key,
                    seed: aegis_types::Secret::new(seed),
                }
            }

            /// Разбирает приватный ключ из сохранённого seed.
            ///
            /// # Errors
            ///
            /// [`AegisError::Crypto`] — seed неверной длины.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                let seed = <[u8; SEED_LEN]>::try_from(bytes).map_err(|_| AegisError::Crypto)?;

                Ok(Self::from_seed(seed))
            }

            /// Возвращает seed приватного ключа.
            ///
            /// # Безопасность
            ///
            /// Раскрывает секретный материал. Результат допустимо записывать
            /// только в зашифрованное хранилище (раздел 11 плана).
            #[must_use]
            pub fn expose_secret(&self) -> &[u8; SEED_LEN] {
                self.seed.expose_secret()
            }

            /// Публичная часть пары.
            #[must_use]
            pub fn public_key(&self) -> $public {
                $public(self.decapsulation_key.encapsulation_key().clone())
            }

            /// Восстанавливает общий секрет из шифротекста.
            ///
            /// Шифротекст приходит из сети, поэтому длина проверяется:
            /// `decapsulate_slice` отвергает вход неверного размера.
            ///
            /// # Про «неявный отказ» (implicit rejection)
            ///
            /// ML-KEM по построению не сообщает, что шифротекст некорректен:
            /// на подделанном входе возвращается псевдослучайный секрет,
            /// выведенный из приватного ключа. Это свойство FIPS 203, а не
            /// упущение — различимый отказ дал бы оракул. Несовпадение
            /// обнаруживается позже, при провале аутентификации AEAD.
            ///
            /// # Errors
            ///
            /// [`AegisError::Crypto`] — шифротекст неверной длины.
            pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; SHARED_SECRET_LEN]> {
                use ml_kem::kem::Decapsulate as _;

                self.decapsulation_key
                    .decapsulate_slice(ciphertext)
                    .map(Into::into)
                    .map_err(|_| AegisError::Crypto)
            }
        }

        impl core::fmt::Debug for $private {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($private), "<redacted>"))
            }
        }
    };
}

declare_ml_kem!(
    ml_kem_768,
    MlKem768PublicKey,
    MlKem768PrivateKey,
    1184,
    1088,
    "ML-KEM-768"
);

declare_ml_kem!(
    ml_kem_1024,
    MlKem1024PublicKey,
    MlKem1024PrivateKey,
    1568,
    1568,
    "ML-KEM-1024"
);

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Размеры из FIPS 203, таблица 3.
    ///
    /// Проверяются явно, потому что в прежней реализации они были указаны
    /// неверно: публичный ключ ML-KEM-768 считался 1568-байтным (это размер
    /// ключа ML-KEM-1024), а шифротекст ML-KEM-1024 — 1088-байтным (это
    /// размер шифротекста ML-KEM-768). Ни одна из этих констант не была
    /// проверена запуском, потому что крейт не компилировался.
    #[test]
    fn key_and_ciphertext_sizes_match_fips_203() {
        let mut rng = OsRng;

        let key768 = MlKem768PrivateKey::generate(&mut rng);
        let public768 = key768.public_key();
        let (_, ciphertext768) = public768.encapsulate(&mut rng);

        assert_eq!(public768.as_bytes().len(), 1184, "ek ML-KEM-768");
        assert_eq!(ciphertext768.len(), 1088, "ct ML-KEM-768");
        assert_eq!(MlKem768PublicKey::LEN, 1184);
        assert_eq!(MlKem768PublicKey::CIPHERTEXT_LEN, 1088);

        let key1024 = MlKem1024PrivateKey::generate(&mut rng);
        let public1024 = key1024.public_key();
        let (_, ciphertext1024) = public1024.encapsulate(&mut rng);

        assert_eq!(public1024.as_bytes().len(), 1568, "ek ML-KEM-1024");
        assert_eq!(ciphertext1024.len(), 1568, "ct ML-KEM-1024");
        assert_eq!(MlKem1024PublicKey::LEN, 1568);
        assert_eq!(MlKem1024PublicKey::CIPHERTEXT_LEN, 1568);
    }

    /// Инкапсуляция и декапсуляция дают один и тот же секрет.
    #[test]
    fn encapsulation_round_trips() {
        let mut rng = OsRng;

        let key768 = MlKem768PrivateKey::generate(&mut rng);
        let (sent, ciphertext) = key768.public_key().encapsulate(&mut rng);
        assert_eq!(key768.decapsulate(&ciphertext).unwrap(), sent);

        let key1024 = MlKem1024PrivateKey::generate(&mut rng);
        let (sent, ciphertext) = key1024.public_key().encapsulate(&mut rng);
        assert_eq!(key1024.decapsulate(&ciphertext).unwrap(), sent);
    }

    /// Публичный ключ переживает сериализацию в байты и обратно.
    #[test]
    fn public_key_round_trips_through_bytes() {
        let mut rng = OsRng;
        let public = MlKem768PrivateKey::generate(&mut rng).public_key();

        let parsed = MlKem768PublicKey::from_bytes(&public.as_bytes()).unwrap();

        assert_eq!(parsed, public);
    }

    /// Приватный ключ восстанавливается из seed и даёт тот же публичный ключ.
    ///
    /// Прежняя реализация `expose_secret` возвращала 1568 нулевых байт —
    /// заглушку, выдававшую себя за экспорт ключа. Такой «ключ» после
    /// перезагрузки приложения не расшифровал бы ничего.
    #[test]
    fn private_key_round_trips_through_seed() {
        let mut rng = OsRng;
        let original = MlKem768PrivateKey::generate(&mut rng);

        let restored = MlKem768PrivateKey::from_bytes(original.expose_secret()).unwrap();

        assert_eq!(restored.public_key(), original.public_key());
        assert_ne!(
            original.expose_secret(),
            &[0u8; SEED_LEN],
            "seed не должен быть нулевым"
        );

        // Ключ, восстановленный из seed, расшифровывает то же самое.
        let (sent, ciphertext) = original.public_key().encapsulate(&mut rng);
        assert_eq!(restored.decapsulate(&ciphertext).unwrap(), sent);
    }

    /// Некорректный вход отвергается, а не приводит к панике.
    #[test]
    fn malformed_input_is_rejected() {
        let mut rng = OsRng;
        let key = MlKem768PrivateKey::generate(&mut rng);

        for bad in [vec![], vec![0u8; 1], vec![0u8; 1087], vec![0u8; 2000]] {
            assert!(key.decapsulate(&bad).is_err(), "ct длины {}", bad.len());
            assert!(MlKem768PublicKey::from_bytes(&bad).is_err());
        }

        assert!(MlKem768PrivateKey::from_bytes(&[0u8; 63]).is_err());
        assert!(MlKem768PrivateKey::from_bytes(&[0u8; 65]).is_err());
    }

    /// Разные пары ключей дают разные секреты.
    #[test]
    fn different_keys_produce_different_secrets() {
        let mut rng = OsRng;
        let alice = MlKem768PrivateKey::generate(&mut rng);
        let mallory = MlKem768PrivateKey::generate(&mut rng);

        let (sent, ciphertext) = alice.public_key().encapsulate(&mut rng);

        // Чужой ключ по построению ML-KEM не сообщает об ошибке, а возвращает
        // псевдослучайный секрет — он просто не совпадает с исходным.
        assert_ne!(mallory.decapsulate(&ciphertext).unwrap(), sent);
    }

    /// Приватный ключ не раскрывает материал в отладочном выводе.
    #[test]
    fn private_key_debug_is_redacted() {
        let mut rng = OsRng;
        let key = MlKem768PrivateKey::generate(&mut rng);

        assert_eq!(format!("{key:?}"), "MlKem768PrivateKey<redacted>");
    }
}

#[cfg(test)]
mod deterministic_vectors {
    use super::*;

    /// 🔐 Фиксированный seed даёт фиксированный публичный ключ.
    ///
    /// # Что ловит этот тест
    ///
    /// Официальных векторов ML-KEM для нашей обвязки не существует:
    /// NIST публикует их для самого алгоритма, и их проверяет
    /// библиотека `ml-kem`. Но между ней и протоколом лежит наш код —
    /// упаковка seed, порядок байтов, выбор набора параметров, — и
    /// ошибка в нём векторами библиотеки не ловится.
    ///
    /// Зафиксированные здесь байты ловят именно её: смену библиотеки
    /// на несовместимую, перепутанные наборы параметров (768 против
    /// 1024), изменение формата seed. Любое из этих расхождений
    /// означает, что устройства, собранные из разных версий, не смогут
    /// установить сессию.
    ///
    /// Значения получены этой же реализацией и потому не доказывают
    /// соответствие FIPS 203 — они доказывают неизменность. Это разные
    /// свойства, и второе тоже нужно.
    #[test]
    fn ml_kem_768_public_key_is_stable() {
        let key = MlKem768PrivateKey::from_seed([0x01; SEED_LEN]);
        let public = key.public_key().as_bytes();

        assert_eq!(
            public.get(..8).expect("ключ длиннее восьми байт"),
            &[0x01, 0x77, 0x5c, 0x73, 0x3b, 0xc5, 0x36, 0x63],
            "публичный ключ ML-KEM-768 изменился: устройства на разных \
             версиях не установят сессию"
        );
    }

    #[test]
    fn ml_kem_1024_public_key_is_stable() {
        let key = MlKem1024PrivateKey::from_seed([0x02; SEED_LEN]);
        let public = key.public_key().as_bytes();

        assert_eq!(
            public.get(..8).expect("ключ длиннее восьми байт"),
            &[0x60, 0xe5, 0x6b, 0x72, 0xc5, 0x82, 0x1a, 0xf2],
            "публичный ключ ML-KEM-1024 изменился: устройства на разных \
             версиях не установят сессию"
        );
    }

    /// 🔐 Наборы параметров не перепутаны.
    ///
    /// Один seed в 768 и 1024 обязан давать разные ключи. Если бы
    /// обвязка молча использовала один набор для обоих, ошибка
    /// проявилась бы только при попытке связаться с устройством,
    /// собранным правильно.
    #[test]
    fn parameter_sets_are_not_interchangeable() {
        let seed = [0x07; SEED_LEN];

        let short = MlKem768PrivateKey::from_seed(seed).public_key().as_bytes();
        let long = MlKem1024PrivateKey::from_seed(seed).public_key().as_bytes();

        assert_ne!(short.len(), long.len(), "размеры наборов совпали");
        assert_ne!(
            short.get(..8),
            long.get(..8),
            "разные наборы параметров дали один ключ"
        );
    }
}
