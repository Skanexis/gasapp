// SPDX-License-Identifier: Apache-2.0

//! SPQR — разреженный пост-квантовый храповик поверх Double Ratchet.
//!
//! # Зачем он нужен
//!
//! PQXDH защищает только **начальный** обмен. Дальше сессию ведёт Double
//! Ratchet на эфемерных ключах X25519, а они уязвимы к квантовому противнику:
//! записав диалог сегодня, его можно расшифровать после появления
//! достаточно большого квантового компьютера. SPQR добавляет второй
//! храповик на ML-KEM-768, работающий параллельно классическому.
//!
//! # Гибридность — главное свойство
//!
//! Финальный ключ сообщения выводится **из обеих** составляющих сразу:
//!
//! ```text
//! MK = HKDF-SHA-256(MK_classic ‖ MK_pq, info = "GASAPP_TripleRatchet_v1")
//! ```
//!
//! Чтобы прочитать сообщение, противнику нужно сломать **и** X25519, **и**
//! ML-KEM-768. Если ML-KEM окажется сломан классически — так уже случалось
//! с кандидатами SIKE и Rainbow — стойкость откатывается к уровню Double
//! Ratchet, а не обнуляется. Симметрично при появлении квантового
//! компьютера защищает ML-KEM.
//!
//! Эти пятнадцать строк ([`combine`]) — то место, ради которого писался
//! весь модуль. В первой редакции на их месте стоял комментарий
//! «in a full implementation, we would combine…», из-за чего Triple Ratchet
//! не был гибридным вопреки ADR-021 (дефект #3 раздела 23.0.1).
//!
//! # Почему «разреженный» (sparse)
//!
//! Публичный ключ ML-KEM-768 занимает 1184 байта, шифротекст — 1088.
//! Прикладывать их к каждому сообщению значило бы утроить трафик. Поэтому
//! пост-квантовый шаг выполняется **редко**, а его материал передаётся
//! [чанками](Chunk) по несколько сообщений. Пока чанки не собраны целиком,
//! сессия продолжает работать на текущем пост-квантовом секрете — она
//! никогда не остаётся без него.
//!
//! # Устойчивость ресборки
//!
//! Чанки нумеруются и привязаны к идентификатору эпохи. Потеря, дубликат
//! и приход не по порядку не ломают сборку: [`ChunkAssembler`] складывает
//! их по индексу и отдаёт результат, только когда получены все. Чанки чужой
//! эпохи отбрасываются, а не смешиваются с текущими.

use std::collections::BTreeMap;

use gasapp_types::{GasAppError, Result, Secret};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    mlkem::{MlKem768PrivateKey, MlKem768PublicKey},
    ProtocolVersion,
};

/// Метка HKDF для гибридного объединения ключей.
///
/// Смена метки меняет все выводимые ключи, поэтому она включает версию:
/// секреты разных версий протокола невозможно перепутать.
const TRIPLE_RATCHET_INFO: &[u8] = b"GASAPP_TripleRatchet_v1";

/// Метка HKDF для обновления пост-квантового корневого ключа.
const PQ_ROOT_INFO: &[u8] = b"GASAPP_SPQR_v1_PQ_ROOT";

/// Размер одного чанка в байтах.
///
/// Выбран так, чтобы прибавка к сообщению оставалась незаметной на фоне
/// самого сообщения: 1184-байтный ключ передаётся за 10 сообщений,
/// 1088-байтный шифротекст — за 9.
pub const CHUNK_SIZE: usize = 128;

/// Максимальное число чанков, которое допускается принять в одной эпохе.
///
/// Верхняя граница выведена из наибольшего передаваемого объекта
/// (публичный ключ ML-KEM-768, 1184 байта) с запасом. Существует, чтобы
/// отправитель не мог заставить нас копить память, объявив эпоху
/// из миллиарда чанков.
pub const MAX_CHUNKS: u16 = 32;

/// Идентификатор пост-квантовой эпохи.
///
/// Увеличивается на единицу при каждом завершённом пост-квантовом шаге.
/// Привязка чанков к эпохе не даёт смешать материал соседних шагов.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct EpochId(u32);

impl EpochId {
    /// Первая эпоха.
    pub const INITIAL: Self = Self(0);

    /// Следующая эпоха.
    ///
    /// Насыщается вместо переполнения: счётчик пришёл бы к `u32::MAX` только
    /// после четырёх миллиардов пост-квантовых шагов, но паника в
    /// криптографическом коде недопустима и в недостижимой ветке.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Числовое представление.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Оборачивает номер эпохи, пришедший из сети.
    ///
    /// Любое значение допустимо: эпоха не несёт криптографического смысла
    /// сама по себе, она лишь не даёт смешать чанки соседних шагов.
    /// Порядковое сравнение эпох делает старые чанки безвредными.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }
}

/// Часть пост-квантового материала, передаваемая с одним сообщением.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Chunk {
    /// Эпоха, к которой относится чанк.
    pub epoch: EpochId,
    /// Порядковый номер, начиная с нуля.
    pub index: u16,
    /// Сколько всего чанков в этой эпохе.
    pub total: u16,
    /// Полезная нагрузка.
    pub payload: Vec<u8>,
}

/// Собирает пост-квантовый материал из чанков.
///
/// # Устойчивость
///
/// * **потеря** — сборка просто не завершается, сессия продолжает работать
///   на текущем секрете;
/// * **дубликат** — повторный чанк перезаписывает себя же, результат тот же;
/// * **не по порядку** — чанки хранятся в [`BTreeMap`] по индексу, порядок
///   поступления не важен;
/// * **чужая эпоха** — отбрасывается, чтобы материал двух шагов не смешался.
#[derive(Debug, Default)]
pub struct ChunkAssembler {
    epoch: Option<EpochId>,
    total: u16,
    parts: BTreeMap<u16, Vec<u8>>,
}

impl ChunkAssembler {
    /// Пустой сборщик.
    #[must_use]
    pub fn new() -> Self {
        Self {
            epoch: None,
            total: 0,
            parts: BTreeMap::new(),
        }
    }

    /// Разбивает данные на чанки для передачи.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — данные не помещаются в [`MAX_CHUNKS`].
    pub fn split(data: &[u8], epoch: EpochId) -> Result<Vec<Chunk>> {
        let total = data.len().div_ceil(CHUNK_SIZE);
        let total = u16::try_from(total).map_err(|_| GasAppError::Malformed)?;

        if total > MAX_CHUNKS {
            return Err(GasAppError::Malformed);
        }

        let chunks = data
            .chunks(CHUNK_SIZE)
            .enumerate()
            .map(|(index, payload)| -> Result<Chunk> {
                Ok(Chunk {
                    epoch,
                    index: u16::try_from(index).map_err(|_| GasAppError::Malformed)?,
                    total,
                    payload: payload.to_vec(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(chunks)
    }

    /// Принимает чанк. Возвращает собранные данные, когда получены все.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — чанк объявляет недопустимое число частей,
    /// индекс вне диапазона либо противоречит уже принятым частям эпохи.
    pub fn accept(&mut self, chunk: &Chunk) -> Result<Option<Vec<u8>>> {
        if chunk.total == 0 || chunk.total > MAX_CHUNKS || chunk.index >= chunk.total {
            return Err(GasAppError::Malformed);
        }

        match self.epoch {
            // Чанк более новой эпохи — прежняя сборка не завершилась
            // и больше не нужна.
            Some(current) if chunk.epoch > current => self.reset(chunk.epoch, chunk.total),
            // Чанк устаревшей эпохи — молча отбрасывается.
            Some(current) if chunk.epoch < current => return Ok(None),
            // Та же эпоха: число частей обязано совпадать.
            Some(_) => {
                if chunk.total != self.total {
                    return Err(GasAppError::Malformed);
                }
            }
            None => self.reset(chunk.epoch, chunk.total),
        }

        self.parts.insert(chunk.index, chunk.payload.clone());

        if u16::try_from(self.parts.len()).map_err(|_| GasAppError::Malformed)? < self.total {
            return Ok(None);
        }

        // BTreeMap отдаёт части по возрастанию индекса, поэтому склейка
        // не зависит от порядка поступления.
        let assembled = self.parts.values().flatten().copied().collect();
        self.parts.clear();
        self.epoch = None;
        self.total = 0;

        Ok(Some(assembled))
    }

    /// Сколько частей уже принято.
    #[must_use]
    pub fn received(&self) -> usize {
        self.parts.len()
    }

    fn reset(&mut self, epoch: EpochId, total: u16) {
        self.epoch = Some(epoch);
        self.total = total;
        self.parts.clear();
    }
}

/// Пост-квантовая половина храповика.
///
/// Хранит текущий пост-квантовый секрет и материал незавершённого шага.
pub struct PqRatchet {
    /// Текущий пост-квантовый корневой ключ.
    root: Secret<[u8; 32]>,
    /// Текущая эпоха.
    epoch: EpochId,
    /// Наш приватный ключ ML-KEM, если мы объявили эпоху и ждём ответа.
    our_key: Option<MlKem768PrivateKey>,
    /// Сборщик входящих чанков.
    assembler: ChunkAssembler,
}

// Неполнота `Debug` — требование правила 4: корневой ключ не печатается
// ни при каких условиях, потому что отладочный вывод попадает в логи.
#[allow(clippy::missing_fields_in_debug)]
impl core::fmt::Debug for PqRatchet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Корневой ключ не печатается ни при каких условиях.
        f.debug_struct("PqRatchet")
            .field("epoch", &self.epoch.as_u32())
            .field("awaiting_reply", &self.our_key.is_some())
            .field("chunks_received", &self.assembler.received())
            .finish()
    }
}

impl PqRatchet {
    /// Создаёт храповик с начальным пост-квантовым секретом.
    ///
    /// Секрет берётся из PQXDH: начальный обмен уже дал пост-квантовую
    /// составляющую, и храповик продолжает её, а не начинает с нуля.
    #[must_use]
    pub fn new(initial_secret: [u8; 32]) -> Self {
        Self {
            root: Secret::new(initial_secret),
            epoch: EpochId::INITIAL,
            our_key: None,
            assembler: ChunkAssembler::new(),
        }
    }

    /// Текущая эпоха.
    #[must_use]
    pub const fn epoch(&self) -> EpochId {
        self.epoch
    }

    /// Текущий пост-квантовый секрет для объединения с классическим.
    #[must_use]
    pub const fn secret(&self) -> &[u8; 32] {
        self.root.expose_secret()
    }

    /// Начинает пост-квантовый шаг: публикует новый ключ ML-KEM чанками.
    ///
    /// Собеседник инкапсулирует под этот ключ и вернёт шифротекст, тоже
    /// чанками. До завершения обмена секрет не меняется.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — ключ не помещается в [`MAX_CHUNKS`].
    pub fn begin_epoch<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<Vec<Chunk>> {
        let key = MlKem768PrivateKey::generate(rng);
        let public = key.public_key().as_bytes();
        let epoch = self.epoch.next();

        let chunks = ChunkAssembler::split(&public, epoch)?;
        self.our_key = Some(key);

        Ok(chunks)
    }

    /// Принимает чанк с публичным ключом собеседника.
    ///
    /// Когда ключ собран целиком, инкапсулирует под него общий секрет,
    /// продвигает свой пост-квантовый корень и возвращает шифротекст
    /// чанками для отправки.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — некорректный чанк.
    /// * [`GasAppError::Crypto`] — собранные байты не являются ключом ML-KEM
    ///   либо сбой HKDF.
    pub fn accept_key_chunk<R: RngCore + CryptoRng>(
        &mut self,
        chunk: &Chunk,
        rng: &mut R,
    ) -> Result<Option<Vec<Chunk>>> {
        let Some(assembled) = self.assembler.accept(chunk)? else {
            return Ok(None);
        };

        let public = MlKem768PublicKey::from_bytes(&assembled)?;
        let (shared, ciphertext) = public.encapsulate(rng);
        let shared = Zeroizing::new(shared);

        self.advance(&shared)?;
        self.epoch = chunk.epoch;

        let chunks = ChunkAssembler::split(&ciphertext, chunk.epoch)?;

        Ok(Some(chunks))
    }

    /// Принимает чанк с шифротекстом-ответом.
    ///
    /// Когда шифротекст собран, декапсулирует его и продвигает корень —
    /// после чего обе стороны приходят к одному пост-квантовому секрету.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — некорректный чанк.
    /// * [`GasAppError::SessionNotFound`] — ответ пришёл, хотя эпоха
    ///   не объявлялась: приватного ключа для декапсуляции нет.
    /// * [`GasAppError::Crypto`] — сбой декапсуляции или HKDF.
    pub fn accept_ciphertext_chunk(&mut self, chunk: &Chunk) -> Result<bool> {
        let Some(assembled) = self.assembler.accept(chunk)? else {
            return Ok(false);
        };

        let key = self.our_key.take().ok_or(GasAppError::SessionNotFound)?;
        let shared = Zeroizing::new(key.decapsulate(&assembled)?);

        self.advance(&shared)?;
        self.epoch = chunk.epoch;

        Ok(true)
    }

    /// Продвигает пост-квантовый корень на общем секрете ML-KEM.
    ///
    /// Прежний корень выступает солью: новый секрет зависит и от всей
    /// истории пост-квантового храповика, и от свежей инкапсуляции.
    fn advance(&mut self, shared: &[u8; 32]) -> Result<()> {
        let hkdf = Hkdf::<Sha256>::new(Some(self.root.expose_secret()), shared);
        let mut next = [0u8; 32];

        hkdf.expand(PQ_ROOT_INFO, &mut next)
            .map_err(|_| GasAppError::Crypto)?;

        self.root = Secret::new(next);

        Ok(())
    }
}

/// Объединяет классический и пост-квантовый ключи в финальный ключ сообщения.
///
/// # Это и есть гибридность
///
/// Оба входа обязательны и оба влияют на результат. Противнику, знающему
/// только один из них, вывод HKDF недоступен: SHA-256 не обращается, а
/// недостающие 32 байта входа перебрать нельзя.
///
/// Порядок конкатенации зафиксирован — сначала классический, затем
/// пост-квантовый. Перестановка дала бы другой ключ, поэтому обе стороны
/// обязаны склеивать одинаково; тест `combination_order_matters` это
/// закрепляет.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — сбой HKDF.
pub fn combine(classic: &[u8; 32], post_quantum: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    // Вход KDF — секретный материал: обнуляется при выходе из области видимости.
    let mut ikm = Zeroizing::new([0u8; 64]);
    let (classic_part, pq_part) = ikm.split_at_mut(32);

    classic_part.copy_from_slice(classic);
    pq_part.copy_from_slice(post_quantum);

    let hkdf = Hkdf::<Sha256>::new(None, ikm.as_slice());
    let mut output = Zeroizing::new([0u8; 32]);

    hkdf.expand(TRIPLE_RATCHET_INFO, output.as_mut_slice())
        .map_err(|_| GasAppError::Crypto)?;

    Ok(output)
}

/// Проверяет, что версия протокола допускает пост-квантовый храповик.
///
/// # Про downgrade
///
/// Версия 0 (без пост-квантовой составляющей) отвергается безусловно.
/// Механизма согласования версий нет намеренно: он и есть тот канал,
/// по которому проводят downgrade-атаку. Требование ADR-021.
///
/// # Errors
///
/// [`GasAppError::UnsupportedProtocolVersion`] — версия не требует
/// пост-квантового храповика.
pub fn ensure_post_quantum(version: ProtocolVersion) -> Result<()> {
    if version.requires_post_quantum_ratchet() {
        Ok(())
    } else {
        Err(GasAppError::UnsupportedProtocolVersion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// 🔐 `test_triple_ratchet_uses_both_components`.
    ///
    /// Финальный ключ обязан зависеть от **обеих** составляющих. Если бы
    /// объединение игнорировало любую из них, изменение этой составляющей
    /// не меняло бы результат — ровно так вела бы себя первая редакция,
    /// где комбинирования не было вовсе.
    #[test]
    fn triple_ratchet_uses_both_components() {
        let classic = [1u8; 32];
        let post_quantum = [2u8; 32];

        let baseline = combine(&classic, &post_quantum).unwrap();

        // Меняем только классическую половину.
        let other_classic = combine(&[9u8; 32], &post_quantum).unwrap();
        assert_ne!(*baseline, *other_classic, "классическая часть не учтена");

        // Меняем только пост-квантовую половину.
        let other_pq = combine(&classic, &[9u8; 32]).unwrap();
        assert_ne!(*baseline, *other_pq, "пост-квантовая часть не учтена");
    }

    /// 🔐 `test_classic_survives_pq_compromise`.
    ///
    /// ML-KEM сломан: противник знает пост-квантовую половину целиком.
    /// Пока классическая половина остаётся секретом, финальный ключ ему
    /// недоступен — стойкость откатывается к уровню Double Ratchet.
    #[test]
    fn classic_survives_pq_compromise() {
        let compromised_pq = [0xAAu8; 32];

        // Две сессии с разными классическими половинами и одинаковой
        // скомпрометированной пост-квантовой.
        let first = combine(&[1u8; 32], &compromised_pq).unwrap();
        let second = combine(&[2u8; 32], &compromised_pq).unwrap();

        assert_ne!(
            *first, *second,
            "при известной PQ-половине ключ определяется классической"
        );

        // Знание только PQ-половины не позволяет предсказать ключ:
        // «угадывание» классической части нулями даёт другой результат.
        let guessed = combine(&[0u8; 32], &compromised_pq).unwrap();
        assert_ne!(*first, *guessed);
    }

    /// 🔐 `test_pq_survives_classic_compromise`.
    ///
    /// Появился квантовый компьютер: X25519 сломан, классическая половина
    /// известна. Пост-квантовая половина продолжает защищать сессию.
    #[test]
    fn pq_survives_classic_compromise() {
        let compromised_classic = [0xBBu8; 32];

        let first = combine(&compromised_classic, &[1u8; 32]).unwrap();
        let second = combine(&compromised_classic, &[2u8; 32]).unwrap();

        assert_ne!(
            *first, *second,
            "при известной классической половине ключ определяется PQ"
        );

        let guessed = combine(&compromised_classic, &[0u8; 32]).unwrap();
        assert_ne!(*first, *guessed);
    }

    /// Порядок склейки зафиксирован: перестановка даёт другой ключ.
    ///
    /// Обе стороны обязаны склеивать одинаково, иначе сессия развалится.
    #[test]
    fn combination_order_matters() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        assert_ne!(*combine(&a, &b).unwrap(), *combine(&b, &a).unwrap());
    }

    /// Объединение детерминировано: те же входы дают тот же ключ.
    #[test]
    fn combination_is_deterministic() {
        let classic = [3u8; 32];
        let pq = [4u8; 32];

        assert_eq!(
            *combine(&classic, &pq).unwrap(),
            *combine(&classic, &pq).unwrap()
        );
    }

    /// 🔐 `test_protocol_downgrade_rejected`.
    ///
    /// Версия без пост-квантового храповика отвергается. Согласования
    /// версий нет намеренно: оно и было бы каналом downgrade-атаки.
    #[test]
    fn protocol_downgrade_rejected() {
        assert!(ensure_post_quantum(ProtocolVersion::CURRENT).is_ok());
        assert!(
            ProtocolVersion::parse(0).is_err(),
            "версия 0 не разбирается"
        );
        assert!(
            ProtocolVersion::CURRENT.requires_post_quantum_ratchet(),
            "текущая версия обязана требовать PQ-храповик"
        );
    }

    /// Чанки собираются обратно в исходные данные.
    #[test]
    fn chunks_round_trip() {
        let data: Vec<u8> = (0..1184u32).map(|i| (i % 251) as u8).collect();
        let chunks = ChunkAssembler::split(&data, EpochId::INITIAL.next()).unwrap();

        let mut assembler = ChunkAssembler::new();
        let mut restored = None;
        for chunk in &chunks {
            if let Some(done) = assembler.accept(chunk).unwrap() {
                restored = Some(done);
            }
        }

        assert_eq!(restored.unwrap(), data);
    }

    /// 🔐 Ресборка устойчива к приходу не по порядку.
    #[test]
    fn chunks_assemble_out_of_order() {
        let data: Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
        let mut chunks = ChunkAssembler::split(&data, EpochId::INITIAL.next()).unwrap();
        chunks.reverse();

        let mut assembler = ChunkAssembler::new();
        let mut restored = None;
        for chunk in &chunks {
            if let Some(done) = assembler.accept(chunk).unwrap() {
                restored = Some(done);
            }
        }

        assert_eq!(restored.unwrap(), data, "порядок не должен влиять");
    }

    /// 🔐 Дубликаты не ломают сборку.
    #[test]
    fn duplicate_chunks_are_harmless() {
        let data: Vec<u8> = (0..400u32).map(|i| (i % 251) as u8).collect();
        let chunks = ChunkAssembler::split(&data, EpochId::INITIAL.next()).unwrap();

        let mut assembler = ChunkAssembler::new();
        let mut restored = None;
        for chunk in chunks.iter().chain(chunks.iter()) {
            if let Some(done) = assembler.accept(chunk).unwrap() {
                restored = Some(done);
                break;
            }
        }

        assert_eq!(restored.unwrap(), data);
    }

    /// Потеря чанка оставляет сборку незавершённой, но не ломает её.
    #[test]
    fn lost_chunk_leaves_assembly_incomplete() {
        let data: Vec<u8> = (0..500u32).map(|i| (i % 251) as u8).collect();
        let chunks = ChunkAssembler::split(&data, EpochId::INITIAL.next()).unwrap();

        let mut assembler = ChunkAssembler::new();
        // Пропускаем первый чанк.
        for chunk in chunks.iter().skip(1) {
            assert!(assembler.accept(chunk).unwrap().is_none());
        }

        assert!(assembler.received() > 0, "остальные части приняты");
    }

    /// Чанки устаревшей эпохи отбрасываются, а не смешиваются с текущими.
    #[test]
    fn stale_epoch_chunks_are_ignored() {
        let old: Vec<u8> = vec![1u8; 300];
        let new: Vec<u8> = vec![2u8; 300];

        let epoch_one = EpochId::INITIAL.next();
        let epoch_two = epoch_one.next();

        let old_chunks = ChunkAssembler::split(&old, epoch_one).unwrap();
        let new_chunks = ChunkAssembler::split(&new, epoch_two).unwrap();

        let mut assembler = ChunkAssembler::new();
        // Начинаем новую эпоху.
        assembler.accept(new_chunks.first().unwrap()).unwrap();
        // Прилетает отставший чанк прежней эпохи — игнорируется.
        assert!(assembler
            .accept(old_chunks.first().unwrap())
            .unwrap()
            .is_none());

        let mut restored = None;
        for chunk in new_chunks.iter().skip(1) {
            if let Some(done) = assembler.accept(chunk).unwrap() {
                restored = Some(done);
            }
        }

        assert_eq!(restored.unwrap(), new, "собран материал новой эпохи");
    }

    /// Некорректные чанки отвергаются, а не паникуют.
    #[test]
    fn malformed_chunks_are_rejected() {
        let mut assembler = ChunkAssembler::new();

        // Индекс за пределами объявленного количества.
        let bad_index = Chunk {
            epoch: EpochId::INITIAL,
            index: 5,
            total: 3,
            payload: vec![0; 8],
        };
        assert!(matches!(
            assembler.accept(&bad_index),
            Err(GasAppError::Malformed)
        ));

        // Нулевое количество частей.
        let zero_total = Chunk {
            epoch: EpochId::INITIAL,
            index: 0,
            total: 0,
            payload: vec![0; 8],
        };
        assert!(matches!(
            assembler.accept(&zero_total),
            Err(GasAppError::Malformed)
        ));

        // Объявлено больше частей, чем допускает лимит.
        let too_many = Chunk {
            epoch: EpochId::INITIAL,
            index: 0,
            total: MAX_CHUNKS.saturating_add(1),
            payload: vec![0; 8],
        };
        assert!(matches!(
            assembler.accept(&too_many),
            Err(GasAppError::Malformed)
        ));
    }

    /// Противоречивое число частей в пределах одной эпохи отвергается.
    #[test]
    fn inconsistent_total_within_epoch_is_rejected() {
        let mut assembler = ChunkAssembler::new();
        let epoch = EpochId::INITIAL.next();

        assembler
            .accept(&Chunk {
                epoch,
                index: 0,
                total: 4,
                payload: vec![0; 8],
            })
            .unwrap();

        assert!(matches!(
            assembler.accept(&Chunk {
                epoch,
                index: 1,
                total: 7,
                payload: vec![0; 8],
            }),
            Err(GasAppError::Malformed)
        ));
    }

    /// Слишком большой объект не разбивается на чанки.
    #[test]
    fn oversized_payload_is_rejected() {
        let huge = vec![0u8; CHUNK_SIZE * (MAX_CHUNKS as usize + 1)];

        assert!(matches!(
            ChunkAssembler::split(&huge, EpochId::INITIAL),
            Err(GasAppError::Malformed)
        ));
    }

    /// 🔐 Полный пост-квантовый шаг: обе стороны приходят к одному секрету.
    #[test]
    fn pq_ratchet_step_converges() {
        let initial = [5u8; 32];
        let mut alice = PqRatchet::new(initial);
        let mut bob = PqRatchet::new(initial);

        assert_eq!(alice.secret(), bob.secret(), "старт с общего секрета");

        // Алиса объявляет эпоху и шлёт свой ключ чанками.
        let key_chunks = alice.begin_epoch(&mut OsRng).unwrap();

        // Боб собирает ключ, инкапсулирует и отвечает шифротекстом.
        let mut ciphertext_chunks = None;
        for chunk in &key_chunks {
            if let Some(reply) = bob.accept_key_chunk(chunk, &mut OsRng).unwrap() {
                ciphertext_chunks = Some(reply);
            }
        }
        let ciphertext_chunks = ciphertext_chunks.expect("ключ собран целиком");

        // Секреты уже разошлись: Боб продвинулся, Алиса ещё нет.
        assert_ne!(alice.secret(), bob.secret());

        // Алиса собирает шифротекст и декапсулирует.
        let mut completed = false;
        for chunk in &ciphertext_chunks {
            completed |= alice.accept_ciphertext_chunk(chunk).unwrap();
        }

        assert!(completed, "шифротекст собран целиком");
        assert_eq!(
            alice.secret(),
            bob.secret(),
            "после полного шага секреты обязаны совпасть"
        );
        assert_eq!(alice.epoch(), bob.epoch());
    }

    /// Пост-квантовый секрет меняется на каждом шаге.
    #[test]
    fn pq_ratchet_advances_the_secret() {
        let initial = [6u8; 32];
        let mut alice = PqRatchet::new(initial);
        let mut bob = PqRatchet::new(initial);

        let key_chunks = alice.begin_epoch(&mut OsRng).unwrap();
        let mut ciphertext_chunks = None;
        for chunk in &key_chunks {
            if let Some(reply) = bob.accept_key_chunk(chunk, &mut OsRng).unwrap() {
                ciphertext_chunks = Some(reply);
            }
        }
        for chunk in &ciphertext_chunks.unwrap() {
            alice.accept_ciphertext_chunk(chunk).unwrap();
        }

        assert_ne!(*alice.secret(), initial, "секрет обязан продвинуться");
        assert_eq!(alice.epoch(), EpochId::INITIAL.next());
    }

    /// Ответ без объявленной эпохи отвергается.
    ///
    /// Приватного ключа для декапсуляции нет — принимать нечего.
    #[test]
    fn ciphertext_without_epoch_is_rejected() {
        let mut ratchet = PqRatchet::new([7u8; 32]);
        let chunks = ChunkAssembler::split(&vec![0u8; 1088], EpochId::INITIAL.next()).unwrap();

        let mut result = Ok(false);
        for chunk in &chunks {
            result = ratchet.accept_ciphertext_chunk(chunk);
        }

        assert!(matches!(result, Err(GasAppError::SessionNotFound)));
    }

    /// Мусор вместо публичного ключа отвергается, а не паникует.
    #[test]
    fn malformed_public_key_is_rejected() {
        let mut ratchet = PqRatchet::new([8u8; 32]);
        // Длина не соответствует ML-KEM-768.
        let chunks = ChunkAssembler::split(&vec![0u8; 256], EpochId::INITIAL.next()).unwrap();

        let mut result = Ok(None);
        for chunk in &chunks {
            result = ratchet.accept_key_chunk(chunk, &mut OsRng);
        }

        assert!(matches!(result, Err(GasAppError::Crypto)));
    }

    /// Состояние храповика не печатает ключевой материал.
    #[test]
    fn pq_ratchet_debug_is_redacted() {
        let ratchet = PqRatchet::new([0xCD; 32]);
        let rendered = format!("{ratchet:?}");

        assert!(rendered.contains("PqRatchet"));
        assert!(!rendered.contains("cd"));
        assert!(!rendered.contains("205"));
    }

    /// Счётчик эпох насыщается вместо переполнения.
    #[test]
    fn epoch_counter_saturates() {
        let mut epoch = EpochId(u32::MAX);
        epoch = epoch.next();

        assert_eq!(epoch.as_u32(), u32::MAX);
    }
}

/// Property-based тесты инвариантов.
///
/// Отличие от тестов выше: там проверяются отдельные сценарии, здесь —
/// свойства на всём пространстве входов. Ошибку, воспроизводимую только
/// на редком сочетании длин и порядков, примерами поймать нельзя,
/// а `proptest` перебирает их сам и минимизирует найденный контрпример.
#[cfg(test)]
// См. пояснение в модуле `properties` крейтового `double_ratchet`.
#[allow(clippy::arithmetic_side_effects)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    /// Данные допустимого размера и эпоха для них.
    fn data_and_epoch() -> impl Strategy<Value = (Vec<u8>, EpochId)> {
        let max_len = CHUNK_SIZE * (MAX_CHUNKS as usize);

        (
            proptest::collection::vec(any::<u8>(), 1..=max_len),
            any::<u32>(),
        )
            .prop_map(|(data, epoch)| (data, EpochId(epoch)))
    }

    proptest! {
        /// Разбиение и сборка возвращают ровно исходные данные.
        ///
        /// Свойство проверяется на любых длинах вплоть до предельной,
        /// включая случаи, когда последний чанк неполный.
        #[test]
        fn split_then_assemble_restores_data((data, epoch) in data_and_epoch()) {
            let chunks = ChunkAssembler::split(&data, epoch).unwrap();
            let mut assembler = ChunkAssembler::new();
            let mut restored = None;

            for chunk in &chunks {
                if let Some(done) = assembler.accept(chunk).unwrap() {
                    restored = Some(done);
                }
            }

            prop_assert_eq!(restored, Some(data));
        }

        /// Сборка не зависит от порядка поступления чанков.
        ///
        /// Перестановка задаётся индексом, по которому чанки поворачиваются:
        /// так покрываются и «хвост вперёд», и произвольные сдвиги.
        #[test]
        fn assembly_is_order_independent(
            (data, epoch) in data_and_epoch(),
            rotation in 0usize..32,
        ) {
            let mut chunks = ChunkAssembler::split(&data, epoch).unwrap();
            let len = chunks.len();
            chunks.rotate_left(rotation % len);

            let mut assembler = ChunkAssembler::new();
            let mut restored = None;
            for chunk in &chunks {
                if let Some(done) = assembler.accept(chunk).unwrap() {
                    restored = Some(done);
                }
            }

            prop_assert_eq!(restored, Some(data));
        }

        /// Дубликаты не влияют на результат сборки.
        #[test]
        fn duplicates_do_not_change_result((data, epoch) in data_and_epoch()) {
            let chunks = ChunkAssembler::split(&data, epoch).unwrap();
            let mut assembler = ChunkAssembler::new();
            let mut restored = None;

            // Каждый чанк подаётся дважды подряд.
            for chunk in &chunks {
                for _ in 0..2 {
                    if let Some(done) = assembler.accept(chunk).unwrap() {
                        restored = Some(done.clone());
                    }
                }
            }

            prop_assert_eq!(restored, Some(data));
        }

        /// Сборщик никогда не паникует на произвольном входе.
        ///
        /// Чанки приходят из сети, то есть это недоверенные данные: любая
        /// комбинация полей обязана привести либо к результату, либо
        /// к ошибке, но не к панике.
        #[test]
        fn assembler_never_panics_on_arbitrary_input(
            chunks in proptest::collection::vec(
                (any::<u32>(), any::<u16>(), any::<u16>(),
                 proptest::collection::vec(any::<u8>(), 0..64)),
                1..24,
            ),
        ) {
            let mut assembler = ChunkAssembler::new();

            for (epoch, index, total, payload) in chunks {
                let chunk = Chunk {
                    epoch: EpochId(epoch),
                    index,
                    total,
                    payload,
                };

                // Результат не важен — важно отсутствие паники.
                let _ = assembler.accept(&chunk);
            }
        }

        /// 🔐 `test_no_key_collision_across_chunks`.
        ///
        /// Разный пост-квантовый материал обязан давать разные финальные
        /// ключи при одной и той же классической половине. Совпадение
        /// означало бы, что часть входа не влияет на результат — то есть
        /// гибридность где-то теряется.
        #[test]
        fn no_key_collision_across_pq_material(
            classic in any::<[u8; 32]>(),
            first in any::<[u8; 32]>(),
            second in any::<[u8; 32]>(),
        ) {
            prop_assume!(first != second);

            let left = combine(&classic, &first).unwrap();
            let right = combine(&classic, &second).unwrap();

            prop_assert_ne!(*left, *right);
        }

        /// Симметрично: разная классическая половина даёт разные ключи.
        #[test]
        fn no_key_collision_across_classic_material(
            post_quantum in any::<[u8; 32]>(),
            first in any::<[u8; 32]>(),
            second in any::<[u8; 32]>(),
        ) {
            prop_assume!(first != second);

            let left = combine(&first, &post_quantum).unwrap();
            let right = combine(&second, &post_quantum).unwrap();

            prop_assert_ne!(*left, *right);
        }

        /// Объединение детерминировано на всём пространстве входов.
        #[test]
        fn combination_is_deterministic_everywhere(
            classic in any::<[u8; 32]>(),
            post_quantum in any::<[u8; 32]>(),
        ) {
            let first = combine(&classic, &post_quantum).unwrap();
            let second = combine(&classic, &post_quantum).unwrap();

            prop_assert_eq!(*first, *second);
        }

        /// Финальный ключ не совпадает ни с одной из половин.
        ///
        /// Совпадение означало бы, что HKDF где-то пропущен и наружу
        /// уходит сам входной материал.
        #[test]
        fn combined_key_differs_from_its_inputs(
            classic in any::<[u8; 32]>(),
            post_quantum in any::<[u8; 32]>(),
        ) {
            let combined = combine(&classic, &post_quantum).unwrap();

            prop_assert_ne!(*combined, classic);
            prop_assert_ne!(*combined, post_quantum);
        }
    }
}
