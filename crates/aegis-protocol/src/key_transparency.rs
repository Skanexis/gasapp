// SPDX-License-Identifier: Apache-2.0

//! Прозрачность ключей (Key Transparency, KT) — автоматическая сверка
//! ключа собеседника при поиске по имени (спецификация §9.7, ADR-027).
//!
//! # Зачем
//!
//! При первом контакте через поиск по `@имени` ключ собеседника называет
//! сервер. До этого модуля такой ключ годился для отправки только после
//! личной сверки: иначе сервер мог подставить свой. Журнал ключей делает
//! подмену **видимой и доказуемой**: сервер обязан показывать всем одно
//! и то же дерево «имя → ключ», и владелец имени проверяет в нём себя.
//!
//! # Устройство
//!
//! * Раз в эпоху ([`EPOCH_MILLIS`]) сервер строит разреженное
//!   Merkle-дерево: индекс — [`index`] от имени, лист — [`leaf_value`]
//!   от identity-ключа, хеша пост-квантовой половины и версии.
//! * Корни эпох связаны в хеш-цепочку ([`head`]): переписать прошлое
//!   нельзя, не разойдясь с цепочкой, которую клиенты уже видели.
//! * Клиент проверяет ключ собеседника доказательством ([`Proof`])
//!   против корня из своей цепочки — **и сейчас, и
//!   [`TRUST_DELAY_EPOCHS`] эпох назад**. Свежую подмену владелец имени
//!   успевает увидеть раньше, чем ей поверят.
//! * Свой лист клиент проверяет за каждую эпоху ([`MONITOR_WINDOW_EPOCHS`]):
//!   чужой ключ под своим именем — тревога с доказательством.
//!
//! # Дерево
//!
//! Компактное разреженное дерево глубины 256 (как в Diem/Aptos JMT):
//! поддерево с одним листом представлено самим листом, пустое —
//! [`ZERO`], с двумя и более — внутренним узлом. Узлы листа и внутренние
//! узлы разделены доменом (0x00 / 0x01), поэтому у любого узла ровно
//! одно толкование, и по одному корню нельзя доказать два разных листа
//! для одного индекса — даже если дерево строил злонамеренный сервер.
//!
//! # 🔐 Чего сервер из журнала не узнаёт
//!
//! Ничего нового: имя и ключ он хранит и так. Наружу уходят только
//! хеши; индексы — хеши имён, и доказательства выдаются по одному
//! индексу, а не деревом целиком.

use sha2::{Digest, Sha256};

/// Длительность эпохи: час.
pub const EPOCH_MILLIS: i64 = 60 * 60 * 1000;

/// Сколько эпох ключ должен простоять в журнале без изменений, чтобы
/// ему поверили без личной сверки: сутки (решение владельца 2026-09-25).
pub const TRUST_DELAY_EPOCHS: u64 = 24;

/// За сколько эпох назад клиент проверяет свой лист: неделя.
pub const MONITOR_WINDOW_EPOCHS: u64 = 7 * 24;

/// Сколько эпох хранит сервер (и клиент — вершин): неделя и сутки.
pub const HISTORY_EPOCHS: u64 = 8 * 24;

/// Предел глубины дерева: 256 бит индекса.
pub const MAX_DEPTH: usize = 256;

/// Хеш пустого поддерева.
pub const ZERO: [u8; 32] = [0u8; 32];

const INDEX_DOMAIN: &[u8] = b"AEGIS_KT_INDEX_v1";
const LEAF_DOMAIN: &[u8] = b"AEGIS_KT_LEAF_v1";
const HEAD_DOMAIN: &[u8] = b"AEGIS_KT_HEAD_v1";
const LEAF_NODE: u8 = 0x00;
const INNER_NODE: u8 = 0x01;

/// Почему доказательство не принято.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KtError {
    /// Доказательство не сходится с корнем или противоречит себе.
    #[error("key transparency proof rejected")]
    Invalid,
}

/// Номер эпохи для момента `millis` (Unix, мс).
#[must_use]
pub fn epoch_at(millis: i64) -> u64 {
    u64::try_from(millis.max(0).div_euclid(EPOCH_MILLIS)).unwrap_or(0)
}

/// Индекс имени в дереве.
#[must_use]
pub fn index(username: &str) -> [u8; 32] {
    let bytes = username.as_bytes();

    Sha256::new()
        .chain_update(INDEX_DOMAIN)
        .chain_update(len32(bytes.len()))
        .chain_update(bytes)
        .finalize()
        .into()
}

/// Значение листа: identity-ключ, хеш пост-квантовой половины, версия.
#[must_use]
pub fn leaf_value(
    index: &[u8; 32],
    identity_key: &[u8; 32],
    pq_identity_hash: &[u8; 32],
    version: u64,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(LEAF_DOMAIN)
        .chain_update(index)
        .chain_update(identity_key)
        .chain_update(pq_identity_hash)
        .chain_update(version.to_be_bytes())
        .finalize()
        .into()
}

/// Хеш узла-листа.
#[must_use]
pub fn leaf_hash(index: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update([LEAF_NODE])
        .chain_update(index)
        .chain_update(value)
        .finalize()
        .into()
}

/// Хеш внутреннего узла.
#[must_use]
pub fn inner_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update([INNER_NODE])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// Вершина эпохи: номер, корень дерева и вершина предыдущей эпохи.
#[must_use]
pub fn head(epoch: u64, root: &[u8; 32], previous: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(HEAD_DOMAIN)
        .chain_update(epoch.to_be_bytes())
        .chain_update(root)
        .chain_update(previous)
        .finalize()
        .into()
}

/// Бит индекса на глубине `depth` (старший бит первого байта — глубина 0).
fn bit(index: &[u8; 32], depth: usize) -> bool {
    index
        .get(depth >> 3)
        .is_some_and(|byte| byte.rotate_left(u32::try_from(depth & 7).unwrap_or(0)) & 0x80 != 0)
}

/// Совпадают ли первые `depth` бит двух индексов.
fn same_prefix(a: &[u8; 32], b: &[u8; 32], depth: usize) -> bool {
    (0..depth).all(|d| bit(a, d) == bit(b, d))
}

fn len32(len: usize) -> [u8; 4] {
    u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes()
}

/// Чем кончается путь к индексу.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminal {
    /// Пустое поддерево: индекса нет.
    Empty,
    /// Единственный лист поддерева: либо искомый, либо чужой (тогда
    /// искомого нет).
    Leaf {
        /// Индекс листа.
        index: [u8; 32],
        /// Значение листа.
        value: [u8; 32],
    },
}

/// Доказательство для одного индекса в одной эпохе.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// Соседи по пути от корня вниз.
    pub siblings: Vec<[u8; 32]>,
    /// Конец пути.
    pub terminal: Terminal,
}

impl Proof {
    /// Проверяет доказательство против корня.
    ///
    /// `expected` — значение листа, если индекс должен быть в дереве;
    /// `None` — индекса в дереве быть не должно.
    ///
    /// # Errors
    ///
    /// [`KtError::Invalid`] — не сходится с корнем, путь длиннее 256,
    /// конечный лист лежит не на пути индекса, либо доказано
    /// не то, что ожидалось.
    pub fn verify(
        &self,
        root: &[u8; 32],
        index: &[u8; 32],
        expected: Option<&[u8; 32]>,
    ) -> Result<(), KtError> {
        let depth = self.siblings.len();

        if depth > MAX_DEPTH {
            return Err(KtError::Invalid);
        }

        let start = match (&self.terminal, expected) {
            (Terminal::Empty, None) => ZERO,
            (
                Terminal::Leaf {
                    index: other,
                    value,
                },
                expected,
            ) => {
                // Лист обязан лежать на пути индекса.
                if !same_prefix(other, index, depth) {
                    return Err(KtError::Invalid);
                }

                match expected {
                    Some(expected) if other == index && value == expected => {}
                    None if other != index => {}
                    _ => return Err(KtError::Invalid),
                }

                leaf_hash(other, value)
            }
            (Terminal::Empty, Some(_)) => return Err(KtError::Invalid),
        };

        let mut hash = start;
        for (depth, sibling) in self.siblings.iter().enumerate().rev() {
            hash = if bit(index, depth) {
                inner_hash(sibling, &hash)
            } else {
                inner_hash(&hash, sibling)
            };
        }

        if &hash == root {
            Ok(())
        } else {
            Err(KtError::Invalid)
        }
    }
}

/// Дерево эпохи: листы, отсортированные по индексу.
///
/// Нужно клиенту только в тестах и в подставном сервере сквозных тестов;
/// у настоящего сервера — своя реализация тех же правил, сверенная
/// эталоном (`tests::reference_root`).
#[derive(Debug, Clone, Default)]
pub struct Tree {
    leaves: Vec<([u8; 32], [u8; 32])>,
}

impl Tree {
    /// Дерево из пар «индекс, значение». Повтор индекса — последнее
    /// значение.
    #[must_use]
    pub fn new(mut leaves: Vec<([u8; 32], [u8; 32])>) -> Self {
        leaves.sort_by_key(|entry| entry.0);
        leaves.reverse();
        leaves.dedup_by(|a, b| a.0 == b.0);
        leaves.reverse();

        Self { leaves }
    }

    /// Корень.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        subtree(&self.leaves, 0)
    }

    /// Доказательство для индекса.
    #[must_use]
    pub fn prove(&self, index: &[u8; 32]) -> Proof {
        let mut slice: &[([u8; 32], [u8; 32])] = &self.leaves;
        let mut siblings = Vec::new();
        let mut depth = 0;

        loop {
            match slice {
                [] => {
                    return Proof {
                        siblings,
                        terminal: Terminal::Empty,
                    }
                }
                [(leaf_index, value)] => {
                    return Proof {
                        siblings,
                        terminal: Terminal::Leaf {
                            index: *leaf_index,
                            value: *value,
                        },
                    }
                }
                _ if depth >= MAX_DEPTH => {
                    // Недостижимо: индексы уникальны.
                    return Proof {
                        siblings,
                        terminal: Terminal::Empty,
                    };
                }
                _ => {
                    let split = slice.partition_point(|(i, _)| !bit(i, depth));
                    let (left, right) = slice.split_at(split);

                    if bit(index, depth) {
                        siblings.push(subtree(left, depth.saturating_add(1)));
                        slice = right;
                    } else {
                        siblings.push(subtree(right, depth.saturating_add(1)));
                        slice = left;
                    }
                    depth = depth.saturating_add(1);
                }
            }
        }
    }
}

/// Хеш поддерева из отсортированных листов, лежащих на глубине `depth`.
fn subtree(leaves: &[([u8; 32], [u8; 32])], depth: usize) -> [u8; 32] {
    match leaves {
        [] => ZERO,
        [(index, value)] => leaf_hash(index, value),
        _ if depth >= MAX_DEPTH => ZERO,
        _ => {
            let split = leaves.partition_point(|(i, _)| !bit(i, depth));
            let (left, right) = leaves.split_at(split);
            let next = depth.saturating_add(1);

            inner_hash(&subtree(left, next), &subtree(right, next))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_for(name: &str, key: u8, version: u64) -> ([u8; 32], [u8; 32]) {
        let idx = index(name);
        (
            idx,
            leaf_value(&idx, &[key; 32], &[key ^ 0xFF; 32], version),
        )
    }

    fn sample() -> Tree {
        Tree::new(
            ["alice", "bob", "carol", "dave", "erin", "frank", "grace"]
                .iter()
                .enumerate()
                .map(|(i, name)| value_for(name, u8::try_from(i).expect("мало"), 1))
                .collect(),
        )
    }

    #[test]
    fn membership_and_absence_are_proved() {
        let tree = sample();
        let root = tree.root();

        // В `sample` ключ имени — его номер в списке.
        for (name, key) in [("alice", 0), ("dave", 3), ("grace", 6)] {
            let (idx, value) = value_for(name, key, 1);
            tree.prove(&idx)
                .verify(&root, &idx, Some(&value))
                .expect("лист есть");
        }

        for name in ["mallory", "trent", "zed"] {
            let idx = index(name);
            tree.prove(&idx)
                .verify(&root, &idx, None)
                .expect("листа нет");
        }
    }

    /// 🔐 Один корень — один ответ: подменить значение, доказать
    /// отсутствие существующего или присутствие чужого нельзя.
    #[test]
    fn forged_proofs_are_rejected() {
        let tree = sample();
        let root = tree.root();
        let (alice, value) = value_for("alice", 0, 1);
        let (_, forged) = value_for("alice", 9, 1);
        let proof = tree.prove(&alice);

        assert!(
            proof.verify(&root, &alice, Some(&forged)).is_err(),
            "чужое значение"
        );
        assert!(
            proof.verify(&root, &alice, None).is_err(),
            "отсутствие существующего"
        );

        let mallory = index("mallory");
        assert!(tree
            .prove(&mallory)
            .verify(&root, &mallory, Some(&value))
            .is_err());

        // Доказательство Алисы, выданное за Мэллори.
        assert!(proof.verify(&root, &mallory, Some(&value)).is_err());

        // Испорченный сосед.
        let mut broken = proof.clone();
        if let Some(first) = broken.siblings.first_mut() {
            first[0] ^= 1;
        }
        assert!(broken.verify(&root, &alice, Some(&value)).is_err());

        // Тот же лист на чужом пути.
        let mut moved = proof;
        moved.siblings.push(ZERO);
        assert!(moved.verify(&root, &alice, Some(&value)).is_err());
    }

    #[test]
    fn empty_and_single_trees() {
        let empty = Tree::default();
        assert_eq!(empty.root(), ZERO);
        let idx = index("anyone");
        empty.prove(&idx).verify(&ZERO, &idx, None).expect("пусто");

        let (alice, value) = value_for("alice", 1, 1);
        let single = Tree::new(vec![(alice, value)]);
        assert_eq!(single.root(), leaf_hash(&alice, &value));
        single
            .prove(&alice)
            .verify(&single.root(), &alice, Some(&value))
            .expect("один");
        let bob = index("bob");
        single
            .prove(&bob)
            .verify(&single.root(), &bob, None)
            .expect("нет боба");
    }

    #[test]
    fn epochs_follow_the_clock() {
        assert_eq!(epoch_at(0), 0);
        assert_eq!(epoch_at(EPOCH_MILLIS - 1), 0);
        assert_eq!(epoch_at(EPOCH_MILLIS), 1);
        assert_eq!(epoch_at(-5), 0);
    }

    /// 🔐 Эталон для сервера (`aegis-server-api/src/kt.rs`): те же имена,
    /// те же значения — тот же корень и та же вершина. Расхождение
    /// означает, что клиент не примет ни одного доказательства сервера.
    #[test]
    fn reference_root() {
        let tree = sample();
        let root = tree.root();
        let first = head(1, &root, &ZERO);

        assert_eq!(hex::encode(index("alice")), REFERENCE_INDEX);
        assert_eq!(hex::encode(root), REFERENCE_ROOT);
        assert_eq!(hex::encode(first), REFERENCE_HEAD);
    }

    const REFERENCE_INDEX: &str =
        "4eed80ab43350231c0cbb715565fefeeff27aaf6b22ce7fd18a2969f574f6cfe";
    const REFERENCE_ROOT: &str = "48c861e0ad254963ef7c6451f126f0730cb10a05330c68006696ebb19616460c";
    const REFERENCE_HEAD: &str = "dfb7298ddd35c1ded662248f124fbcbfb01400cd4aea7540397e7ee5f01d0ee5";
}
