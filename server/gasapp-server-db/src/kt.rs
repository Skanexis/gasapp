// SPDX-License-Identifier: AGPL-3.0-only

//! Прозрачность ключей: хеши и дерево на стороне сервера
//! (спецификация §9.7, ADR-027).
//!
//! Правила — те же, что в клиенте (`gasapp_protocol::key_transparency`),
//! реализованные отдельно: серверный и клиентский workspace друг друга
//! не видят (ADR-006). Совпадение закреплено эталоном
//! (`tests::reference_root`) с теми же значениями, что у клиента:
//! разойдись правила — клиент не примет ни одного доказательства.
//!
//! Проверки доказательств здесь нет: сервер доказательства выдаёт,
//! а проверяет их клиент.

use sha2::{Digest, Sha256};

/// Длительность эпохи: час.
pub const EPOCH_MILLIS: i64 = 60 * 60 * 1000;

/// Сколько эпох хранится история: неделя и сутки.
pub const HISTORY_EPOCHS: i64 = 8 * 24;

/// Хеш пустого поддерева.
pub const ZERO: [u8; 32] = [0u8; 32];

/// Предел глубины дерева.
const MAX_DEPTH: usize = 256;

const INDEX_DOMAIN: &[u8] = b"GASAPP_KT_INDEX_v1";
const LEAF_DOMAIN: &[u8] = b"GASAPP_KT_LEAF_v1";
const HEAD_DOMAIN: &[u8] = b"GASAPP_KT_HEAD_v1";
const PQ_HASH_DOMAIN: &[u8] = b"GASAPP_PQID_HASH_v1";
const LEAF_NODE: u8 = 0x00;
const INNER_NODE: u8 = 0x01;

/// Номер эпохи для момента `millis` (Unix, мс).
#[must_use]
pub fn epoch_at(millis: i64) -> i64 {
    millis.max(0).div_euclid(EPOCH_MILLIS)
}

/// Индекс имени.
#[must_use]
pub fn index(username: &str) -> [u8; 32] {
    let bytes = username.as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes();

    Sha256::new()
        .chain_update(INDEX_DOMAIN)
        .chain_update(len)
        .chain_update(bytes)
        .finalize()
        .into()
}

/// Хеш пост-квантовой половины identity — как `pq_identity_hash` клиента.
#[must_use]
pub fn pq_identity_hash(public: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(PQ_HASH_DOMAIN)
        .chain_update(public)
        .finalize()
        .into()
}

/// Значение листа.
#[must_use]
pub fn leaf_value(
    index: &[u8; 32],
    identity_key: &[u8; 32],
    pq_hash: &[u8; 32],
    version: u64,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(LEAF_DOMAIN)
        .chain_update(index)
        .chain_update(identity_key)
        .chain_update(pq_hash)
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

/// Вершина эпохи.
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

fn bit(index: &[u8; 32], depth: usize) -> bool {
    index
        .get(depth >> 3)
        .is_some_and(|byte| byte.rotate_left(u32::try_from(depth & 7).unwrap_or(0)) & 0x80 != 0)
}

/// Конец пути доказательства.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminal {
    /// Пустое поддерево.
    Empty,
    /// Единственный лист поддерева.
    Leaf {
        /// Индекс листа.
        index: [u8; 32],
        /// Значение листа.
        value: [u8; 32],
    },
}

/// Доказательство для индекса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// Соседи от корня вниз.
    pub siblings: Vec<[u8; 32]>,
    /// Конец пути.
    pub terminal: Terminal,
}

/// Дерево эпохи.
#[derive(Debug, Clone, Default)]
pub struct Tree {
    leaves: Vec<([u8; 32], [u8; 32])>,
}

impl Tree {
    /// Дерево из пар «индекс, значение» (повтор индекса — последнее).
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
                    return Proof {
                        siblings,
                        terminal: Terminal::Empty,
                    }
                }
                _ => {
                    let split = slice.partition_point(|(i, _)| !bit(i, depth));
                    let (left, right) = slice.split_at(split);
                    let next = depth.saturating_add(1);

                    if bit(index, depth) {
                        siblings.push(subtree(left, next));
                        slice = right;
                    } else {
                        siblings.push(subtree(right, next));
                        slice = left;
                    }
                    depth = next;
                }
            }
        }
    }
}

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

    /// Эталон клиента: `gasapp_protocol::key_transparency::tests::reference_root`.
    #[test]
    fn reference_root() {
        let tree = Tree::new(
            ["alice", "bob", "carol", "dave", "erin", "frank", "grace"]
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    let key = u8::try_from(i).expect("мало");
                    let idx = index(name);
                    (idx, leaf_value(&idx, &[key; 32], &[key ^ 0xFF; 32], 1))
                })
                .collect(),
        );
        let root = tree.root();

        assert_eq!(
            hex(&index("alice")),
            "59f2c57ab513349ed11f777259f5e3cc270aa82f1cecdef08d6139bbd348405b"
        );
        assert_eq!(
            hex(&root),
            "1e86b3e99f262d5a4166c2033d6a587ca5a263638d2e134dc156ca511ee0e095"
        );
        assert_eq!(
            hex(&head(1, &root, &ZERO)),
            "90b31a0b5a5c9efdc9dee2449079e5b5b0b4d48f095b3a555683c9f0e966eea1"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }
}
