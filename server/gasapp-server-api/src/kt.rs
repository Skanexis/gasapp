// SPDX-License-Identifier: AGPL-3.0-only

//! Прозрачность ключей: эпохи и доказательства (спецификация §9.7,
//! ADR-027).
//!
//! # Что здесь
//!
//! * [`run`] — раз в минуту строит эпоху, если началась новая
//!   (`repo::kt_build_epoch`; узлов несколько — строит один).
//! * `GET /v1/kt/heads[/{from}]` — корни и вершины эпох.
//! * `POST /v1/kt/proofs` — доказательства для одного индекса в
//!   нескольких эпохах.
//!
//! # 🔐 Без аутентификации — намеренно
//!
//! Клиент ходит сюда отдельной цепочкой Tor и без подписи устройства:
//! сервер не должен знать, **кто** спрашивает корни и доказательства.
//! Иначе он мог бы показать проверяющему своё дерево, а остальным —
//! настоящее. Не зная, кто спрашивает, он вынужден показывать всем одно.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::Json;
use gasapp_server_db::kt::{self, Terminal, Tree};
use gasapp_server_db::repo;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::routes::{now_millis, ApiError, AppState};

/// Как часто проверять, не началась ли новая эпоха.
pub const TICK: Duration = Duration::from_mins(1);

/// Предел эпох в одном ответе: окно самопроверки клиента (неделя)
/// с запасом.
pub const MAX_EPOCHS_PER_REQUEST: usize = 7 * 24 + 8;

/// 🔐 Предел построений деревьев на узел в минуту.
///
/// Построение — O(числа аккаунтов); кеш держит последние состояния.
/// Ограничитель по индексу от этого не защищает: индекс выбирает
/// запрашивающий, и случайные индексы с сотней старых эпох заставили
/// бы узел строить деревья без конца. Исчерпанный предел значит
/// «журнал временно недоступен» — клиент тогда просит личную сверку.
const MAX_TREE_BUILDS_PER_MINUTE: u32 = 60;

/// Сколько деревьев держать в памяти.
const TREE_CACHE: usize = 16;

/// Строит эпохи по расписанию всё время работы процесса.
pub async fn run(pool: PgPool) {
    let mut ticks = tokio::time::interval(TICK);

    loop {
        ticks.tick().await;

        match repo::kt_build_epoch(&pool, kt::epoch_at(now_millis())).await {
            // Только номер и размер — ни индексов, ни ключей.
            Ok(Some(built)) => {
                tracing::info!(epoch = built.epoch, "эпоха журнала ключей построена");
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(%error, "эпоха журнала ключей не построена"),
        }
    }
}

/// Деревья эпох по «эпохе состояния» (`repo::kt_state_epoch`): эпохи
/// без изменений делят одно дерево.
fn cache() -> &'static Mutex<HashMap<i64, Arc<Tree>>> {
    static CACHE: OnceLock<Mutex<HashMap<i64, Arc<Tree>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Разрешено ли ещё одно построение дерева в текущей минуте.
fn allow_build(now_millis: i64) -> bool {
    static BUILDS: Mutex<(i64, u32)> = Mutex::new((0, 0));

    let Ok(mut builds) = BUILDS.lock() else {
        return false;
    };
    let minute = now_millis.div_euclid(60_000);

    if builds.0 != minute {
        *builds = (minute, 0);
    }
    if builds.1 >= MAX_TREE_BUILDS_PER_MINUTE {
        return false;
    }
    builds.1 = builds.1.saturating_add(1);

    true
}

async fn tree_for(pool: &PgPool, epoch: i64) -> Result<Arc<Tree>, ApiError> {
    let state = repo::kt_state_epoch(pool, epoch).await?.unwrap_or(-1);

    if let Some(tree) = cache().lock().map_err(|_| ApiError::Internal)?.get(&state) {
        return Ok(Arc::clone(tree));
    }

    if !allow_build(now_millis()) {
        return Err(ApiError::TooManyRequests);
    }

    let leaves = repo::kt_leaves_at(pool, epoch).await?;
    let tree = Arc::new(Tree::new(leaves.iter().map(repo::KtLeaf::entry).collect()));

    let mut cache = cache().lock().map_err(|_| ApiError::Internal)?;
    if cache.len() >= TREE_CACHE {
        // Вытесняется самое старое состояние: свежие нужнее.
        if let Some(oldest) = cache.keys().min().copied() {
            cache.remove(&oldest);
        }
    }
    cache.insert(state, Arc::clone(&tree));

    Ok(tree)
}

/// Эпоха в ответе.
#[derive(Debug, Serialize, Deserialize)]
pub struct EpochView {
    /// Номер.
    pub epoch: i64,
    /// Корень, hex.
    pub root: String,
    /// Вершина, hex.
    pub head: String,
}

/// Ответ со списком эпох.
#[derive(Debug, Serialize, Deserialize)]
pub struct HeadsResponse {
    /// Эпохи по возрастанию.
    pub epochs: Vec<EpochView>,
}

/// `GET /v1/kt/heads` — окно истории до последней эпохи.
///
/// # Errors
///
/// [`ApiError`] — сбой базы.
pub async fn heads_all(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HeadsResponse>, ApiError> {
    heads_since(&state, None).await
}

/// `GET /v1/kt/heads/{from}` — эпохи начиная с `from`.
///
/// # Errors
///
/// [`ApiError`] — сбой базы.
pub async fn heads_from(
    State(state): State<Arc<AppState>>,
    Path(from): Path<i64>,
) -> Result<Json<HeadsResponse>, ApiError> {
    heads_since(&state, Some(from)).await
}

/// Эпохи начиная с `from`; без `from` — окно истории. Раньше окна истории
/// эпох нет: клиенту, отсутствовавшему дольше, приходится начать
/// цепочку заново.
///
/// # Errors
///
/// [`ApiError`] — сбой базы.
async fn heads_since(state: &AppState, from: Option<i64>) -> Result<Json<HeadsResponse>, ApiError> {
    let latest = repo::kt_latest_epoch(&state.pool).await?;
    let floor = latest
        .as_ref()
        .map_or(0, |latest| latest.epoch.saturating_sub(kt::HISTORY_EPOCHS));
    let from = from.unwrap_or(floor).max(floor);

    let epochs = repo::kt_epochs_from(
        &state.pool,
        from,
        i64::try_from(MAX_EPOCHS_PER_REQUEST).unwrap_or(i64::MAX),
    )
    .await?;

    Ok(Json(HeadsResponse {
        epochs: epochs
            .into_iter()
            .map(|epoch| EpochView {
                epoch: epoch.epoch,
                root: hex::encode(epoch.root),
                head: hex::encode(epoch.head),
            })
            .collect(),
    }))
}

/// Запрос доказательств.
#[derive(Debug, Deserialize)]
pub struct ProofsRequest {
    /// Индекс (хеш имени), hex.
    pub index: String,
    /// Эпохи.
    pub epochs: Vec<i64>,
}

/// Лист в ответе.
#[derive(Debug, Serialize, Deserialize)]
pub struct LeafView {
    /// Identity-ключ, hex.
    pub identity_key: String,
    /// Хеш пост-квантовой половины, hex.
    pub pq_hash: String,
    /// Версия.
    pub version: u64,
}

/// Чужой лист на конце пути (доказательство отсутствия).
#[derive(Debug, Serialize, Deserialize)]
pub struct OtherLeafView {
    /// Индекс, hex.
    pub index: String,
    /// Значение, hex.
    pub value: String,
}

/// Доказательство в ответе.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProofView {
    /// Эпоха.
    pub epoch: i64,
    /// Лист индекса, если он есть.
    pub leaf: Option<LeafView>,
    /// Чужой лист на конце пути, если индекса нет, а поддерево не пусто.
    pub other: Option<OtherLeafView>,
    /// Соседи от корня вниз, hex.
    pub siblings: Vec<String>,
}

/// Ответ с доказательствами.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProofsResponse {
    /// Доказательства для существующих эпох (несуществующие пропущены).
    pub proofs: Vec<ProofView>,
}

/// `POST /v1/kt/proofs`.
///
/// # Errors
///
/// * [`ApiError::BadRequest`] — индекс не 32 байта в hex или эпох
///   больше [`MAX_EPOCHS_PER_REQUEST`];
/// * [`ApiError::TooManyRequests`] — исчерпан предел построений деревьев
///   на узле;
/// * [`ApiError`] — сбой базы.
pub async fn proofs(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ProofsRequest>,
) -> Result<Json<ProofsResponse>, ApiError> {
    let index: [u8; 32] = hex::decode(&request.index)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ApiError::BadRequest)?;

    if request.epochs.is_empty() || request.epochs.len() > MAX_EPOCHS_PER_REQUEST {
        return Err(ApiError::BadRequest);
    }

    // 🔐 Ограничителя по индексу нет — намеренно. Он позволял
    // постороннему выбрать бюджет чужого имени и сорвать владельцу
    // проверку своей записи (как раз то, что прячет подмену). Нагрузку
    // держит глобальный предел построений деревьев, а следить за сменой
    // ключа через журнал не быстрее, чем через discovery: эпоха — час.

    let mut epochs = request.epochs.clone();
    epochs.sort_unstable();
    epochs.dedup();

    let mut proofs = Vec::with_capacity(epochs.len());

    for epoch in epochs {
        // Только существующие эпохи: для прочих доказывать не против чего.
        match repo::kt_epochs_before(&state.pool, epoch).await? {
            Some(found) if found.epoch == epoch => {}
            _ => continue,
        }

        let tree = tree_for(&state.pool, epoch).await?;
        let proof = tree.prove(&index);

        let (leaf, other) = match proof.terminal {
            Terminal::Empty => (None, None),
            Terminal::Leaf {
                index: leaf_index,
                value,
            } if leaf_index == index => {
                // Сам лист — из базы: значение хеширует ключ, и клиенту
                // нужны исходные поля, чтобы его пересчитать.
                let leaf = repo::kt_leaf_at(&state.pool, &index, epoch)
                    .await?
                    .ok_or(ApiError::Internal)?;
                if leaf.entry().1 != value {
                    return Err(ApiError::Internal);
                }

                (
                    Some(LeafView {
                        identity_key: hex::encode(leaf.identity_key),
                        pq_hash: hex::encode(leaf.pq_hash),
                        version: leaf.version,
                    }),
                    None,
                )
            }
            Terminal::Leaf {
                index: leaf_index,
                value,
            } => (
                None,
                Some(OtherLeafView {
                    index: hex::encode(leaf_index),
                    value: hex::encode(value),
                }),
            ),
        };

        proofs.push(ProofView {
            epoch,
            leaf,
            other,
            siblings: proof.siblings.iter().map(hex::encode).collect(),
        });
    }

    Ok(Json(ProofsResponse { proofs }))
}
