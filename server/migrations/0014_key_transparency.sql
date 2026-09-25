-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Прозрачность ключей (спецификация §9.7, ADR-027).
--
-- Сервер ведёт журнал «имя → ключ»: раз в час строит Merkle-дерево,
-- корни эпох связаны в хеш-цепочку. Клиенты проверяют по нему ключ
-- собеседника и свой собственный, и подмена ключа сервером становится
-- видимой и доказуемой.
--
-- 🔐 Что здесь нового хранится — и чего нет.
--
-- Нового знания нет: имя, identity-ключ и пост-квантовая половина
-- лежат в accounts и так. Вместо имени в журнале — его хеш (индекс),
-- вместо половины — её хеш. История листов хранится неделю и сутки
-- (HISTORY_EPOCHS): ровно столько, сколько нужно клиентам для выдержки
-- в сутки и проверки своего листа за неделю отсутствия. Более старые
-- строки удаляются при построении эпохи — кроме последней для индекса.

-- Версия ключа имени: растёт при каждой перепривязке аккаунта
-- к новой identity (возвращение аккаунта, миграция 0013).
ALTER TABLE accounts
    ADD COLUMN key_version BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT key_version_positive CHECK (key_version >= 1);

-- Листы журнала: значение индекса начиная с эпохи epoch_from.
-- identity_key IS NULL — имя исчезло (аккаунт удалён).
CREATE TABLE kt_leaves (
    idx           BYTEA  NOT NULL CHECK (octet_length(idx) = 32),
    epoch_from    BIGINT NOT NULL CHECK (epoch_from >= 0),
    identity_key  BYTEA  CHECK (identity_key IS NULL OR octet_length(identity_key) = 32),
    pq_hash       BYTEA  CHECK (pq_hash IS NULL OR octet_length(pq_hash) = 32),
    version       BIGINT NOT NULL CHECK (version >= 1),
    PRIMARY KEY (idx, epoch_from),
    CHECK ((identity_key IS NULL) = (pq_hash IS NULL))
);

-- Эпохи: корень дерева и вершина хеш-цепочки.
CREATE TABLE kt_epochs (
    epoch  BIGINT PRIMARY KEY CHECK (epoch >= 0),
    root   BYTEA  NOT NULL CHECK (octet_length(root) = 32),
    head   BYTEA  NOT NULL CHECK (octet_length(head) = 32)
);
