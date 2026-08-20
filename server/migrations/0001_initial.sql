-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Начальная схема сервера AEGIS.
--
-- Общий принцип: сервер хранит минимум, необходимый для маршрутизации,
-- и ничего сверх. Каждая таблица ниже сопровождается ответом на вопрос
-- «что узнает тот, кто получит дамп этой базы».

-- Аккаунты.
--
-- Дамп даёт: список username и публичных identity-ключей. Ни телефонов,
-- ни email, ни паролей — их нет в системе вовсе (ADR-007).
CREATE TABLE accounts (
    account_id    UUID PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    identity_key  BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Устройства аккаунта.
--
-- Дамп даёт: сколько устройств у аккаунта. Имя устройства задаёт
-- пользователь и может не указывать.
CREATE TABLE devices (
    device_id     UUID PRIMARY KEY,
    account_id    UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    device_name   TEXT,
    identity_key  BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ
);

CREATE INDEX devices_by_account ON devices (account_id);

-- Подписанные предключи: по одному актуальному на устройство.
--
-- Дамп даёт: публичные предключи. Они и так раздаются любому, кто
-- спросит, — в этом их назначение.
CREATE TABLE signed_prekeys (
    device_id     UUID PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
    key_id        INTEGER NOT NULL,
    public_key    BYTEA NOT NULL,
    signature     BYTEA NOT NULL,
    kem_key_id    INTEGER NOT NULL,
    kem_public    BYTEA NOT NULL,
    kem_signature BYTEA NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Одноразовые предключи.
--
-- Расходуются при выдаче: строка удаляется, а не помечается. Пометка
-- означала бы, что сервер накапливает историю «кто у кого спрашивал
-- ключи», то есть фрагмент социального графа (раздел 15 плана).
CREATE TABLE one_time_prekeys (
    id          BIGSERIAL PRIMARY KEY,
    device_id   UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    key_id      INTEGER NOT NULL,
    public_key  BYTEA NOT NULL,
    -- Пост-квантовые предключи подписаны, классические — нет
    -- (раздел 6.2: подмена OPK ничего не даёт, подмена PQOPK даёт).
    signature   BYTEA,
    is_kem      BOOLEAN NOT NULL,
    UNIQUE (device_id, key_id, is_kem)
);

CREATE INDEX one_time_prekeys_by_device ON one_time_prekeys (device_id, is_kem);

-- Очередь недоставленных сообщений.
--
-- Дамп даёт: шифроблобы и метаданные доставки. Содержимое недоступно:
-- у сервера нет ключей.
--
-- `queued_at` округляется до часа перед выдачей клиенту, чтобы точное
-- время не служило признаком для корреляции (раздел 15).
CREATE TABLE envelopes (
    envelope_id           UUID PRIMARY KEY,
    destination_device_id UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    ciphertext            BYTEA NOT NULL,
    queued_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- TTL: недоставленное удаляется через 30 дней (раздел 14.4).
    expires_at            TIMESTAMPTZ NOT NULL
);

CREATE INDEX envelopes_by_destination ON envelopes (destination_device_id, queued_at);
CREATE INDEX envelopes_by_expiry ON envelopes (expires_at);

-- Ограничение размера конверта — 256 КБ (раздел 14.5).
--
-- Проверка на уровне схемы, а не только в коде: она действует и для
-- запросов, написанных в обход API.
ALTER TABLE envelopes
    ADD CONSTRAINT envelope_size_limit CHECK (octet_length(ciphertext) <= 262144);
