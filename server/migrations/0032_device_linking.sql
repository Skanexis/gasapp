-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 0032: несколько устройств на аккаунте (docs/protocol/MULTI-DEVICE.md).
--
-- * `device_lists` — подписанный список устройств аккаунта (SDL). Подпись
--   ключа аккаунта проверяют клиенты; сервер хранит последнюю версию и
--   принимает новую только от основного устройства (его identity — ключ
--   аккаунта) и только с большей версией.
-- * `link_boxes` — ящики связывания по QR: новое устройство кладёт запрос
--   (открытые ключи), основное — грант (шифротекст для нового) и список с
--   новым устройством. Живут две минуты, грант отдаётся по nonce из QR.
--
-- 🔐 Сервер видит: что у аккаунта появилось устройство (с точностью до
-- часа) и сколько их. Грант — шифротекст для нового устройства; ключей
-- аккаунта и переписки в нём сервер прочитать не может.

CREATE TABLE device_lists (
    account_id UUID PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
    version    BIGINT NOT NULL CHECK (version >= 1),
    signed     BYTEA NOT NULL CHECK (octet_length(signed) BETWEEN 64 AND 20000),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', now())
);

CREATE TABLE link_boxes (
    nonce          UUID PRIMARY KEY,
    request        BYTEA NOT NULL CHECK (octet_length(request) BETWEEN 77 AND 8192),
    -- Заполняется, когда основное устройство выдало грант.
    account_id     UUID REFERENCES accounts(account_id) ON DELETE CASCADE,
    grant_blob     BYTEA CHECK (grant_blob IS NULL OR octet_length(grant_blob) <= 1200000),
    device_list    BYTEA CHECK (device_list IS NULL OR octet_length(device_list) BETWEEN 64 AND 20000),
    list_version   BIGINT,
    expires_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX link_boxes_by_expiry ON link_boxes (expires_at);

-- Пост-квантовая половина identity **подключённого** устройства и её
-- привязка к его классическому ключу. У основного устройства она та же,
-- что у аккаунта (`accounts.pq_identity_key`), — здесь пусто.
-- 🔐 Подключённое устройство не может менять половину аккаунта.
ALTER TABLE devices
    ADD COLUMN pq_identity_key  BYTEA,
    ADD COLUMN identity_binding BYTEA;
