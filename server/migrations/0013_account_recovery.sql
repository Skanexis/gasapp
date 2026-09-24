-- 0013: ключ восстановления аккаунта — имя переживает переустановку.
--
-- Приватный identity-ключ не копируется между устройствами (13.1),
-- поэтому новая установка приходит с новой identity. Право на прежнее
-- имя доказывает гибридная подпись ключа восстановления: его открытые
-- половины сервер получает при регистрации, секрет лежит в
-- зашифрованной резервной копии владельца.
--
-- `recovered_at` — момент последней перепривязки (мс): запрос с тем же
-- или более ранним моментом отвергается, повтор перехваченного запроса
-- ничего не даёт.

ALTER TABLE accounts
    ADD COLUMN recovery_key BYTEA,
    ADD COLUMN recovery_pq_key BYTEA,
    ADD COLUMN recovered_at BIGINT,
    ADD CONSTRAINT recovery_key_len
        CHECK (recovery_key IS NULL OR octet_length(recovery_key) = 32),
    ADD CONSTRAINT recovery_pq_key_len
        CHECK (recovery_pq_key IS NULL OR octet_length(recovery_pq_key) = 1952);
