-- 0012: пост-квантовая половина identity (ML-DSA-65, FIPS 204).
--
-- # Зачем
--
-- Подписи предключей и ключа sealed sender держались на одной кривой:
-- квантовый противник в момент атаки подделал бы их и подставил свои
-- ключи. Теперь подписи гибридные (XEdDSA ‖ ML-DSA-65), и у аккаунта
-- вторая половина identity — открытый ключ ML-DSA-65 с гибридной
-- привязкой к классическому.
--
-- Сервер ничего не проверяет: он хранит и раздаёт. Проверяют клиенты —
-- привязку, подписи и хеш половины, который входит в safety number.
--
-- Длины: ключ ML-DSA-65 — 1952 байта; гибридная подпись —
-- 64 (XEdDSA) + 3309 (ML-DSA-65) = 3373.

ALTER TABLE accounts
    ADD COLUMN pq_identity_key BYTEA,
    ADD COLUMN identity_binding BYTEA,
    ADD CONSTRAINT pq_identity_key_len
        CHECK (pq_identity_key IS NULL OR octet_length(pq_identity_key) = 1952),
    ADD CONSTRAINT identity_binding_len
        CHECK (identity_binding IS NULL OR octet_length(identity_binding) = 3373);

-- Подпись ключа sealed sender тоже гибридная. Прежние строки
-- (64 байта) не проверяются: их клиенты переопубликуют ключ.
ALTER TABLE devices DROP CONSTRAINT IF EXISTS sealed_kem_signature_len;
ALTER TABLE devices
    ADD CONSTRAINT sealed_kem_signature_len
        CHECK (sealed_kem_signature IS NULL OR octet_length(sealed_kem_signature) = 3373) NOT VALID;
