-- 0008: ключ ML-KEM-1024 sealed sender у каждого устройства.
--
-- # Зачем
--
-- Внешний слой sealed sender был только X25519. Содержимое сообщений
-- защищал пост-квантовый храповик, а имя отправителя — одна
-- классическая кривая: записав конверты сегодня, с квантовым
-- компьютером завтра можно было бы восстановить, кто кому писал.
-- Теперь внешний слой гибридный, и отправителю нужен ключ ML-KEM
-- получателя.
--
-- # Что знает сервер
--
-- Открытый ключ и его подпись identity-ключом владельца. Подпись
-- сервер не проверяет — её проверяет отправитель, — и подменить ключ
-- сервер поэтому не может. Закрытого ключа здесь нет и быть не может.

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS sealed_kem_public BYTEA,
    ADD COLUMN IF NOT EXISTS sealed_kem_signature BYTEA;

ALTER TABLE devices
    ADD CONSTRAINT sealed_kem_public_len
        CHECK (sealed_kem_public IS NULL OR octet_length(sealed_kem_public) = 1568),
    ADD CONSTRAINT sealed_kem_signature_len
        CHECK (sealed_kem_signature IS NULL OR octet_length(sealed_kem_signature) = 64);
