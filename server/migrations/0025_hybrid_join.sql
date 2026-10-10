-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 0025: заявка в закрытый канал и ответ на неё стали гибридными.
--
-- Ключ чтения канала передаётся участнику шифротекстом. Прежде обмен
-- шёл только на X25519: тот, кто сохранил ответы с сервера, вскрыл бы
-- их, сломав одну кривую. Теперь к X25519 добавлен ML-KEM-1024, и
-- заявка (открытый ключ ML-KEM, 1568 байт), и ответ (его шифротекст,
-- ещё 1568) стали длиннее прежнего предела в 512 байт.
--
-- Сервер по-прежнему не разбирает ни заявку, ни ответ: меняется только
-- допустимая длина непрозрачных байтов.

ALTER TABLE channel_join_requests
    DROP CONSTRAINT channel_join_requests_request_check,
    ADD CONSTRAINT channel_join_requests_request_check
        CHECK (octet_length(request) BETWEEN 1 AND 4096);

ALTER TABLE channel_grants
    DROP CONSTRAINT channel_grants_grant_blob_check,
    ADD CONSTRAINT channel_grants_grant_blob_check
        CHECK (octet_length(grant_blob) BETWEEN 1 AND 4096);

ALTER TABLE channel_member_keys
    DROP CONSTRAINT channel_member_keys_member_key_check,
    ADD CONSTRAINT channel_member_keys_member_key_check
        CHECK (octet_length(member_key) BETWEEN 1 AND 4096);
