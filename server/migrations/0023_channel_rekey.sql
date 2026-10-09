-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 0023: смена ключа закрытого канала — чтобы удалённый подписчик
-- перестал читать не только по слову сервера.
--
-- # Как это устроено
--
-- Удаляя подписчика, приложение того, кто ведёт канал, заводит новый
-- ключ чтения (новую «эпоху») и раздаёт его всем оставшимся: каждому —
-- шифротекстом под его ключ доставки. Новые записи шифруются новым
-- ключом; удалённому его никто не выдаёт.
--
-- * `channels.key_epoch` — номер действующей эпохи. Запись, сделанную
--   под другой эпохой, сервер не принимает.
-- * `channel_epochs` — звенья цепочки: прежний ключ, зашифрованный
--   новым, за подписью того, кто ключ сменил. По ним участник с новым
--   ключом читает и старые записи; обратно пройти нельзя.
-- * `channel_member_keys` — ключи доставки участников: открытый ключ
--   за подписью аккаунта. Под него шифруют ключ эпохи.
--
-- # 🔐 Что сервер узнаёт и чего не знает
--
-- * Сколько раз и когда у канала меняли ключ.
-- * Ключей эпох он не получает: и звенья, и ответы участникам — для
--   него непрозрачные байты.
--
-- # ⚠️ Чего это НЕ даёт
--
-- * Записи, вышедшие **до** удаления, удалённый читал и читать может:
--   их ключ у него был.
-- * Название, описание и аватар канала остаются под первым ключом.
-- * Сервер, подменивший ключ доставки участника своим, получил бы новый
--   ключ эпохи. От удалённого подписчика это не спасает его самого —
--   только в сговоре с сервером.
-- * Канал, у которого меняли ключ, снова открытым не сделать: ссылка
--   открытого канала несёт один ключ, а у такого их несколько.

ALTER TABLE channels
    ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 0 CHECK (key_epoch >= 0),
    ADD CONSTRAINT channel_rekeyed_stays_closed CHECK (key_epoch = 0 OR closed);

ALTER TABLE channel_grants
    ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0;

CREATE TABLE channel_epochs (
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    epoch      INTEGER NOT NULL CHECK (epoch > 0),
    record     BYTEA NOT NULL CHECK (octet_length(record) BETWEEN 1 AND 512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', now()),
    PRIMARY KEY (channel_id, epoch)
);

CREATE TABLE channel_member_keys (
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    member_key BYTEA NOT NULL CHECK (octet_length(member_key) BETWEEN 1 AND 512),
    PRIMARY KEY (channel_id, account_id)
);
