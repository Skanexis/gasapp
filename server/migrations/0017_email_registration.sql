-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 0017: для регистрации нужен подтверждённый адрес электронной почты.
--
-- # Зачем
--
-- Решение владельца (2026-10-07): аккаунт создаётся только после
-- подтверждения адреса почты кодом из письма. Один адрес — один
-- аккаунт. Это отменяет прежнее «ни телефона, ни email» (ADR-007).
--
-- # 🔐 Что хранится
--
-- Сам адрес сервер НЕ хранит. В базе лежит `email_hash` —
-- HMAC-SHA-256 от приведённого адреса на ключе узла
-- (`GASAPP_EMAIL_KEY`). Его хватает, чтобы не дать завести второй
-- аккаунт на тот же адрес, и не хватает, чтобы прочитать адрес из
-- дампа базы без ключа.
--
-- ⚠️ Чего это НЕ скрывает — и политика приватности обязана это
-- говорить:
--   * оператор, у которого есть ключ, проверит, зарегистрирован ли
--     ИЗВЕСТНЫЙ ему адрес (посчитает тот же HMAC);
--   * почтовая служба, через которую уходит письмо с кодом, видит
--     адрес и время запроса кода — это вне сервера и вне этой схемы.
--
-- Аккаунтам, созданным до миграции, адрес не приписывается: `NULL`.

ALTER TABLE accounts
    ADD COLUMN email_hash BYTEA
        CHECK (email_hash IS NULL OR octet_length(email_hash) = 32);

CREATE UNIQUE INDEX accounts_by_email_hash ON accounts (email_hash)
    WHERE email_hash IS NOT NULL;

-- Коды подтверждения.
--
-- Дамп даёт: хеши адресов, запросивших код за последние минуты, и
-- хеши кодов. Строка живёт до регистрации или до истечения срока
-- (`retention` удаляет просроченные).
--
-- В базе, а не в памяти узла: узлов несколько, и код, выданный одним,
-- проверяет любой.
CREATE TABLE email_codes (
    email_hash   BYTEA PRIMARY KEY CHECK (octet_length(email_hash) = 32),
    -- SHA-256(домен ‖ email_hash ‖ код): шестизначный код в открытом
    -- виде не лежит, хотя перебирается по хешу — защита здесь не хеш,
    -- а счётчик попыток и срок.
    code_hash    BYTEA NOT NULL CHECK (octet_length(code_hash) = 32),
    expires_at   TIMESTAMPTZ NOT NULL,
    -- Неверные вводы этого кода: после пяти код сгорает.
    attempts     INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    -- Окно ограничения отправки: не больше пяти писем в час на адрес.
    window_start TIMESTAMPTZ NOT NULL DEFAULT now(),
    sends        INTEGER NOT NULL DEFAULT 1 CHECK (sends >= 1),
    last_sent_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX email_codes_by_expiry ON email_codes (expires_at);
