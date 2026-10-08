// SPDX-License-Identifier: AGPL-3.0-only

//! 🔐 Небезопасная настройка не запускается молча.
//!
//! # Что здесь решается
//!
//! У сервера две настройки, отсутствие которых снимает защиту
//! целиком, а не частично:
//!
//! * **TLS.** Без него переписка идёт открытым текстом. Клиент такой
//!   сервер не примет (`network_security_config.xml` запрещает
//!   открытый трафик), но администратор об этом узнает не сразу
//!   и, скорее всего, «починит» не ту сторону.
//! * **`GASAPP_CERTIFICATE_KEY`.** Им подписываются сертификаты
//!   отправителя для sealed sender. Без него берётся ключ из нулей —
//!   то есть **публично известный**. Сертификат при этом подделывает
//!   кто угодно, и получатель показывает чужое сообщение как
//!   пришедшее от вас.
//!
//! # Почему раньше это были предупреждения
//!
//! Чтобы сервер поднимался без настройки: разворачивающий инстанс
//! для друзей не должен упираться в конфигурацию на первом шаге.
//! Довод разумный, и он сохранён — но перевёрнут.
//!
//! ⚠️ Предупреждение в журнале не защищает. Его читают один раз,
//! при первом запуске, и не читают никогда потом. Сервер, поднятый
//! по руководству `deploy/РАЗВЁРТЫВАНИЕ.md`, до сих пор получал
//! ключ из нулей: в примере файла окружения этой переменной просто
//! **не было**. То есть каждый развёрнутый по документации инстанс
//! подделывался кем угодно, и никто бы не заметил.
//!
//! Тот же код и называет такой отказ худшим:
//!
//! > молчаливый откат к незашифрованному каналу — худший вид отказа
//! > защиты
//!
//! Здесь это доведено до конца: откат перестал быть молчаливым.
//!
//! # Как теперь
//!
//! Обе настройки обязательны. Чтобы поднять сервер без них —
//! для локальной проверки, интеграционных тестов, CI — нужно
//! **сказать это вслух**:
//!
//! ```text
//! GASAPP_ALLOW_INSECURE=1
//! ```
//!
//! Разница между «забыл настроить» и «знаю, что делаю» в том,
//! что второе нельзя сделать случайно.

/// Переменная, которой небезопасный запуск разрешается явно.
pub const ALLOW_INSECURE: &str = "GASAPP_ALLOW_INSECURE";

/// Чего не хватает для безопасного запуска.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// Не заданы `GASAPP_TLS_CERT` и `GASAPP_TLS_KEY`.
    Tls,
    /// Не задан или неверен `GASAPP_CERTIFICATE_KEY`.
    CertificateKey,
    /// Связь с базой на другой машине без TLS с проверкой сертификата.
    DatabaseLink,
    /// Процесс работает от root.
    Root,
    /// Не задана программа отправки писем `GASAPP_EMAIL_CMD`.
    EmailSender,
    /// Не задан или неверен `GASAPP_EMAIL_KEY`.
    EmailKey,
}

impl Missing {
    /// Человеческое объяснение с командой, которая это чинит.
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::Tls => concat!(
                "GASAPP_TLS_CERT и GASAPP_TLS_KEY не заданы — ",
                "переписка пойдёт открытым текстом.
",
                "
    Выдайте сертификат (например, certbot) и укажите пути:
",
                "
      GASAPP_TLS_CERT=/etc/gasapp/tls/cert.pem",
                "
      GASAPP_TLS_KEY=/etc/gasapp/tls/key.pem",
            ),
            Self::CertificateKey => concat!(
                "GASAPP_CERTIFICATE_KEY не задан — сертификаты отправителя ",
                "будут подписаны ключом из нулей.
",
                "    Такой ключ известен всем, и любой может ",
                "выдать своё сообщение за чужое.
",
                "
    Сгенерируйте ключ один раз и храните как секрет:
",
                "
      GASAPP_CERTIFICATE_KEY=$(openssl rand -hex 32)",
            ),
            Self::DatabaseLink => concat!(
                "DATABASE_URL ведёт на другую машину без проверенного TLS — ",
                "конверты и время их доставки
",
                "    (то есть кто кому пишет) увидит любой во внутренней сети.
",
                "
    Включите TLS в Postgres и проверку его сертификата:
",
                "
      DATABASE_URL=postgres://gasapp:…@10.0.0.4/gasapp",
                "?sslmode=verify-full&sslrootcert=/etc/gasapp/pki/ca.pem&sslcert=/etc/gasapp/pki/client-gasapp.pem&sslkey=/run/credentials/gasapp-server.service/db_client_key",
            ),
            Self::Root => concat!(
                "сервер запущен от root — дыра в нём стала бы всей машиной: ",
                "ключи TLS, ключ подписи
",
                "    сертификатов, доступ к базе.
",
                "
    Запускайте от отдельного пользователя (служба systemd ",
                "из server/deploy/systemd).",
            ),
            Self::EmailSender => concat!(
                "GASAPP_EMAIL_CMD не задан — письмо с кодом подтверждения ",
                "отправить нечем,\n",
                "    и код уйдёт в журнал сервера: почту никто не подтвердит.\n",
                "\n    Укажите программу, которая отправляет письмо ",
                "(пример — server/deploy/mail):\n",
                "\n      GASAPP_EMAIL_CMD=/opt/gasapp/mail/send-code.sh",
            ),
            Self::EmailKey => concat!(
                "GASAPP_EMAIL_KEY не задан — адреса почты хешировались бы ",
                "ключом из нулей.\n",
                "    Такой ключ известен всем: по дампу базы адреса ",
                "проверялись бы перебором.\n",
                "\n    Сгенерируйте ключ один раз, храните как секрет, ",
                "один на все узлы:\n",
                "\n      GASAPP_EMAIL_KEY=$(openssl rand -hex 32)",
            ),
        }
    }
}

/// Проверяет настройку и возвращает то, чего не хватает.
///
/// Чтение окружения вынесено в параметры, чтобы функция проверялась
/// тестами: `std::env` глобален, и тесты, меняющие его, мешают друг
/// другу при параллельном запуске.
#[must_use]
pub fn missing(has_tls: bool, has_certificate_key: bool) -> Vec<Missing> {
    let mut gaps = Vec::new();

    if !has_tls {
        gaps.push(Missing::Tls);
    }

    if !has_certificate_key {
        gaps.push(Missing::CertificateKey);
    }

    gaps
}

/// Чего не хватает подтверждению почты при регистрации
/// (см. `crate::email`).
#[must_use]
pub fn email_gaps(has_sender: bool, has_key: bool) -> Vec<Missing> {
    let mut gaps = Vec::new();

    if !has_sender {
        gaps.push(Missing::EmailSender);
    }
    if !has_key {
        gaps.push(Missing::EmailKey);
    }

    gaps
}

/// Собирает сообщение об отказе запуска.
///
/// Отдельно от печати, чтобы тест проверял текст, а не вывод.
/// Чего не хватает окружению процесса: защищённой связи с базой и
/// непривилегированного пользователя (см. `gasapp_server_db::runtime`).
#[must_use]
pub fn environment_gaps(database_url: &str, as_root: bool) -> Vec<Missing> {
    let mut gaps = Vec::new();

    if !gasapp_server_db::runtime::database_link_protected(database_url) {
        gaps.push(Missing::DatabaseLink);
    }
    if as_root {
        gaps.push(Missing::Root);
    }

    gaps
}

#[must_use]
pub fn refusal(gaps: &[Missing]) -> String {
    let mut text = String::from(
        "сервер не запущен: небезопасная настройка\n\
         \n\
         🔐 Ниже — то, без чего защита не работает. Это не советы.\n\n",
    );

    for gap in gaps {
        text.push_str("  • ");
        text.push_str(gap.explain());
        text.push_str("\n\n");
    }

    text.push_str(
        "Если это локальная проверка или интеграционные тесты и вы\n\
         понимаете, что защиты не будет, — скажите это явно:\n\
         \n    ",
    );
    text.push_str(ALLOW_INSECURE);
    text.push_str("=1\n");

    text
}

#[cfg(test)]
mod tests {

    /// 🔐 Удалённая база без проверенного TLS и запуск от root — отказ.
    #[test]
    fn an_exposed_database_link_and_root_are_refused() {
        assert_eq!(
            environment_gaps("postgres://gasapp:x@10.0.0.4/gasapp?sslmode=require", true),
            vec![Missing::DatabaseLink, Missing::Root]
        );
        assert!(environment_gaps(
            "postgres://gasapp:x@10.0.0.4/gasapp?sslmode=verify-full&sslrootcert=/etc/gasapp/pki/ca.pem&sslcert=/etc/gasapp/pki/client-gasapp.pem&sslkey=/run/credentials/gasapp-server.service/db_client_key",
            false
        )
        .is_empty());

        let text = refusal(&[Missing::DatabaseLink, Missing::Root]);
        assert!(text.contains("verify-full"));
        assert!(text.contains("root"));
    }

    use super::*;

    /// Полная настройка не вызывает возражений.
    #[test]
    fn a_complete_configuration_has_no_gaps() {
        assert!(missing(true, true).is_empty());
    }

    /// 🔐 Отсутствие TLS замечено.
    #[test]
    fn missing_tls_is_reported() {
        assert_eq!(missing(false, true), vec![Missing::Tls]);
    }

    /// 🔐 Отсутствие ключа сертификатов замечено.
    #[test]
    fn missing_certificate_key_is_reported() {
        assert_eq!(missing(true, false), vec![Missing::CertificateKey]);
    }

    /// Обе пропажи называются разом, а не по одной за запуск.
    ///
    /// Администратор, чинящий по одной, перезапускает сервер дважды
    /// и дважды ждёт; хуже того — вторую он может счесть новой
    /// поломкой, а не частью той же.
    #[test]
    fn both_gaps_are_reported_together() {
        assert_eq!(
            missing(false, false),
            vec![Missing::Tls, Missing::CertificateKey]
        );
    }

    /// 🔐 Сообщение объясняет последствие, а не только факт.
    ///
    /// «`GASAPP_CERTIFICATE_KEY` не задан» ничего не говорит тому, кто
    /// не читал `certificate.rs`. Сообщение обязано назвать цену:
    /// сертификат подделывает кто угодно.
    #[test]
    fn the_refusal_explains_the_consequence() {
        let text = refusal(&missing(false, false));

        assert!(
            text.contains("открытым текстом"),
            "не сказано про TLS: {text}"
        );
        assert!(
            text.contains("выдать своё сообщение за чужое"),
            "не сказано, чем грозит ключ из нулей: {text}"
        );
    }

    /// Сообщение содержит команды, которыми это чинится.
    ///
    /// Отказ без способа исправления превращается в повод обойти
    /// проверку, а обходят её ровно одним способом — тем, который
    /// назван в конце сообщения.
    #[test]
    fn the_refusal_tells_how_to_fix_it() {
        let text = refusal(&missing(false, false));

        assert!(
            text.contains("openssl rand -hex 32"),
            "нет команды генерации"
        );
        assert!(
            text.contains("GASAPP_TLS_CERT="),
            "нет примера пути к сертификату"
        );
    }

    /// Способ запуститься без защиты назван — и назван явно.
    #[test]
    fn the_refusal_names_the_escape_hatch() {
        let text = refusal(&missing(false, false));

        assert!(text.contains(ALLOW_INSECURE), "не назван {ALLOW_INSECURE}");
    }
}
