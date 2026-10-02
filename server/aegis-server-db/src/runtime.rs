// SPDX-License-Identifier: AGPL-3.0-only

//! Окружение процесса: откуда берутся секреты, чем защищена связь с базой,
//! от чьего имени работает процесс.
//!
//! Общее для узла API и админ-центра: оба держат секреты и ходят в базу,
//! и правила у них обязаны быть одни.

use std::path::Path;

/// Секрет по имени переменной: само значение, файл или учётные данные systemd.
///
/// Порядок:
///
/// 1. `NAME_FILE` — путь к файлу со значением;
/// 2. `$CREDENTIALS_DIRECTORY/<name>` — учётные данные systemd
///    (`LoadCredential=`), имя файла — имя переменной строчными;
/// 3. `NAME` — значение прямо в окружении.
///
/// 🔐 Файл лучше переменной. Окружение процесса читается из
/// `/proc/<pid>/environ`, наследуется дочерними процессами и попадает
/// в отчёты о падениях и в `systemctl show`; учётные данные systemd
/// лежат в каталоге, доступном только этому процессу, и в окружение не
/// попадают вовсе.
///
/// Пробелы и перевод строки по краям отбрасываются: файл, сохранённый
/// редактором, кончается переводом строки.
#[must_use]
pub fn secret(name: &str) -> Option<String> {
    let from_file = |path: &Path| {
        std::fs::read_to_string(path)
            .ok()
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
    };

    if let Ok(path) = std::env::var(format!("{name}_FILE")) {
        return from_file(Path::new(&path));
    }

    if let Ok(directory) = std::env::var("CREDENTIALS_DIRECTORY") {
        let path = Path::new(&directory).join(name.to_ascii_lowercase());
        if path.exists() {
            return from_file(&path);
        }
    }

    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Защищена ли связь с базой по этому адресу.
///
/// Связь с базой на этой же машине (петля, unix-сокет) защищать не от
/// кого. С другой машиной — только TLS **с проверкой сертификата базы**:
/// `sslmode=verify-full` (лучше) или `verify-ca`.
///
/// 🔐 `require` здесь не годится: шифрует, но принимает любой
/// сертификат, и тот, кто встал посреди внутренней сети, видит конверты
/// и время их доставки — то есть кто кому пишет. `prefer` и умолчание
/// без TLS отдают то же самое без всякого усилия.
#[must_use]
pub fn database_link_protected(url: &str) -> bool {
    let query = url.split_once('?').map_or("", |(_, query)| query);
    let param = |key: &str| {
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value)
    };

    if matches!(param("sslmode"), Some("verify-full" | "verify-ca")) {
        return true;
    }

    // Unix-сокет, заданный в запросе (`host=/var/run/postgresql`).
    if param("host").is_some_and(|host| host.starts_with('/') || host.starts_with("%2F")) {
        return true;
    }

    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(bracketed) = host_port.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or_default()
    } else {
        host_port.split(':').next().unwrap_or_default()
    };

    host.is_empty() || host == "localhost" || host == "::1" || host.starts_with("127.")
}

/// Работает ли процесс с правами root.
///
/// 🔐 Узлу root не нужен ни для чего: порт выше 1024, файлы — свои. Дыра
/// в процессе под root — это сразу вся машина: ключи TLS, ключ подписи
/// сертификатов, доступ к базе и остальным службам.
#[must_use]
pub fn running_as_root() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Вторая колонка строки `Uid:` — действующий пользователь.
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("Uid:"))
                    .and_then(|line| line.split_whitespace().nth(2).map(str::to_owned))
            })
            .is_some_and(|effective| effective == "0")
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔐 Удалённая база — только с проверкой её сертификата.
    #[test]
    fn a_remote_database_needs_a_verified_tls_link() {
        for protected in [
            "postgres://aegis:x@10.0.0.4/aegis?sslmode=verify-full",
            "postgres://aegis:x@db.internal:5432/aegis?sslrootcert=/etc/aegis/db-ca.pem&sslmode=verify-ca",
            "postgres://aegis:x@localhost:5432/aegis",
            "postgres://aegis:x@127.0.0.1/aegis",
            "postgres://aegis:x@[::1]:5432/aegis",
            "postgres:///aegis?host=/var/run/postgresql",
        ] {
            assert!(database_link_protected(protected), "{protected} отвергнут");
        }

        for exposed in [
            "postgres://aegis:x@10.0.0.4/aegis",
            "postgres://aegis:x@10.0.0.4/aegis?sslmode=require",
            "postgres://aegis:x@10.0.0.4/aegis?sslmode=prefer",
            "postgres://aegis:x@db.internal/aegis?application_name=verify-full",
            "postgres://localhost:x@10.0.0.4/aegis",
        ] {
            assert!(!database_link_protected(exposed), "{exposed} принят");
        }
    }

    /// Секрет из файла важнее значения в окружении и обрезается по краям.
    #[test]
    fn a_secret_file_wins_over_the_environment() {
        let dir = std::env::temp_dir().join(format!("aegis-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("каталог");
        let file = dir.join("value");
        std::fs::write(&file, "from-file\n").expect("файл");

        // Имя только для этого теста: окружение процесса общее.
        let name = "AEGIS_TEST_SECRET_FILE_WINS";
        std::env::set_var(name, "from-env");
        std::env::set_var(format!("{name}_FILE"), &file);

        assert_eq!(secret(name).as_deref(), Some("from-file"));

        std::env::remove_var(format!("{name}_FILE"));
        assert_eq!(secret(name).as_deref(), Some("from-env"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
