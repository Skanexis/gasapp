// SPDX-License-Identifier: Apache-2.0

//! `gasapp-bot` — движок бота GasApp.
//!
//! ```text
//! gasapp-bot init --server https://gasapp.example --data ./mybot --token gasapp-bot:news_bot:…
//! gasapp-bot run  --data ./mybot
//! ```
//!
//! `init` регистрирует бота по токену из приложения владельца и кладёт
//! его ключи в каталог `--data`. `run` читает команды со стандартного
//! ввода и пишет ответы и события в стандартный вывод — по строке JSON
//! (см. `docs/bots.md`).

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gasapp_bot::{HttpTransport, Runtime};
use gasapp_core::client::Client;
use gasapp_storage::Storage;
use gasapp_types::Timestamp;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// Файл базы бота в каталоге данных.
const DATABASE_FILE: &str = "bot.db";

/// Файл с ключом базы.
const KEY_FILE: &str = "bot.key";

/// Файл с адресом сервера.
const SERVER_FILE: &str = "server";

/// Как часто движок обходит сервер, если не сказано иначе, секунды.
const DEFAULT_POLL_SECS: u64 = 5;

/// Чаще этого обходить сервер нельзя: он ограничивает частоту запросов.
const MIN_POLL_SECS: u64 = 2;

const USAGE: &str = "\
gasapp-bot — движок бота GasApp

  gasapp-bot init --server <https://адрес> --data <каталог> --token <gasapp-bot:имя:токен>
  gasapp-bot run  --data <каталог> [--poll <секунды>]

  --allow-http   разрешить открытый HTTP к чужой машине (только для стенда)

Токен берут в приложении: Каналы → Создать → Мои боты → Создать бота.
Команды и события — в docs/bots.md.";

/// Разобранная командная строка.
struct Options {
    command: String,
    server: Option<String>,
    data: Option<PathBuf>,
    token: Option<String>,
    poll: u64,
    allow_http: bool,
}

fn parse_options() -> Option<Options> {
    let mut arguments = std::env::args().skip(1);
    let mut options = Options {
        command: arguments.next()?,
        server: None,
        data: None,
        token: None,
        poll: DEFAULT_POLL_SECS,
        allow_http: false,
    };

    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--server" => options.server = Some(arguments.next()?),
            "--data" => options.data = Some(PathBuf::from(arguments.next()?)),
            "--token" => options.token = Some(arguments.next()?),
            "--poll" => options.poll = arguments.next()?.parse().ok()?,
            "--allow-http" => options.allow_http = true,
            _ => return None,
        }
    }

    Some(options)
}

fn now() -> Timestamp {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());

    Timestamp::from_millis(i64::try_from(millis).unwrap_or(i64::MAX))
}

/// Ключ базы из файла; `create` — завести, если файла нет.
///
/// ⚠️ Ключ лежит рядом с базой: её защищают права на каталог, а не
/// этот файл (см. описание крейта).
fn storage_key(data: &Path, create: bool) -> Result<Zeroizing<[u8; 32]>, String> {
    let path = data.join(KEY_FILE);
    let mut key = Zeroizing::new([0u8; 32]);

    if let Ok(saved) = std::fs::read_to_string(&path) {
        let saved = Zeroizing::new(saved);

        hex::decode_to_slice(saved.trim(), key.as_mut_slice())
            .map_err(|_| format!("{}: это не ключ базы", path.display()))?;

        return Ok(key);
    }

    if !create {
        return Err(format!("{}: ключа базы нет — сначала init", path.display()));
    }

    OsRng.fill_bytes(key.as_mut_slice());
    let encoded = Zeroizing::new(hex::encode(key.as_slice()));

    write_private(&path, encoded.as_bytes())
        .map_err(|error| format!("{}: {error}", path.display()))?;

    Ok(key)
}

/// Пишет файл, который читает только владелец (на Unix — `0600`).
fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.mode(0o600);
    }

    options.open(path)?.write_all(contents)
}

fn open_client(
    data: &Path,
    server: &str,
    allow_http: bool,
    create: bool,
) -> Result<Client<HttpTransport>, String> {
    let transport = HttpTransport::new(server, allow_http)
        .map_err(|_| format!("{server}: это не адрес сервера (нужен https://…)"))?;
    let key = storage_key(data, create)?;
    let database = data.join(DATABASE_FILE);
    let storage = Storage::new(
        database
            .to_str()
            .ok_or("путь к каталогу данных не читается")?,
        &key,
    )
    .map_err(|_| format!("{}: база не открывается", database.display()))?;

    Ok(Client::new(transport, storage))
}

fn init(options: &Options) -> Result<(), String> {
    let data = options.data.as_deref().ok_or("нужен --data")?;
    let server = options.server.as_deref().ok_or("нужен --server")?;
    let token = options.token.as_deref().ok_or("нужен --token")?;

    std::fs::create_dir_all(data).map_err(|error| format!("{}: {error}", data.display()))?;

    if data.join(DATABASE_FILE).exists() {
        return Err(format!(
            "{}: здесь уже есть бот. Новому боту — новый каталог",
            data.display()
        ));
    }

    let client = open_client(data, server, options.allow_http, true)?;
    let account = client
        .register_bot(token, now(), &mut OsRng)
        .map_err(|error| {
            // Недорегистрированный бот не должен мешать повторить.
            let _ = std::fs::remove_file(data.join(DATABASE_FILE));
            let _ = std::fs::remove_file(data.join(KEY_FILE));

            format!(
                "бот не зарегистрирован ({error}). Токен действует час и годится один раз: \
                 возьмите новый в приложении"
            )
        })?;

    std::fs::write(data.join(SERVER_FILE), server.trim())
        .map_err(|error| format!("{}: {error}", data.display()))?;

    eprintln!("бот @{} зарегистрирован", account.username);

    Ok(())
}

fn run(options: &Options) -> Result<(), String> {
    let data = options.data.as_deref().ok_or("нужен --data")?;
    let server = match &options.server {
        Some(server) => server.clone(),
        None => std::fs::read_to_string(data.join(SERVER_FILE))
            .map_err(|_| format!("{}: бота здесь нет — сначала init", data.display()))?,
    };

    let client = open_client(data, &server, options.allow_http, false)?;
    let mut runtime =
        Runtime::new(client).map_err(|_| "бот не зарегистрирован — сначала init".to_owned())?;
    let poll = Duration::from_secs(options.poll.max(MIN_POLL_SECS));

    // Ввод читается отдельным потоком: движок обязан обходить сервер и
    // тогда, когда программа бота молчит.
    let (lines, commands) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };

            if lines.send(line).is_err() {
                break;
            }
        }
    });

    let stdout = std::io::stdout();
    let emit = |line: &str| -> bool {
        let mut out = stdout.lock();

        writeln!(out, "{line}").and_then(|()| out.flush()).is_ok()
    };

    let mut next_poll = std::time::Instant::now();

    loop {
        let wait = next_poll.saturating_duration_since(std::time::Instant::now());

        match commands.recv_timeout(wait) {
            Ok(line) => {
                if !line.trim().is_empty() && !emit(&runtime.handle(&line, now())) {
                    return Ok(());
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                for event in runtime.poll(now()) {
                    if !emit(&event) {
                        return Ok(());
                    }
                }

                next_poll = std::time::Instant::now()
                    .checked_add(poll)
                    .unwrap_or_else(std::time::Instant::now);
            }
            // Программа бота закрыла ввод — работа окончена.
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

fn main() -> ExitCode {
    let Some(options) = parse_options() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };

    let outcome = match options.command.as_str() {
        "init" => init(&options),
        "run" => run(&options),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("gasapp-bot: {message}");
            ExitCode::FAILURE
        }
    }
}
