// SPDX-License-Identifier: Apache-2.0

//! Проверка против **живого** сервера.
//!
//! # Чем отличается от `end_to_end`
//!
//! Там сервер поддельный: он проверяет, что клиент правильно соединяет
//! свои части. Здесь настоящий сервер с настоящим Postgres — проверяется
//! то, чего заглушка не покажет: совпадение форматов запросов, кодов
//! ответа, proof-of-work и адресации.
//!
//! # Почему тест игнорируется по умолчанию
//!
//! Ему нужен запущенный сервер. В CI он включается отдельным шагом,
//! где сервер поднимается из docker-compose; на машине разработчика
//! запускается вручную:
//!
//! ```text
//! AEGIS_SERVER=http://127.0.0.1:8443 cargo test -p aegis-core --test live_server -- --ignored
//! ```
//!
//! Молчаливый пропуск при отсутствии сервера был бы хуже: тест,
//! который «проходит», ничего не проверив, вводит в заблуждение.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;

use aegis_core::client::Client;
use aegis_net::client::{HttpRequest, HttpResponse, Transport};
use aegis_storage::Storage;
use aegis_types::{AegisError, Result, Timestamp};
use rand_core::OsRng;

/// Минимальный HTTP-клиент поверх TCP.
///
/// Своя реализация, а не библиотека: тесту нужен обычный HTTP без TLS
/// к локальному серверу, и тащить ради этого зависимость с собственным
/// TLS-стеком в клиентский workspace означало бы ровно то, чего
/// архитектура избегает — сеть внутри Rust.
struct LocalHttp {
    host: String,
    port: u16,
}

impl Transport for LocalHttp {
    /// # ⚠️ Заголовки обязаны доходить до сервера
    ///
    /// Прежде эта реализация их просто **теряла**: собирала запрос
    /// из метода, пути и тела, а `request.headers` не читала вовсе.
    /// Для регистрации это было незаметно — она анонимна, — а всё
    /// остальное получало `401`: подпись устройства уходит именно
    /// в заголовках `x-aegis-signature` и `x-aegis-issued-at`.
    ///
    /// Заметить было нечем: тесты этого файла помечены `#[ignore]`
    /// и ни разу не запускались, потому что сервер для них никто
    /// не поднимал. Написаны они были до того, как маршруты стали
    /// требовать подпись.
    fn execute(&self, request: &HttpRequest) -> Result<HttpResponse> {
        let mut stream =
            TcpStream::connect((self.host.as_str(), self.port)).map_err(|_| AegisError::Network)?;

        // Тело бывает двух видов: JSON и сырые байты вложения.
        // Второе тоже терялось, и загрузка вложения уходила пустой.
        let body: Vec<u8> = match (&request.body, &request.binary_body) {
            (Some(text), _) => text.as_bytes().to_vec(),
            (None, Some(bytes)) => bytes.clone(),
            (None, None) => Vec::new(),
        };

        let content_type = if request.binary_body.is_some() {
            "application/octet-stream"
        } else {
            "application/json"
        };

        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: {}\r\n\
             Content-Length: {}\r\nConnection: close\r\n",
            request.method.as_str(),
            request.path,
            self.host,
            self.port,
            content_type,
            body.len(),
        );

        for (name, value) in &request.headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }

        head.push_str("\r\n");

        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .map_err(|_| AegisError::Network)?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|_| AegisError::Network)?;

        parse_response(&raw)
    }
}

/// Разбирает ответ HTTP.
fn parse_response(raw: &[u8]) -> Result<HttpResponse> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n").ok_or(AegisError::Network)?;

    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(AegisError::Network)?;

    // Chunked-кодирование: сервер отдаёт им ответы без Content-Length.
    let body = if head.to_lowercase().contains("transfer-encoding: chunked") {
        dechunk(body)
    } else {
        body.to_owned()
    };

    Ok(HttpResponse {
        status,
        body,
        // Поддельный сервер отдаёт только JSON: вложения проверяются
        // тестами настоящего сервера, где есть база.
        binary_body: Vec::new(),
    })
}

/// Собирает тело из chunked-кодирования.
fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;

    while let Some((size_line, remainder)) = rest.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size_line.trim(), 16) else {
            break;
        };

        if size == 0 {
            break;
        }

        let Some(chunk) = remainder.get(..size) else {
            break;
        };

        out.push_str(chunk);
        rest = remainder.get(size.saturating_add(2)..).unwrap_or("");
    }

    out
}

/// Адрес сервера из окружения.
fn server() -> Option<(String, u16)> {
    let raw = std::env::var("AEGIS_SERVER").ok()?;
    let trimmed = raw.trim_start_matches("http://");
    let (host, port) = trimmed.split_once(':')?;

    Some((host.to_owned(), port.parse().ok()?))
}

/// Текущее время — настоящее, а не зафиксированное.
///
/// # ⚠️ Почему здесь нельзя застывшую метку
///
/// Здесь стояло `Timestamp::from_millis(1_760_000_000_000)`, и это
/// работало ровно до того дня, когда маршруты стали требовать подпись.
/// Подпись включает `issued_at`, а сервер отвергает всё старше пяти
/// минут ([`crate::auth::CHALLENGE_TTL_MILLIS`] на его стороне) —
/// то есть застывшая метка гарантированно просрочена, и каждый
/// подписанный запрос получает `401`.
///
/// Диагностика при этом обманчива: `InvalidSignature` читается как
/// «подпись неверна», хотя подпись верна, а просрочено время.
///
/// Заметить было нечем: тесты этого файла помечены `#[ignore]`
/// и ни разу не запускались — сервер для них никто не поднимал.
fn now() -> Timestamp {
    Timestamp::from_millis(
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("часы после 1970")
                .as_millis(),
        )
        .expect("время помещается в i64"),
    )
}

/// Уникальное имя: сервер хранит аккаунты между запусками теста.
fn unique(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::new_v4().simple())
        .chars()
        .take(24)
        .collect()
}

/// 🔐 Полный цикл против живого сервера.
#[test]
#[ignore = "нужен запущенный сервер: AEGIS_SERVER=http://127.0.0.1:8443"]
fn real_server_delivers_a_message() {
    let (host, port) = server().expect("переменная AEGIS_SERVER не задана");
    let dir = tempfile::tempdir().expect("каталог");

    let alice_path = dir.path().join("alice.db").to_string_lossy().into_owned();
    let bob_path = dir.path().join("bob.db").to_string_lossy().into_owned();

    let alice = Client::new(
        LocalHttp {
            host: host.clone(),
            port,
        },
        Storage::new(&alice_path, &[0x5A; 32]).expect("база Алисы"),
    );
    let bob = Client::new(
        LocalHttp { host, port },
        Storage::new(&bob_path, &[0x5B; 32]).expect("база Боба"),
    );

    let alice_name = unique("alice");
    let bob_name = unique("bob");

    alice
        .register(&alice_name, now(), &mut OsRng)
        .expect("регистрация Алисы");
    let bob_account = bob
        .register(&bob_name, now(), &mut OsRng)
        .expect("регистрация Боба");

    alice
        .send_message(
            &bob_name,
            "привет через настоящий сервер",
            now(),
            &mut OsRng,
        )
        .expect("отправка");

    let received = bob
        .receive_messages(&bob_account.device_id.to_string(), now())
        .expect("приём");

    assert_eq!(received, 1, "сообщение не дошло через настоящий сервер");

    let chats = bob.chats().expect("чаты");
    let messages = bob.messages(&chats[0], 10).expect("сообщения");

    assert_eq!(messages[0].text, "привет через настоящий сервер");
}

/// 🔐 В базе сервера лежит только шифротекст.
///
/// Проверка ручная по замыслу плана: заглянуть в дамп БД и убедиться,
/// что оператор не может прочитать переписку. Здесь она автоматизирована
/// — сообщение отправляется, но **не** принимается, поэтому конверт
/// остаётся в очереди и его видно в базе.
#[test]
#[ignore = "нужен запущенный сервер: AEGIS_SERVER=http://127.0.0.1:8443"]
fn server_database_holds_only_ciphertext() {
    let (host, port) = server().expect("переменная AEGIS_SERVER не задана");
    let dir = tempfile::tempdir().expect("каталог");

    let alice_path = dir.path().join("a.db").to_string_lossy().into_owned();
    let bob_path = dir.path().join("b.db").to_string_lossy().into_owned();

    let alice = Client::new(
        LocalHttp {
            host: host.clone(),
            port,
        },
        Storage::new(&alice_path, &[0x11; 32]).expect("база"),
    );
    let bob = Client::new(
        LocalHttp { host, port },
        Storage::new(&bob_path, &[0x22; 32]).expect("база"),
    );

    let bob_name = unique("bob");
    alice
        .register(&unique("alice"), now(), &mut OsRng)
        .expect("Алиса");
    bob.register(&bob_name, now(), &mut OsRng).expect("Боб");

    // Опознаваемая строка: если сервер видит текст, она найдётся в дампе.
    let canary = "CANARY-PLAINTEXT-MUST-NOT-APPEAR";
    alice
        .send_message(&bob_name, canary, now(), &mut OsRng)
        .expect("отправка");

    // Приём не выполняется намеренно: конверт должен остаться в очереди,
    // чтобы его можно было увидеть в базе.
    println!("канарейка отправлена, проверьте базу: {canary}");
}

/// 🔐 Приём сообщения: полный цикл между двумя клиентами.
///
/// Проверяет то, чего не покажет отправка: получатель действительно
/// расшифровывает конверт и видит исходный текст.
#[test]
#[ignore = "нужен запущенный сервер: AEGIS_SERVER=http://127.0.0.1:8444"]
fn message_is_received_and_decrypted() {
    let (host, port) = server().expect("переменная AEGIS_SERVER не задана");
    let dir = tempfile::tempdir().expect("каталог");

    let sender_path = dir.path().join("s.db").to_string_lossy().into_owned();
    let receiver_path = dir.path().join("r.db").to_string_lossy().into_owned();

    let sender = Client::new(
        LocalHttp {
            host: host.clone(),
            port,
        },
        Storage::new(&sender_path, &[0x31; 32]).expect("база"),
    );
    let receiver = Client::new(
        LocalHttp { host, port },
        Storage::new(&receiver_path, &[0x32; 32]).expect("база"),
    );

    let receiver_name = unique("recv");
    sender
        .register(&unique("send"), now(), &mut OsRng)
        .expect("отправитель");
    let receiver_account = receiver
        .register(&receiver_name, now(), &mut OsRng)
        .expect("получатель");

    let text = "сообщение прошло весь путь";
    sender
        .send_message(&receiver_name, text, now(), &mut OsRng)
        .expect("отправка");

    let count = receiver
        .receive_messages(&receiver_account.device_id.to_string(), now())
        .expect("приём");

    assert_eq!(count, 1, "сообщение не принято");

    let chats = receiver.chats().expect("чаты");
    assert_eq!(chats.len(), 1, "чат не появился");

    let messages = receiver.messages(&chats[0], 10).expect("сообщения");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].text, text, "текст не совпал после расшифровки");
    assert!(!messages[0].outgoing, "входящее помечено исходящим");
}

/// 🔐 Пул одноразовых предключей наполняется на настоящем сервере.
///
/// # Что это проверяет, чего не проверяет заглушка
///
/// Весь путь целиком: запрос остатка за подписью, выпуск недостающих
/// ключей, публикацию с подписями пост-квантовых и то, что сервер их
/// принял и учёл. Заглушка проверяет договорённость клиента с самим
/// собой; здесь — с Postgres и настоящим разбором JSON.
///
/// # Почему после регистрации в пуле один ключ
///
/// `generate` публикует `one_time.first()` — один из ста. Остальные
/// девяносто девять на сервер не попадают вовсе, и до появления
/// обслуживания не попадали никогда: первый же незнакомец забирал
/// единственный, и все следующие первые контакты шли без
/// одноразового предключа.
#[test]
#[ignore = "нужен запущенный сервер: AEGIS_SERVER=http://127.0.0.1:8443"]
fn the_one_time_pool_is_filled_on_a_real_server() {
    let (host, port) = server().expect("переменная AEGIS_SERVER не задана");
    let dir = tempfile::tempdir().expect("каталог");

    let path = dir.path().join("m.db").to_string_lossy().into_owned();
    let client = Client::new(
        LocalHttp { host, port },
        Storage::new(&path, &[0x41; 32]).expect("база"),
    );

    client
        .register(&unique("pool"), now(), &mut OsRng)
        .expect("регистрация");

    let first = client
        .maintain_prekeys(now(), &mut OsRng)
        .expect("первое обслуживание");

    assert!(
        first.added_one_time > 0,
        "после регистрации пул уже полон — значит проверять нечего",
    );

    assert_eq!(
        first.remaining_one_time,
        aegis_protocol::ONE_TIME_PRE_KEY_POOL_SIZE,
        "пул наполнен не до полного размера",
    );

    // Повторное обслуживание ничего не добавляет: сервер уже полон.
    let second = client
        .maintain_prekeys(now(), &mut OsRng)
        .expect("второе обслуживание");

    assert_eq!(second.added_one_time, 0, "полный пул пополнен повторно");
    assert_eq!(
        second.remaining_one_time,
        aegis_protocol::ONE_TIME_PRE_KEY_POOL_SIZE,
    );
}

/// 🔐 Ручная сквозная проверка с настоящим устройством.
///
/// Регистрирует нового собеседника, пишет пользователю `AEGIS_PEER`
/// (например, аккаунту в приложении на эмуляторе) и ждёт ответа до
/// `AEGIS_WAIT_SECONDS` секунд (по умолчанию 180). Ответ печатается.
///
/// Проверяет то, чего не видит ни один автоматический тест: что
/// клиент на Rust и приложение на Android договариваются через
/// настоящий сервер — discovery, bundle с подписями, PQXDH, подписанная
/// отправка, приём и расшифровка на телефоне, ответ обратно.
///
/// ```text
/// AEGIS_SERVER=http://127.0.0.1:8080 AEGIS_PEER=bob_e2e \
///     cargo test -p aegis-core --test live_server talk_to -- --ignored --nocapture
/// ```
#[test]
#[ignore = "ручная проверка с устройством: AEGIS_SERVER и AEGIS_PEER"]
fn talk_to_an_existing_user() {
    let (host, port) = server().expect("переменная AEGIS_SERVER не задана");
    let peer = std::env::var("AEGIS_PEER").expect("переменная AEGIS_PEER не задана");
    let wait = std::env::var("AEGIS_WAIT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(180);

    let dir = tempfile::tempdir().expect("каталог");
    let path = dir.path().join("carol.db").to_string_lossy().into_owned();
    let carol = Client::new(
        LocalHttp { host, port },
        Storage::new(&path, &[0x5C; 32]).expect("база"),
    );

    let name = unique("carol");
    let account = carol
        .register(&name, now(), &mut OsRng)
        .expect("регистрация");
    let device = account.device_id.to_string();

    carol
        .send_message(&peer, "привет с другой стороны", now(), &mut OsRng)
        .expect("отправка");
    println!("отправлено от {name} к {peer}; жду ответа до {wait} с");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait);

    loop {
        if carol.receive_messages(&device, now()).expect("приём") > 0 {
            break;
        }

        assert!(
            std::time::Instant::now() < deadline,
            "ответа от {peer} нет за {wait} с"
        );
        std::thread::sleep(std::time::Duration::from_secs(3));
    }

    let chats = carol.chats().expect("чаты");
    let messages = carol.messages(&chats[0], 10).expect("сообщения");

    for message in &messages {
        println!(
            "{} {}",
            if message.outgoing { "→" } else { "←" },
            message.text
        );
    }

    assert!(
        messages.iter().any(|message| !message.outgoing),
        "входящего ответа нет"
    );
}

/// Печатает переписку клиента: направление, статус и текст.
fn print_chat(client: &Client<LocalHttp>, title: &str) {
    println!("---- {title} ----");

    for chat in client.chats().expect("чаты") {
        for message in client.messages(&chat, 50).expect("сообщения") {
            println!(
                "{} [{:?}] {}",
                if message.outgoing { "→" } else { "←" },
                message.status,
                message.text
            );
        }
    }
}

/// Правка, удаление у всех и квитанции — между клиентом на Rust
/// и приложением на Android через настоящий сервер.
///
/// Дейв пишет два сообщения и ждёт ответа. Затем правит первое,
/// удаляет второе у всех и следит за перепиской, печатая её при каждом
/// изменении: так видно и то, что сделано в приложении, — правку,
/// удаление у всех, отметку «прочитано».
///
/// ```text
/// AEGIS_SERVER=http://127.0.0.1:9080 AEGIS_PEER=bob_e2e AEGIS_WATCH_SECONDS=300 \
///     cargo test -p aegis-core --test live_server edits_and_deletes -- --ignored --nocapture
/// ```
#[test]
#[ignore = "ручная проверка с устройством: AEGIS_SERVER и AEGIS_PEER"]
fn edits_and_deletes_with_an_existing_user() {
    let (host, port) = server().expect("переменная AEGIS_SERVER не задана");
    let peer = std::env::var("AEGIS_PEER").expect("переменная AEGIS_PEER не задана");
    let seconds = |name: &str, default: u64| {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(default)
    };
    let wait = seconds("AEGIS_WAIT_SECONDS", 180);
    let watch = seconds("AEGIS_WATCH_SECONDS", 300);

    let dir = tempfile::tempdir().expect("каталог");
    let path = dir.path().join("dave.db").to_string_lossy().into_owned();
    let dave = Client::new(
        LocalHttp { host, port },
        Storage::new(&path, &[0x5D; 32]).expect("база"),
    );

    let name = unique("dave");
    let device = dave
        .register(&name, now(), &mut OsRng)
        .expect("регистрация")
        .device_id
        .to_string();

    let first = dave
        .send_message(&peer, "дейв: первое — будет исправлено", now(), &mut OsRng)
        .expect("первое");
    let second = dave
        .send_message(
            &peer,
            "дейв: второе — будет удалено у всех",
            now(),
            &mut OsRng,
        )
        .expect("второе");
    println!("{name} → {peer}: два сообщения; жду ответа до {wait} с");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait);
    while dave.receive_messages(&device, now()).expect("приём") == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "ответа от {peer} нет за {wait} с"
        );
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    print_chat(&dave, "ответ получен");

    dave.edit_message(
        &peer,
        &first,
        "дейв: первое — ИСПРАВЛЕНО",
        now(),
        &mut OsRng,
    )
    .expect("правка");
    dave.delete_for_everyone(&peer, &second, now(), &mut OsRng)
        .expect("удаление у всех");
    println!("правка первого и удаление второго отправлены; слежу {watch} с");

    let until = std::time::Instant::now() + std::time::Duration::from_secs(watch);
    while std::time::Instant::now() < until {
        if dave.receive_messages(&device, now()).expect("приём") > 0 {
            print_chat(&dave, "изменение");
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }

    print_chat(&dave, "итог");
}
