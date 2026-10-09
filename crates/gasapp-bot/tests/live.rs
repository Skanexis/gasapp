// SPDX-License-Identifier: Apache-2.0

//! Движок бота против настоящего сервера — целиком, по сети.
//!
//! Тест помечен `#[ignore]`: ему нужен поднятый сервер и оператор,
//! который выдаст владельцу премиум.
//!
//! ```text
//! # сервер: GASAPP_ALLOW_INSECURE=1 GASAPP_DEV_EMAIL_CODE=000000 GASAPP_BIND=127.0.0.1:8443
//! GASAPP_SERVER=http://127.0.0.1:8443 cargo test -p gasapp-bot --test live -- --ignored --nocapture
//! # тест печатает имя владельца и ждёт премиума:
//! #   UPDATE accounts SET premium = true WHERE username = '<имя>';
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_pass_by_value
)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gasapp_bot::{HttpTransport, Runtime};
use gasapp_core::client::Client;
use gasapp_storage::Storage;
use gasapp_types::Timestamp;
use rand_core::OsRng;
use serde_json::{json, Value};

fn now() -> Timestamp {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("часы")
        .as_millis();

    Timestamp::from_millis(i64::try_from(millis).expect("время"))
}

fn client(dir: &tempfile::TempDir, name: &str) -> Client<HttpTransport> {
    let server = std::env::var("GASAPP_SERVER").expect("переменная GASAPP_SERVER не задана");
    let path = dir.path().join(name);

    Client::new(
        HttpTransport::new(&server, false).expect("адрес сервера"),
        Storage::new(path.to_str().expect("путь"), &[0x5B; 32]).expect("база"),
    )
}

fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("часы")
        .as_nanos();

    format!("{prefix}{:x}", nanos % 0xffff_ffff_ffff)
}

fn register(client: &Client<HttpTransport>, username: &str) {
    let email = format!("{username}@test.example");
    let code = std::env::var("GASAPP_DEV_EMAIL_CODE").unwrap_or_else(|_| "000000".to_owned());

    client.request_email_code(&email).expect("код запрошен");
    client
        .register(username, &email, &code, now(), &mut OsRng)
        .expect("регистрация");
}

/// Команда движку; ответ обязан быть успешным.
fn call(runtime: &mut Runtime<HttpTransport>, method: &str, params: Value) -> Value {
    let line = json!({ "id": 7, "method": method, "params": params }).to_string();
    let answer: Value = serde_json::from_str(&runtime.handle(&line, now())).expect("ответ — JSON");

    assert_eq!(answer["id"], 7);
    assert_eq!(answer["ok"], true, "{method}: {answer}");

    answer["result"].clone()
}

/// События одного обхода сервера.
fn poll(runtime: &mut Runtime<HttpTransport>) -> Vec<Value> {
    runtime
        .poll(now())
        .iter()
        .map(|line| serde_json::from_str(line).expect("событие — JSON"))
        .collect()
}

fn event<'a>(events: &'a [Value], kind: &str) -> &'a Value {
    events
        .iter()
        .find(|event| event["event"] == kind)
        .unwrap_or_else(|| panic!("нет события {kind}: {events:?}"))
}

#[test]
#[ignore = "нужен запущенный сервер: GASAPP_SERVER=http://127.0.0.1:8443, и премиум владельцу"]
#[allow(clippy::too_many_lines)]
fn a_bot_runs_a_closed_channel_over_the_network() {
    let dir = tempfile::tempdir().expect("каталог");
    let owner = client(&dir, "owner.db");
    let reader = client(&dir, "reader.db");
    let owner_name = unique("own");
    let reader_name = unique("rdr");
    let bot_name = format!("{}_bot", unique("b"));

    register(&owner, &owner_name);
    register(&reader, &reader_name);

    // Премиум выдаёт оператор — руками, как в жизни.
    println!("PREMIUM_FOR={owner_name}");
    let mut premium = false;
    for _ in 0..120 {
        if owner.refresh_premium(now()).unwrap_or(false) {
            premium = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    assert!(premium, "владельцу не выдали премиум");

    // Закрытый канал и ссылка-приглашение.
    let channel = owner
        .create_channel("Свои", "", now(), &mut OsRng)
        .expect("канал");
    let channel_id = channel.channel_id.as_str();
    owner
        .publish_channel_post(channel_id, "первая", &[], now(), &mut OsRng)
        .expect("запись");
    owner
        .set_channel_closed(channel_id, true, now())
        .expect("закрыть");
    let invite = owner
        .create_channel_invite(channel_id, now(), &mut OsRng)
        .expect("ссылка");

    // Бот: токен у владельца, регистрация — программой бота.
    let token = owner.create_bot(&bot_name, now()).expect("токен");
    let bot = client(&dir, "bot.db");
    bot.register_bot(&token, now(), &mut OsRng).expect("бот");
    assert_eq!(
        owner.bots(now()).expect("боты"),
        std::slice::from_ref(&bot_name)
    );

    let mut runtime = Runtime::new(bot).expect("движок");
    let me = call(&mut runtime, "getMe", json!({}));
    assert_eq!(me["username"], bot_name);

    // Бот входит в канал по заявке; владелец одобряет.
    call(&mut runtime, "requestJoin", json!({ "link": invite }));
    let requests = owner
        .channel_join_requests(channel_id, now())
        .expect("заявки");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].username, bot_name);
    owner
        .answer_channel_join(channel_id, &requests[0].account_id, true, now(), &mut OsRng)
        .expect("одобрение");

    let events = poll(&mut runtime);
    assert_eq!(
        event(&events, "joined")["channel"]["channel_id"],
        channel_id
    );

    // Владелец назначает бота администратором.
    let request = call(
        &mut runtime,
        "adminRequest",
        json!({ "channel_id": channel_id }),
    );
    owner
        .add_channel_admin(
            channel_id,
            request["request"].as_str().expect("заявка"),
            "Бот",
            now(),
            &mut OsRng,
        )
        .expect("назначение");
    call(
        &mut runtime,
        "syncChannel",
        json!({ "channel_id": channel_id }),
    );
    let channels = call(&mut runtime, "channels", json!({}));
    assert_eq!(channels[0]["role"], "admin");
    assert_eq!(channels[0]["closed"], true);

    // Заявку читателя видит и одобряет бот.
    reader
        .request_channel_join(&invite, now(), &mut OsRng)
        .expect("заявка читателя");
    let events = poll(&mut runtime);
    let join = event(&events, "join_request");
    assert_eq!(join["username"], reader_name);
    let account_id = join["account_id"].as_str().expect("аккаунт").to_owned();

    call(
        &mut runtime,
        "approveJoinRequest",
        json!({ "channel_id": channel_id, "account_id": account_id }),
    );
    assert_eq!(reader.check_channel_joins(now()).expect("вход").len(), 1);

    // Бот пишет в канал; читатель принимает запись.
    let post = call(
        &mut runtime,
        "publishPost",
        json!({ "channel_id": channel_id, "text": "от бота" }),
    );
    assert_eq!(post["seq"], 2);
    reader
        .sync_channel(channel_id, now())
        .expect("синхронизация");
    let texts: Vec<String> = reader
        .channel_posts(channel_id, 10)
        .expect("записи")
        .into_iter()
        .map(|entry| entry.text)
        .collect();
    assert_eq!(texts, ["первая", "от бота"]);

    // Запись владельца доходит до бота событием.
    owner
        .publish_channel_post(channel_id, "третья", &[], now(), &mut OsRng)
        .expect("запись");
    let events = poll(&mut runtime);
    assert_eq!(event(&events, "post")["post"]["text"], "третья");

    // Бот удаляет подписчика.
    let subscribers = call(
        &mut runtime,
        "subscribers",
        json!({ "channel_id": channel_id }),
    );
    assert!(subscribers
        .as_array()
        .expect("список")
        .iter()
        .any(|member| member["username"] == reader_name));
    call(
        &mut runtime,
        "removeSubscriber",
        json!({ "channel_id": channel_id, "account_id": account_id }),
    );
    assert!(reader.sync_channel(channel_id, now()).is_err());

    // Переписка: владелец пишет боту, бот отвечает.
    owner
        .add_contact_from_link(me["contact_link"].as_str().expect("ссылка"), now())
        .expect("контакт");
    owner
        .send_message(&bot_name, "привет, бот", now(), &mut OsRng)
        .expect("сообщение");
    let events = poll(&mut runtime);
    assert_eq!(event(&events, "message")["text"], "привет, бот");

    call(
        &mut runtime,
        "trustContact",
        json!({ "username": owner_name }),
    );
    call(
        &mut runtime,
        "sendMessage",
        json!({ "to": owner_name, "text": "привет, человек" }),
    );
    let device = owner.own_device_id().expect("устройство").expect("есть");
    assert_eq!(owner.receive_messages(&device, now()).expect("приём"), 1);

    // Кнопки: бот прикладывает их к сообщению, человек нажимает,
    // нажатие приходит боту событием.
    let asked = call(
        &mut runtime,
        "sendMessage",
        json!({
            "to": owner_name,
            "text": "Одобрить?",
            "buttons": [[{ "text": "Да", "data": "yes" }, { "text": "Сайт", "url": "https://example.org/" }]],
        }),
    );
    let asked_id = gasapp_types::MessageId::from_uuid(
        asked["message_id"]
            .as_str()
            .expect("id")
            .parse()
            .expect("uuid"),
    );
    owner.receive_messages(&device, now()).expect("приём");
    let keyboard = owner
        .message_keyboard(&asked_id)
        .expect("кнопки")
        .expect("есть");
    assert_eq!(keyboard.rows[0][0].label, "Да");
    assert_eq!(
        owner
            .press_button(&asked_id, 0, 1, now(), &mut OsRng)
            .expect("ссылка")
            .as_deref(),
        Some("https://example.org/")
    );
    owner
        .press_button(&asked_id, 0, 0, now(), &mut OsRng)
        .expect("нажатие");
    let events = poll(&mut runtime);
    let press = event(&events, "callback");
    assert_eq!(press["data"], "yes");
    assert_eq!(press["from"], owner_name);
    assert_eq!(press["message_id"], asked["message_id"]);

    // Негодная клавиатура — отказ, и сообщение не уходит.
    let refused: Value = serde_json::from_str(&runtime.handle(
        &json!({ "id": 2, "method": "sendMessage", "params": {
            "to": owner_name, "text": "x", "buttons": [[{ "text": "js", "url": "javascript:1" }]],
        }})
        .to_string(),
        now(),
    ))
    .unwrap();
    assert_eq!(refused["error"], "bad_request");

    // Негодная команда — ответ с ошибкой, а не молчание.
    let answer: Value =
        serde_json::from_str(&runtime.handle(r#"{"id":1,"method":"nope"}"#, now())).unwrap();
    assert_eq!(answer["ok"], false);
    assert_eq!(answer["error"], "bad_request");

    owner.delete_bot(&bot_name, now()).expect("удаление бота");

    cli_round_trip(&owner, &dir);
}

/// Сама программа `gasapp-bot`: `init` по токену, затем `run` — команда
/// на вход, ответ на выход, и выход по закрытию ввода.
fn cli_round_trip(owner: &Client<HttpTransport>, dir: &tempfile::TempDir) {
    use std::io::{BufRead as _, Write as _};
    use std::process::{Command, Stdio};

    let server = std::env::var("GASAPP_SERVER").expect("сервер");
    let bot_name = format!("{}_bot", unique("c"));
    let token = owner.create_bot(&bot_name, now()).expect("токен");
    let data = dir.path().join("cli-bot");
    let program = env!("CARGO_BIN_EXE_gasapp-bot");

    let init = Command::new(program)
        .args(["init", "--server", &server, "--data"])
        .arg(&data)
        .args(["--token", &token])
        .output()
        .expect("init запущен");
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    // Второй `init` в тот же каталог чужого бота не затирает.
    let again = Command::new(program)
        .args(["init", "--server", &server, "--data"])
        .arg(&data)
        .args(["--token", &token])
        .output()
        .expect("init запущен");
    assert!(!again.status.success());

    let mut run = Command::new(program)
        .arg("run")
        .arg("--data")
        .arg(&data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("run запущен");

    let mut input = run.stdin.take().expect("ввод");
    writeln!(input, r#"{{"id":"a","method":"getMe"}}"#).expect("команда");
    input.flush().expect("команда ушла");

    let mut output = std::io::BufReader::new(run.stdout.take().expect("вывод"));
    let mut answer = None;

    // Между ответами идут события обхода сервера; нужен ответ на команду.
    for _ in 0..50 {
        let mut line = String::new();
        if output.read_line(&mut line).expect("строка") == 0 {
            break;
        }

        let value: Value = serde_json::from_str(&line).expect("строка — JSON");
        if value["id"] == "a" {
            answer = Some(value);
            break;
        }
    }

    let answer = answer.expect("ответ на getMe");
    assert_eq!(answer["ok"], true);
    assert_eq!(answer["result"]["username"], bot_name);

    // Ввод закрыт — движок завершается сам.
    drop(input);
    assert!(run.wait().expect("выход").success());

    http_and_webhook(owner, &data, &bot_name);

    owner.delete_bot(&bot_name, now()).expect("удаление бота");
}

/// Один запрос к движку по HTTP; возвращает код и тело.
fn http_call(port: u16, request: &str) -> (u16, Value) {
    use std::io::{Read as _, Write as _};

    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("движок слушает");
    stream.write_all(request.as_bytes()).expect("запрос");

    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("ответ");

    let status = raw
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("код");
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default();

    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

/// Режим HTTP: команды запросами за секретом, события — на веб-хук.
fn http_and_webhook(owner: &Client<HttpTransport>, data: &std::path::Path, bot_name: &str) {
    use std::io::{Read as _, Write as _};
    use std::process::{Command, Stdio};

    // Веб-хук — этот тест; порт движку — свободный.
    let hook = std::net::TcpListener::bind("127.0.0.1:0").expect("веб-хук");
    let hook_port = hook.local_addr().expect("адрес").port();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|probe| probe.local_addr())
        .expect("свободный порт")
        .port();

    let mut run = Command::new(env!("CARGO_BIN_EXE_gasapp-bot"))
        .arg("run")
        .arg("--data")
        .arg(data)
        .args(["--poll", "2", "--secret", "s3cret"])
        .args(["--listen", &format!("127.0.0.1:{port}")])
        .args(["--webhook", &format!("http://127.0.0.1:{hook_port}/hook")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .expect("run запущен");

    // Движок поднимается не мгновенно.
    let mut ready = false;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "движок не слушает порт");

    // 🔐 Без секрета командой не управляют.
    let (status, _) = http_call(port, "POST /getMe HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(status, 401);

    let (status, me) = http_call(
        port,
        "POST /getMe HTTP/1.1\r\nAuthorization: Bearer s3cret\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(me["result"]["username"], bot_name);

    // Человек пишет боту — событие приходит на веб-хук с секретом.
    owner
        .add_contact_from_link(
            me["result"]["contact_link"].as_str().expect("ссылка"),
            now(),
        )
        .expect("контакт");
    owner
        .send_message(bot_name, "на веб-хук", now(), &mut OsRng)
        .expect("сообщение");

    hook.set_nonblocking(false).expect("режим");
    let (mut delivery, _) = hook.accept().expect("веб-хук вызван");
    delivery
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("таймаут");
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    while !String::from_utf8_lossy(&raw).contains("на веб-хук") {
        let read = delivery.read(&mut chunk).expect("тело события");
        assert!(read > 0, "событие оборвалось");
        raw.extend_from_slice(&chunk[..read]);
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    assert!(text.starts_with("POST /hook HTTP/1.1"));
    assert!(text.contains("X-GasApp-Bot-Secret: s3cret"));
    assert!(text.contains("\"event\":\"message\""));
    delivery
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .expect("ответ веб-хука");

    run.kill().expect("остановка");
    let _ = run.wait();
}
