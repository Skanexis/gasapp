// SPDX-License-Identifier: Apache-2.0

//! Движок бота: команды его программы и события для неё.
//!
//! Программа бота пишет в движок строки JSON — по одной команде на
//! строку — и читает строки JSON в ответ:
//!
//! ```text
//! → {"id": 1, "method": "sendMessage", "params": {"to": "alice", "text": "привет"}}
//! ← {"id": 1, "ok": true, "result": {"message_id": "…"}}
//! ← {"event": "message", "from": "alice", "text": "и тебе", …}
//! ```
//!
//! Команда — это один вызов ядра; движок ничего не решает за программу.
//! Исключение одно: входящий запрос на переписку принимается сам —
//! бот, который не отвечает незнакомым, никому не нужен.
//!
//! Событие — то, что движок увидел при очередном обходе сервера
//! ([`Runtime::poll`]): новое сообщение, новая запись канала, заявка в
//! канал, который бот ведёт, одобрение собственной заявки.
//!
//! # 🔐 Чему верит бот
//!
//! * Ответить человеку можно, только если его ключ подтверждён: ссылкой
//!   контакта (`addContact`), журналом ключей — сам, для имён старше
//!   суток, — либо командой `trustContact`. ⚠️ Последняя значит «верю
//!   серверу на слово, что это ключ этого имени»: решение автора бота.
//! * `approveJoinRequest` отдаёт заявителю ключ чтения канала. Поле
//!   `known_contact` события говорит, знаком ли заявитель боту; для
//!   незнакомых бот доверяет серверу в том, чья это заявка.

use std::collections::{HashMap, HashSet};

use gasapp_core::client::{Channel, ChannelEntry, ChannelMember, ChannelRole, ChatRequest, Client};
use gasapp_net::client::Transport;
use gasapp_types::{ChatId, GasAppError, Result, Timestamp};
use rand_core::OsRng;
use serde_json::{json, Map, Value};

/// Сколько последних сообщений чата просматривается за обход.
const MESSAGES_PER_POLL: u32 = 50;

/// Сколько сообщений чата считаются уже виденными при запуске.
const MESSAGES_AT_START: u32 = 500;

/// Сколько последних записей канала просматривается за обход.
const POSTS_PER_POLL: u32 = 100;

/// Предел записей в ответе на `posts`.
const MAX_POSTS: u64 = 500;

/// Предел строки команды: запись канала — до 16 000 байт, с запасом.
pub const MAX_COMMAND_BYTES: usize = 256 * 1024;

/// Движок одного бота.
pub struct Runtime<T: Transport> {
    client: Client<T>,
    /// Сообщения, о которых программе уже сказано.
    seen_messages: HashSet<String>,
    /// Заявки в каналы, о которых программе уже сказано: канал и аккаунт.
    seen_requests: HashSet<(String, String)>,
    /// Номер последней записи канала, о которой программе уже сказано.
    last_seq: HashMap<String, u64>,
}

impl<T: Transport> Runtime<T> {
    /// Собирает движок над клиентом зарегистрированного бота.
    ///
    /// Всё, что уже лежит в хранилище, считается виденным: после
    /// перезапуска программа получает только новое.
    ///
    /// # Errors
    ///
    /// [`GasAppError::SessionNotFound`] — бот не зарегистрирован;
    /// [`GasAppError::Storage`] — хранилище не читается.
    pub fn new(client: Client<T>) -> Result<Self> {
        if client.own_username()?.is_none() {
            return Err(GasAppError::SessionNotFound);
        }

        let mut seen_messages = HashSet::new();

        for chat in client.chats()? {
            for message in client.messages(&chat, MESSAGES_AT_START)? {
                seen_messages.insert(message.message_id.to_string());
            }
        }

        let mut last_seq = HashMap::new();

        for channel in client.channels()? {
            let newest = client
                .channel_posts(&channel.channel_id, 1)?
                .last()
                .map_or(0, |post| post.seq);

            last_seq.insert(channel.channel_id, newest);
        }

        Ok(Self {
            client,
            seen_messages,
            seen_requests: HashSet::new(),
            last_seq,
        })
    }

    /// Выполняет одну команду и возвращает строку ответа.
    ///
    /// Негодная строка — тоже ответ, с ошибкой `bad_request`: молчание
    /// оставило бы программу ждать вечно.
    pub fn handle(&mut self, line: &str, now: Timestamp) -> String {
        let parsed: Option<Value> = if line.len() <= MAX_COMMAND_BYTES {
            serde_json::from_str(line).ok()
        } else {
            None
        };

        let id = parsed
            .as_ref()
            .and_then(|command| command.get("id"))
            .cloned()
            .unwrap_or(Value::Null);

        let outcome = parsed
            .as_ref()
            .and_then(Value::as_object)
            .ok_or(GasAppError::Malformed)
            .and_then(|command| {
                let method = command
                    .get("method")
                    .and_then(Value::as_str)
                    .ok_or(GasAppError::Malformed)?;
                let empty = Map::new();
                let params = match command.get("params") {
                    None | Some(Value::Null) => &empty,
                    Some(Value::Object(params)) => params,
                    Some(_) => return Err(GasAppError::Malformed),
                };

                self.call(method, params, now)
            });

        match outcome {
            Ok(result) => json!({ "id": id, "ok": true, "result": result }),
            Err(error) => json!({ "id": id, "ok": false, "error": code_of(&error) }),
        }
        .to_string()
    }

    /// Один обход сервера: приём сообщений, каналы, заявки. Возвращает
    /// строки событий для программы.
    ///
    /// Сбой сети — не событие: следующий обход повторит то же самое.
    pub fn poll(&mut self, now: Timestamp) -> Vec<String> {
        let mut events = Vec::new();

        self.poll_messages(now, &mut events);
        self.poll_joins(now, &mut events);
        self.poll_channels(now, &mut events);

        // Предключи — после приёма: активная переписка их расходует.
        let _ = self.client.maintain_prekeys(now, &mut OsRng);

        events.iter().map(Value::to_string).collect()
    }

    fn poll_messages(&mut self, now: Timestamp, events: &mut Vec<Value>) {
        let Ok(Some(device_id)) = self.client.own_device_id() else {
            return;
        };

        let _ = self.client.receive_messages(&device_id, now);

        let names: HashMap<ChatId, String> = self
            .client
            .contacts()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|contact| Some((contact.chat_id?, contact.username?)))
            .collect();

        for chat in self.client.chats().unwrap_or_default() {
            let Ok(messages) = self.client.messages(&chat, MESSAGES_PER_POLL) else {
                continue;
            };

            for message in messages {
                if !self.seen_messages.insert(message.message_id.to_string()) || message.outgoing {
                    continue;
                }

                // Незнакомец написал первым: запрос принимается, чтобы
                // бот мог ответить. Ключ собеседника это не подтверждает.
                if matches!(
                    self.client.chat_request(&chat),
                    Ok(Some(ChatRequest::Incoming))
                ) {
                    let _ = self.client.accept_chat(&chat, now, &mut OsRng);
                }

                events.push(json!({
                    "event": "message",
                    "chat_id": chat.to_string(),
                    "from": names.get(&chat),
                    "message_id": message.message_id.to_string(),
                    "text": message.text,
                    "at": message.timestamp.as_millis(),
                }));
            }
        }
    }

    fn poll_joins(&mut self, now: Timestamp, events: &mut Vec<Value>) {
        for channel in self.client.check_channel_joins(now).unwrap_or_default() {
            // Записи, пришедшие вместе со входом, — уже история.
            let newest = self
                .client
                .channel_posts(&channel.channel_id, 1)
                .ok()
                .and_then(|posts| posts.last().map(|post| post.seq))
                .unwrap_or(0);
            self.last_seq.insert(channel.channel_id.clone(), newest);

            events.push(json!({ "event": "joined", "channel": channel_json(&channel) }));
        }
    }

    fn poll_channels(&mut self, now: Timestamp, events: &mut Vec<Value>) {
        let _ = self.client.sync_channels(now);
        // Бот, который ведёт закрытый канал, доводит смену ключа и выдаёт
        // ключи участникам, у кого их нет.
        let _ = self.client.maintain_channel_keys(now, &mut OsRng);

        for channel in self.client.channels().unwrap_or_default() {
            let id = channel.channel_id.clone();
            let posts = self
                .client
                .channel_posts(&id, POSTS_PER_POLL)
                .unwrap_or_default();
            let newest = posts.last().map_or(0, |post| post.seq);

            match self.last_seq.get(&id).copied() {
                // Канал появился между обходами: его лента — история.
                None => {}
                Some(known) => {
                    for post in posts.iter().filter(|post| post.seq > known) {
                        events.push(json!({
                            "event": "post",
                            "channel_id": id,
                            "post": post_json(post),
                        }));
                    }
                }
            }
            self.last_seq.insert(id.clone(), newest);

            if channel.closed && channel.can_post() {
                self.poll_requests(&id, now, events);
            }
        }
    }

    fn poll_requests(&mut self, channel_id: &str, now: Timestamp, events: &mut Vec<Value>) {
        let Ok(requests) = self.client.channel_join_requests(channel_id, now) else {
            return;
        };

        let waiting: HashSet<&str> = requests
            .iter()
            .map(|request| request.account_id.as_str())
            .collect();

        // Заявка, на которую ответили, забывается: повторная от того же
        // аккаунта — новое событие.
        self.seen_requests.retain(|(channel, account)| {
            channel != channel_id || waiting.contains(account.as_str())
        });

        for request in &requests {
            if self
                .seen_requests
                .insert((channel_id.to_owned(), request.account_id.clone()))
            {
                events.push(json!({
                    "event": "join_request",
                    "channel_id": channel_id,
                    "account_id": request.account_id,
                    "username": request.username,
                    "known_contact": request.known_contact,
                }));
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn call(&mut self, method: &str, params: &Map<String, Value>, now: Timestamp) -> Result<Value> {
        let client = &self.client;
        let rng = &mut OsRng;

        match method {
            "getMe" => Ok(json!({
                "username": client.own_username()?,
                "device_id": client.own_device_id()?,
                "contact_link": client.own_contact_link()?,
            })),

            // --- Переписка ---------------------------------------------------
            "addContact" => {
                let contact = client.add_contact_from_link(text(params, "link")?, now)?;

                Ok(json!({ "username": contact.username }))
            }
            "trustContact" => {
                // ⚠️ «Верю серверу на слово»: ключ имени берётся у сервера
                // и отмечается сверенным без сверки.
                let contact = client.discover_contact(text(params, "username")?, now)?;
                client.set_contact_verified(&contact.account_id, true, now)?;

                Ok(json!({ "username": contact.username }))
            }
            "contacts" => Ok(Value::Array(
                client
                    .contacts()?
                    .into_iter()
                    .map(|contact| {
                        json!({
                            "username": contact.username,
                            "verified": contact.verified,
                            "key_confirmed": contact.key_confirmed,
                            "key_changed": contact.key_changed,
                        })
                    })
                    .collect(),
            )),
            "sendMessage" => {
                let id =
                    client.send_message(text(params, "to")?, text(params, "text")?, now, rng)?;

                Ok(json!({ "message_id": id.to_string() }))
            }

            // --- Каналы: читать ---------------------------------------------
            "channels" => Ok(Value::Array(
                client.channels()?.iter().map(channel_json).collect(),
            )),
            "joinChannel" => {
                let channel = client.join_channel(text(params, "link")?, now)?;
                self.remember(&channel);

                Ok(channel_json(&channel))
            }
            "requestJoin" => {
                client.request_channel_join(text(params, "link")?, now, rng)?;

                Ok(Value::Null)
            }
            "pendingJoins" => Ok(Value::Array(
                client
                    .pending_channel_joins()?
                    .into_iter()
                    .map(|join| {
                        json!({
                            "channel_id": join.channel_id,
                            "requested_at": join.requested_at.as_millis(),
                        })
                    })
                    .collect(),
            )),
            "syncChannel" => {
                let fresh = client.sync_channel(text(params, "channel_id")?, now)?;

                Ok(json!({ "new_posts": fresh }))
            }
            "posts" => {
                let limit = params
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(50)
                    .min(MAX_POSTS);
                let limit = u32::try_from(limit).map_err(|_| GasAppError::Malformed)?;

                Ok(Value::Array(
                    client
                        .channel_posts(text(params, "channel_id")?, limit)?
                        .iter()
                        .map(post_json)
                        .collect(),
                ))
            }
            "leaveChannel" => {
                let channel_id = text(params, "channel_id")?;
                client.leave_channel(channel_id, now)?;
                self.last_seq.remove(channel_id);

                Ok(Value::Null)
            }

            // --- Каналы: вести ----------------------------------------------
            "adminRequest" => Ok(json!({
                "request": client.channel_admin_request(text(params, "channel_id")?, rng)?,
            })),
            "publishPost" => {
                let channel_id = text(params, "channel_id")?;
                let post = client.publish_channel_post(
                    channel_id,
                    text(params, "text")?,
                    &[],
                    now,
                    rng,
                )?;

                // Своя запись — не новость для того, кто её написал.
                let known = self.last_seq.entry(channel_id.to_owned()).or_insert(0);
                *known = (*known).max(post.seq);

                Ok(post_json(&post))
            }
            "editPost" => {
                let post = client.edit_channel_post(
                    text(params, "channel_id")?,
                    number(params, "seq")?,
                    text(params, "text")?,
                    now,
                    rng,
                )?;

                Ok(post_json(&post))
            }
            "deletePost" => {
                client.delete_channel_post(
                    text(params, "channel_id")?,
                    number(params, "seq")?,
                    now,
                    rng,
                )?;

                Ok(Value::Null)
            }
            "pinPost" => {
                // `seq: 0` снимает закреп.
                let channel = client.pin_channel_post(
                    text(params, "channel_id")?,
                    number(params, "seq")?,
                    now,
                    rng,
                )?;

                Ok(channel_json(&channel))
            }

            // --- Закрытый канал: приглашения, заявки, подписчики ------------
            "createInvite" => Ok(json!({
                "link": client.create_channel_invite(text(params, "channel_id")?, now, rng)?,
            })),
            "invites" => Ok(json!(client.channel_invites(text(params, "channel_id")?)?)),
            "revokeInvite" => {
                client.revoke_channel_invite(
                    text(params, "channel_id")?,
                    text(params, "link")?,
                    now,
                )?;

                Ok(Value::Null)
            }
            "joinRequests" => Ok(Value::Array(
                client
                    .channel_join_requests(text(params, "channel_id")?, now)?
                    .into_iter()
                    .map(|request| {
                        json!({
                            "account_id": request.account_id,
                            "username": request.username,
                            "known_contact": request.known_contact,
                        })
                    })
                    .collect(),
            )),
            "approveJoinRequest" | "declineJoinRequest" => {
                client.answer_channel_join(
                    text(params, "channel_id")?,
                    text(params, "account_id")?,
                    method == "approveJoinRequest",
                    now,
                    rng,
                )?;

                Ok(Value::Null)
            }
            "subscribers" => Ok(members_json(client.channel_subscribers(
                text(params, "channel_id")?,
                params.get("after").and_then(Value::as_str),
                now,
            )?)),
            "banned" => Ok(members_json(
                client.channel_banned(text(params, "channel_id")?, now)?,
            )),
            "removeSubscriber" | "restoreSubscriber" => {
                client.remove_channel_subscriber(
                    text(params, "channel_id")?,
                    text(params, "account_id")?,
                    method == "restoreSubscriber",
                    now,
                    rng,
                )?;

                Ok(Value::Null)
            }

            _ => Err(GasAppError::Malformed),
        }
    }

    /// Канал, добавленный командой: его лента к этому моменту — история.
    fn remember(&mut self, channel: &Channel) {
        let newest = self
            .client
            .channel_posts(&channel.channel_id, 1)
            .ok()
            .and_then(|posts| posts.last().map(|post| post.seq))
            .unwrap_or(0);

        self.last_seq
            .entry(channel.channel_id.clone())
            .or_insert(newest);
    }
}

fn text<'a>(params: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    params
        .get(name)
        .and_then(Value::as_str)
        .ok_or(GasAppError::Malformed)
}

fn number(params: &Map<String, Value>, name: &str) -> Result<u64> {
    params
        .get(name)
        .and_then(Value::as_u64)
        .ok_or(GasAppError::Malformed)
}

fn channel_json(channel: &Channel) -> Value {
    json!({
        "channel_id": channel.channel_id,
        "title": channel.title,
        "description": channel.description,
        "role": match channel.role {
            ChannelRole::Reader => "reader",
            ChannelRole::Pending => "admin_pending",
            ChannelRole::Admin => "admin",
            ChannelRole::Owner => "owner",
        },
        "closed": channel.closed,
        "rekey_pending": channel.rekey_pending,
        "handle": channel.handle,
        "subscribers": channel.subscribers,
        "pinned_seq": channel.pinned_seq,
    })
}

fn post_json(post: &ChannelEntry) -> Value {
    json!({
        "seq": post.seq,
        "text": post.text,
        "created_at": post.created_at.as_millis(),
        "edited_at": post.edited_at.map(|at| at.as_millis()),
        "views": post.views,
        "attachments": post.attachments.len(),
    })
}

fn members_json(members: Vec<ChannelMember>) -> Value {
    Value::Array(
        members
            .into_iter()
            .map(|member| json!({ "account_id": member.account_id, "username": member.username }))
            .collect(),
    )
}

/// Ошибка ядра — коротким словом для программы бота.
///
/// 🔐 Текста ошибки нет намеренно: он мог бы вынести наружу то, что
/// ядро держит при себе.
fn code_of(error: &GasAppError) -> &'static str {
    match error {
        GasAppError::Network => "network",
        GasAppError::Forbidden => "forbidden",
        GasAppError::SessionNotFound => "not_found",
        GasAppError::UsernameTaken => "conflict",
        GasAppError::Malformed => "bad_request",
        GasAppError::InvalidUsername => "invalid_username",
        GasAppError::PeerUnconfirmed => "peer_unconfirmed",
        GasAppError::IdentityChanged => "identity_changed",
        GasAppError::InvalidSignature => "invalid_signature",
        GasAppError::Storage => "storage",
        _ => "error",
    }
}
