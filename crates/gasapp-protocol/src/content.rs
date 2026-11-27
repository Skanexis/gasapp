// SPDX-License-Identifier: Apache-2.0

//! Содержимое сообщения.
//!
//! # Зачем формат, если раньше хватало текста
//!
//! Текст — только один вид сообщения. Вложения, ответы, реакции,
//! правки и удаления должны отличаться друг от друга, и отличие
//! обязано быть **внутри** шифрования: сервер, знающий, что вот это
//! реакция, а вот это удаление, восстанавливает структуру разговора,
//! не читая ни слова.
//!
//! # Почему ручной формат, а не serde
//!
//! Разбор идёт над тем, что прислал собеседник. Он расшифровался —
//! значит отправлен владельцем ключа сессии, но это не делает его
//! добросовестным: он мог собрать сообщение своей реализацией.
//! Ручной разбор с явной проверкой каждой длины показывает границы
//! глазами и покрывается фаззингом.
//!
//! # Про совместимость
//!
//! Неизвестный тип содержимого отвергается, а не игнорируется.
//! Молчаливый пропуск означал бы, что сообщение от новой версии
//! выглядит доставленным и пустым — пользователь решил бы, что
//! собеседник прислал пустоту, хотя тот прислал, например, опрос.

use gasapp_types::{GasAppError, Result};

/// Версия формата содержимого.
pub const CONTENT_VERSION: u8 = 1;

/// Предел длины текста сообщения.
///
/// 🔐 Приходит от собеседника и попадает в разметку. Без предела
/// текст на десять мегабайт занял бы память при разборе каждого
/// входящего сообщения.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;

/// Предел числа вложений в одном сообщении.
pub const MAX_ATTACHMENTS: usize = 10;

/// Предел длины реакции.
///
/// Реакция — один-два эмодзи; четыре символа с запасом покрывают
/// составные последовательности вроде флагов и семей.
pub const MAX_REACTION_BYTES: usize = 32;

/// Тип содержимого: текст.
const KIND_TEXT: u8 = 1;

/// Тип: сообщение с вложениями.
const KIND_ATTACHMENTS: u8 = 2;

/// Тип: реакция на сообщение.
const KIND_REACTION: u8 = 3;

/// Тип: правка ранее отправленного.
const KIND_EDIT: u8 = 4;

/// Тип: удаление для всех.
const KIND_DELETE: u8 = 5;

/// Тип: индикатор набора текста.
const KIND_TYPING: u8 = 6;

/// Тип: квитанция о прочтении.
const KIND_READ_RECEIPT: u8 = 7;

/// Тип: ключ доступа sealed sender.
const KIND_ACCESS_KEY: u8 = 8;

/// Тип: вершина журнала ключей, которую видит отправитель (§9.7).
const KIND_KT_HEAD: u8 = 9;

/// Тип содержимого: кнопки под сообщением.
const KIND_KEYBOARD: u8 = 10;

/// Тип содержимого: нажатие кнопки.
const KIND_CALLBACK: u8 = 11;

/// Тип содержимого: таймер исчезающих сообщений чата.
const KIND_DISAPPEARING_TIMER: u8 = 12;

/// Копия отправленного своим устройствам (`docs/protocol/MULTI-DEVICE.md`).
const KIND_SENT: u8 = 13;

/// Перенесённая история: последние 30 дней — новому своему устройству.
const KIND_HISTORY: u8 = 14;

/// Блокировка собеседника — своим устройствам (только внутри копии).
const KIND_BLOCK: u8 = 15;

/// Назначение администратором канала (см. [`Content::ChannelAdmin`]).
const KIND_CHANNEL_ADMIN: u8 = 16;

/// Предел ссылки канала в назначении администратором.
pub const MAX_CHANNEL_LINK_BYTES: usize = 4 * 1024;

/// Фото профиля (см. [`Content::ProfilePhoto`]).
const KIND_PROFILE_PHOTO: u8 = 17;

/// Квитанция доставки (см. [`Content::DeliveryReceipt`]).
const KIND_DELIVERY_RECEIPT: u8 = 18;

/// Предел фото профиля: маленький квадрат JPEG, а не снимок.
pub const MAX_PROFILE_PHOTO_BYTES: usize = 96 * 1024;

/// Сколько сообщений истории в одной пачке. Объём это не ограничивает:
/// 200 текстов на пределе в бакет padding (256 КиБ) не влезут — пачки по
/// объёму режет отправитель (`client::history`), а слишком большую
/// отвергнет `to_bytes`.
pub const MAX_HISTORY_ITEMS: usize = 200;

/// Наибольший таймер исчезающих сообщений — год.
///
/// 🔐 Значение приходит от собеседника. Без предела «таймер» на
/// сотню лет был бы тем же «выключено», но выглядел бы включённым.
pub const MAX_DISAPPEARING_SECONDS: u32 = 365 * 24 * 60 * 60;

/// Длина вершины журнала ключей.
pub const KT_HEAD_LEN: usize = 32;

/// Длина ключа доступа sealed sender.
pub const ACCESS_KEY_LEN: usize = 32;

/// Длина идентификатора сообщения.
pub const MESSAGE_ID_LEN: usize = 16;

/// Ключ доступа: метка, ключ и необязательный хвост — имя (метка 1;
/// так писали прежние версии) и список устройств (метка 2).
fn write_access_key(
    out: &mut Vec<u8>,
    key: &[u8; ACCESS_KEY_LEN],
    sender_username: Option<&str>,
    device_list: Option<&[u8]>,
) -> Result<()> {
    out.push(KIND_ACCESS_KEY);
    out.extend_from_slice(key);

    // Хвост необязателен: сообщение без него читается как
    // «имени нет» — так писали прежние версии.
    if let Some(name) = sender_username {
        out.push(1);
        write_text(out, name)?;
    }
    if let Some(list) = device_list {
        if list.len() > MAX_DEVICE_LIST_BYTES {
            return Err(GasAppError::Malformed);
        }
        out.push(2);
        write_bytes(out, list)?;
    }
    Ok(())
}

/// Разбирает ключ доступа после метки вида.
fn read_access_key(reader: &mut Reader<'_>) -> Result<Content> {
    let key = reader.take_access_key()?;
    let mut sender_username = None;
    let mut device_list = None;
    // Поля хвоста — по метке, каждое не больше раза, в порядке
    // имя → список: прежние версии писали только имя.
    while !reader.at_end() {
        match reader.take_u8()? {
            1 if sender_username.is_none() && device_list.is_none() => {
                sender_username = Some(reader.take_text()?);
            }
            2 if device_list.is_none() => {
                let list = reader.take_blob()?;
                if list.len() > MAX_DEVICE_LIST_BYTES {
                    return Err(GasAppError::Malformed);
                }
                device_list = Some(list);
            }
            _ => return Err(GasAppError::Malformed),
        }
    }
    Ok(Content::AccessKey {
        key,
        sender_username,
        device_list,
    })
}

/// Копия отправленного: метка, ключ собеседника, имя (0/1 и текст),
/// вложенное содержимое без padding.
fn write_sent(
    out: &mut Vec<u8>,
    peer: &[u8; 32],
    peer_username: Option<&str>,
    content: &Content,
) -> Result<()> {
    if matches!(
        content,
        Content::Sent { .. } | Content::History { .. } | Content::ChannelAdmin { .. }
    ) {
        return Err(GasAppError::Malformed);
    }
    out.push(KIND_SENT);
    out.extend_from_slice(peer);
    match peer_username {
        Some(name) => {
            out.push(1);
            write_text(out, name)?;
        }
        None => out.push(0),
    }
    write_bytes(out, &content.to_unpadded_bytes()?)
}

/// Разбирает копию отправленного после метки вида.
fn read_sent(reader: &mut Reader<'_>) -> Result<Content> {
    let peer: [u8; 32] = reader
        .take_slice(32)?
        .try_into()
        .map_err(|_| GasAppError::Malformed)?;
    let peer_username = match reader.take_u8()? {
        0 => None,
        1 => Some(reader.take_text()?),
        _ => return Err(GasAppError::Malformed),
    };
    let inner = Content::from_unpadded_bytes(&reader.take_blob()?)?;
    if matches!(
        inner,
        Content::Sent { .. } | Content::History { .. } | Content::ChannelAdmin { .. }
    ) {
        return Err(GasAppError::Malformed);
    }
    Ok(Content::Sent {
        peer,
        peer_username,
        content: Box::new(inner),
    })
}

/// Сообщение перенесённой истории ([`Content::History`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryItem {
    /// Ключ аккаунта собеседника — по нему чат на новом устройстве.
    pub peer: [u8; 32],
    /// Его имя — чтобы чат был с именем.
    pub peer_username: Option<String>,
    /// Идентификатор сообщения — тот же, что у оригинала: правки и
    /// удаления потом находят его и здесь.
    pub id: [u8; MESSAGE_ID_LEN],
    /// Отправлено с этого аккаунта (иначе — получено от собеседника).
    pub outgoing: bool,
    /// Время отправки, миллисекунды Unix.
    pub sent_at_millis: i64,
    /// Текст.
    pub body: String,
}

/// История: число, затем каждое сообщение — собеседник, имя (0/1 и
/// текст), идентификатор, направление, время, текст.
fn write_history(out: &mut Vec<u8>, items: &[HistoryItem]) -> Result<()> {
    if items.is_empty() || items.len() > MAX_HISTORY_ITEMS {
        return Err(GasAppError::Malformed);
    }
    out.push(KIND_HISTORY);
    out.extend_from_slice(
        &u16::try_from(items.len())
            .map_err(|_| GasAppError::Malformed)?
            .to_be_bytes(),
    );
    for item in items {
        out.extend_from_slice(&item.peer);
        match &item.peer_username {
            Some(name) => {
                out.push(1);
                write_text(out, name)?;
            }
            None => out.push(0),
        }
        out.extend_from_slice(&item.id);
        out.push(u8::from(item.outgoing));
        out.extend_from_slice(&item.sent_at_millis.to_be_bytes());
        write_text(out, &item.body)?;
    }
    Ok(())
}

/// Разбирает историю после метки вида.
fn read_history(reader: &mut Reader<'_>) -> Result<Content> {
    let count_bytes: [u8; 2] = reader
        .take_slice(2)?
        .try_into()
        .map_err(|_| GasAppError::Malformed)?;
    let count = usize::from(u16::from_be_bytes(count_bytes));
    if count == 0 || count > MAX_HISTORY_ITEMS {
        return Err(GasAppError::Malformed);
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let peer: [u8; 32] = reader
            .take_slice(32)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)?;
        let peer_username = match reader.take_u8()? {
            0 => None,
            1 => Some(reader.take_text()?),
            _ => return Err(GasAppError::Malformed),
        };
        let id = reader.take_id()?;
        let outgoing = match reader.take_u8()? {
            0 => false,
            1 => true,
            _ => return Err(GasAppError::Malformed),
        };
        let time: [u8; 8] = reader
            .take_slice(8)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)?;
        items.push(HistoryItem {
            peer,
            peer_username,
            id,
            outgoing,
            sent_at_millis: i64::from_be_bytes(time),
            body: reader.take_text()?,
        });
    }
    Ok(Content::History { items })
}

/// Предел списка устройств в ключе доступа: 5 устройств и подпись.
pub const MAX_DEVICE_LIST_BYTES: usize = 20_000;

/// Содержимое сообщения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// Текст, возможно ответ на другое сообщение.
    Text {
        /// Сам текст.
        body: String,
        /// Сообщение, на которое отвечают.
        ///
        /// 🔐 Цитата не передаётся: получатель находит исходное
        /// сообщение у себя. Передача цитаты означала бы, что текст,
        /// который собеседник, возможно, уже удалил, возвращается
        /// к нему обратно.
        reply_to: Option<[u8; MESSAGE_ID_LEN]>,
        /// Идентификатор сообщения, выбранный отправителем.
        ///
        /// 🔐 Общий для обеих сторон: правка, удаление, реакция
        /// и квитанция ссылаются на сообщение по нему. Прежде его не было,
        /// и идентификатор каждая сторона выдумывала сама: ссылок
        /// отправителя получатель не находил — «удалить у всех»
        /// не удаляло, правка не правила, квитанция ничего не отмечала.
        ///
        /// ⚠️ Выбран собеседником, то есть не доверен: получатель
        /// не даёт ему заменить уже сохранённое сообщение и принимает
        /// правку и удаление только для сообщений этого же собеседника
        /// в этом же чате.
        id: [u8; MESSAGE_ID_LEN],
    },

    /// Вложения с подписью.
    Attachments {
        /// Подпись к вложениям.
        body: String,
        /// Описания вложений в сериализованном виде.
        ///
        /// Байты, а не разобранные структуры: описание принадлежит
        /// `gasapp-media`, и протокол не должен от него зависеть —
        /// иначе смена формата вложения тянула бы за собой изменение
        /// протокола сообщений.
        descriptors: Vec<Vec<u8>>,
        /// Ответ на сообщение.
        reply_to: Option<[u8; MESSAGE_ID_LEN]>,
        /// Идентификатор сообщения — как у [`Content::Text`].
        ///
        /// 🔐 Общий для обеих сторон: правка, удаление, реакция
        /// и квитанция ссылаются на сообщение по нему. Прежде его не было,
        /// и идентификатор каждая сторона выдумывала сама: ссылок
        /// отправителя получатель не находил — «удалить у всех»
        /// не удаляло, правка не правила, квитанция ничего не отмечала.
        ///
        /// ⚠️ Выбран собеседником, то есть не доверен: получатель
        /// не даёт ему заменить уже сохранённое сообщение и принимает
        /// правку и удаление только для сообщений этого же собеседника
        /// в этом же чате.
        id: [u8; MESSAGE_ID_LEN],
    },

    /// Реакция на сообщение.
    Reaction {
        /// Сообщение, на которое реагируют.
        target: [u8; MESSAGE_ID_LEN],
        /// Символ реакции. Пустая строка снимает реакцию.
        emoji: String,
    },

    /// Правка ранее отправленного сообщения.
    Edit {
        /// Правимое сообщение.
        target: [u8; MESSAGE_ID_LEN],
        /// Новый текст.
        body: String,
    },

    /// Удаление сообщения у всех участников.
    ///
    /// 🔐 Это просьба, а не гарантия: получатель уже видел сообщение
    /// и мог сделать снимок экрана. Клиент обязан удалить, но
    /// обещать пользователю, что сообщение исчезло у собеседника,
    /// нельзя — интерфейс должен говорить «удалено у вас и запрошено
    /// удаление у собеседника».
    Delete {
        /// Удаляемое сообщение.
        target: [u8; MESSAGE_ID_LEN],
    },

    /// Индикатор набора текста.
    ///
    /// 🔐 Отправляется только при явно включённой настройке.
    /// Индикатор сообщает собеседнику, что человек сейчас у телефона
    /// и печатает, — то есть выдаёт присутствие с точностью до секунд.
    /// Для переписки, где важна анонимность, это существеннее
    /// содержимого: собеседник узнаёт распорядок дня.
    ///
    /// По умолчанию выключен: privacy-функция, требующая отключения,
    /// защищает только тех, кто нашёл настройку.
    Typing {
        /// Печатает ли пользователь сейчас.
        ///
        /// `false` отправляется при остановке: без него индикатор
        /// висел бы до таймаута, показывая активность, которой нет.
        active: bool,
    },

    /// Кнопки под ранее отправленным сообщением
    /// (`crate::keyboard`). Пустая клавиатура убирает кнопки.
    ///
    /// Отдельным содержимым, а не полем сообщения: формат текста не
    /// меняется, а кнопки можно заменить или убрать позже.
    Keyboard {
        /// Сообщение отправителя, к которому относятся кнопки.
        target: [u8; MESSAGE_ID_LEN],
        /// Клавиатура в закодированном виде. Байты, а не структура:
        /// разбирает её тот, кто показывает.
        keyboard: Vec<u8>,
    },

    /// Нажатие кнопки с данными — автору сообщения с кнопками.
    ///
    /// 🔐 В переписке не показывается, но сообщает автору, что человек
    /// сейчас у телефона, — как любой ответ.
    Callback {
        /// Сообщение, под которым нажата кнопка.
        target: [u8; MESSAGE_ID_LEN],
        /// Данные нажатой кнопки.
        data: Vec<u8>,
    },

    /// Квитанция о прочтении.
    ///
    /// 🔐 Тоже opt-in и по той же причине: квитанция сообщает
    /// отправителю, что человек открыл переписку именно сейчас.
    ///
    /// Отправляется не за каждое сообщение, а с указанием последнего
    /// прочитанного: иначе открытие чата с сотней непрочитанных
    /// породило бы сто сообщений, и по их числу собеседник узнал бы,
    /// сколько всего накопилось.
    ReadReceipt {
        /// Последнее прочитанное сообщение.
        until: [u8; MESSAGE_ID_LEN],
    },

    /// Ключ доступа sealed sender (раздел 15.2).
    ///
    /// # Зачем он передаётся сообщением
    ///
    /// 🔐 При sealed sender сервер не знает отправителя, и без
    /// дополнительной проверки писать анонимно мог бы кто угодно
    /// кому угодно. Ключ доступа — ответ на это: сервер сверяет
    /// его с хешем, не узнавая, кто предъявил, и пропускает только
    /// тех, кому получатель ключ дал.
    ///
    /// Ключ раздаётся **внутри переписки**, то есть под сквозным
    /// шифрованием: сервер не видит, кому он выдан, и потому не может
    /// построить по нему список контактов.
    ///
    /// ⚠️ Отсюда следует порядок, который стоит понимать честно:
    /// первое сообщение собеседнику идёт обычным путём — сервер
    /// видит отправителя, — а запечатанными становятся последующие.
    /// Скрыть первое нечем: пока ключ не передан, доказать право
    /// на анонимную отправку невозможно.
    ///
    /// Ключ не секрет в криптографическом смысле: он ничего
    /// не шифрует и не подписывает. Его утечка означает лишь, что
    /// укравший сможет писать владельцу анонимно, — а не читать
    /// его переписку.
    AccessKey {
        /// Сам ключ.
        key: [u8; ACCESS_KEY_LEN],
        /// Собственное имя отправителя — чтобы ему можно было ответить.
        ///
        /// 🔐 Начальный конверт несёт только identity-ключ отправителя:
        /// ни имени, ни устройства. Ответить на него было нечем, и первое
        /// сообщение от нового собеседника оставалось без ответа — чат
        /// был, отправка в него падала. Имя едет здесь, под шифрованием:
        /// получатель его узнаёт, сервер нет.
        ///
        /// ⚠️ Это заявление, а не удостоверение: получатель принимает имя,
        /// только если discovery по нему возвращает тот же identity-ключ.
        /// Иначе назвавшийся «alice» получил бы ответ, ушедший настоящей
        /// Алисе в другой чат.
        sender_username: Option<String>,
        /// Подписанный ключом аккаунта список устройств отправителя
        /// (`docs/protocol/MULTI-DEVICE.md`) — его шлёт подключённое
        /// устройство первым сообщением новой сессии.
        ///
        /// 🔐 Под шифрованием, а не запросом к серверу: спроси получатель
        /// сервер «чьё это устройство» сразу после доставки, сервер узнал
        /// бы отправителя запечатанного конверта. Получатель проверяет
        /// подпись сам.
        device_list: Option<Vec<u8>>,
    },

    /// Копия отправленного — своим устройствам (`docs/protocol/MULTI-DEVICE.md`).
    ///
    /// Сообщение, отправленное собеседнику с одного устройства, уходит и
    /// остальным устройствам аккаунта: обычными сессиями между своими
    /// устройствами, сервер видит только шифротекст. Принимается только
    /// от устройства своего же аккаунта.
    Sent {
        /// Ключ аккаунта собеседника, которому отправлено.
        peer: [u8; 32],
        /// Его имя — чтобы чат на этом устройстве был с именем.
        peer_username: Option<String>,
        /// Само отправленное содержимое (вложенная копия не допускается).
        content: Box<Content>,
    },

    /// Перенесённая история — новому своему устройству
    /// (`docs/protocol/MULTI-DEVICE.md`, этап 4б): последние 30 дней,
    /// только текст, пачками до [`MAX_HISTORY_ITEMS`].
    ///
    /// 🔐 Принимается только от основного устройства своего аккаунта и
    /// только вскоре после подключения: иначе любое своё устройство
    /// могло бы вписать другим «входящие» от собеседников.
    History {
        /// Сообщения пачки.
        items: Vec<HistoryItem>,
    },

    /// Блокировка собеседника, поставленная или снятая на другом своём
    /// устройстве. Имеет смысл только внутри [`Content::Sent`]: от
    /// собеседника она ничего не значит.
    Block {
        /// Заблокирован ли.
        blocked: bool,
    },

    /// Владелец канала назначает собеседника администратором — без
    /// заявки: ссылка на канал и ключ подписи администратора, который
    /// владелец завёл для него и уже вписал в описание канала.
    ///
    /// 🔐 Ключ едет только внутри сквозного шифрования, и только этому
    /// собеседнику: копий своим устройствам владельца нет (внутри
    /// [`Content::Sent`] не принимается). Владелец ключ знает — но он и
    /// так подписывает канал целиком; читатели проверяют записи по
    /// ключам из описания, подписанного владельцем.
    ChannelAdmin {
        /// Ссылка-доступ к каналу (`gasapp://channel/…`).
        link: String,
        /// Секретный ключ подписи администратора (Ed25519).
        signing_key: [u8; 32],
    },

    /// Фото профиля отправителя — тем, с кем он переписывается.
    ///
    /// 🔐 Внутри сквозного шифрования: сервер фото не видит и не знает,
    /// что оно сменилось. Пустая картинка — фото снято. Версия — время
    /// смены: старое письмо не вернёт снятое или прежнее фото.
    ProfilePhoto {
        /// JPEG, не больше [`MAX_PROFILE_PHOTO_BYTES`]; пусто — снято.
        image: Vec<u8>,
        /// Время смены, миллисекунды.
        version: u64,
    },

    /// Квитанция доставки: сообщения отправителя квитанции в этом чате до
    /// названного включительно дошли до телефона получателя (две галочки).
    ///
    /// В отличие от квитанции прочтения не говорит, что их видели, — только
    /// что телефон их принял. Не уходит в непринятый запрос на переписку.
    DeliveryReceipt {
        /// Последнее доставленное сообщение.
        until: [u8; MESSAGE_ID_LEN],
    },

    /// Таймер исчезающих сообщений, заданный отправителем для чата.
    ///
    /// 🔐 Таймер общий для обоих: кто бы его ни поставил, сообщения
    /// исчезают у обоих собеседников. Прежде таймер жил только на том
    /// телефоне, где его включили, и собеседник хранил «исчезающую»
    /// переписку вечно. Как и «удалить у всех», это договорённость,
    /// а не гарантия: собеседник мог снять экран до исчезновения.
    ///
    /// Внутри шифрования: сервер не знает, что таймер сменился.
    DisappearingTimer {
        /// Срок жизни сообщения в секундах; `None` — выключено.
        seconds: Option<u32>,
    },

    /// Вершина журнала ключей, которую видит отправитель (§9.7).
    ///
    /// 🔐 Сверка цепочек между собеседниками. Сервер, показавший кому-то
    /// свою ветку журнала (например, новой установке — её первую
    /// вершину клиент принимает на веру), разойдётся с любым честным
    /// собеседником этого человека: вершина одной и той же эпохи у них
    /// будет разной. Вершина публична — секрета здесь нет.
    KtHead {
        /// Номер эпохи.
        epoch: u64,
        /// Вершина цепочки в этой эпохе.
        head: [u8; KT_HEAD_LEN],
    },
}

impl Content {
    /// Сериализует содержимое для отправки, дополняя его до бакета.
    ///
    /// # 🔐 Почему padding здесь, а не отдельным вызовом
    ///
    /// Раздел 15.3 требует, чтобы **все** шифротексты имели размер
    /// из списка бакетов. Отдельная функция `pad`, которую нужно
    /// не забыть вызвать, однажды была бы забыта — и забытой
    /// оказалась бы ровно та ветка кода, которую реже всего трогают.
    /// Поэтому padding встроен в сериализацию: получить содержимое
    /// без него нельзя, не написав это явно ([`Content::to_unpadded_bytes`]).
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — поле выходит за допустимые границы
    /// либо содержимое не помещается в наибольший бакет.
    /// Отказ на своей стороне лучше отправки сообщения, которое
    /// получатель обязан отвергнуть.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        crate::padding::pad(&self.to_unpadded_bytes()?)
    }

    /// Сериализует содержимое **без** padding.
    ///
    /// ⚠️ Результат отличим по длине и в сеть уходить не должен.
    /// Метод существует для тестов формата и для случаев, когда
    /// содержимое кладётся внутрь другой структуры, которую
    /// дополняют целиком.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — поле выходит за допустимые границы.
    pub fn to_unpadded_bytes(&self) -> Result<Vec<u8>> {
        let mut out = vec![CONTENT_VERSION];

        match self {
            Self::Text { body, reply_to, id } => {
                out.push(KIND_TEXT);
                write_text(&mut out, body)?;
                write_optional_id(&mut out, reply_to.as_ref());
                // Идентификатор — последним: содержимое без него (так
                // писали прежние версии) обрывается ровно на нём
                // и отвергается, а не читается со сдвигом.
                out.extend_from_slice(id);
            }
            Self::Attachments {
                body,
                descriptors,
                reply_to,
                id,
            } => {
                if descriptors.len() > MAX_ATTACHMENTS {
                    return Err(GasAppError::Malformed);
                }

                out.push(KIND_ATTACHMENTS);
                write_text(&mut out, body)?;
                write_optional_id(&mut out, reply_to.as_ref());

                out.push(u8::try_from(descriptors.len()).map_err(|_| GasAppError::Malformed)?);

                for descriptor in descriptors {
                    write_bytes(&mut out, descriptor)?;
                }

                out.extend_from_slice(id);
            }
            Self::Reaction { target, emoji } => {
                if emoji.len() > MAX_REACTION_BYTES {
                    return Err(GasAppError::Malformed);
                }

                out.push(KIND_REACTION);
                out.extend_from_slice(target);
                write_bytes(&mut out, emoji.as_bytes())?;
            }
            Self::Edit { target, body } => {
                out.push(KIND_EDIT);
                out.extend_from_slice(target);
                write_text(&mut out, body)?;
            }
            Self::Delete { target } => {
                out.push(KIND_DELETE);
                out.extend_from_slice(target);
            }
            Self::Typing { active } => {
                out.push(KIND_TYPING);
                out.push(u8::from(*active));
            }
            Self::ReadReceipt { until } => {
                out.push(KIND_READ_RECEIPT);
                out.extend_from_slice(until);
            }
            Self::AccessKey {
                key,
                sender_username,
                device_list,
            } => {
                write_access_key(
                    &mut out,
                    key,
                    sender_username.as_deref(),
                    device_list.as_deref(),
                )?;
            }
            Self::Keyboard { target, keyboard } => write_targeted(
                &mut out,
                KIND_KEYBOARD,
                target,
                keyboard,
                crate::keyboard::MAX_KEYBOARD_BYTES,
            )?,
            Self::Callback { target, data } => write_targeted(
                &mut out,
                KIND_CALLBACK,
                target,
                data,
                crate::keyboard::MAX_DATA_BYTES,
            )?,
            Self::DisappearingTimer { seconds } => write_disappearing_timer(&mut out, *seconds)?,
            // Служебное — отдельно (`write_service`).
            _ => self.write_service(&mut out)?,
        }

        Ok(out)
    }

    /// Служебное содержимое: копии своим устройствам, история, блокировка,
    /// назначение администратором, фото профиля, квитанция доставки,
    /// вершина журнала ключей.
    fn write_service(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Sent {
                peer,
                peer_username,
                content,
            } => write_sent(out, peer, peer_username.as_deref(), content)?,
            Self::History { items } => write_history(out, items)?,
            Self::Block { blocked } => {
                out.push(KIND_BLOCK);
                out.push(u8::from(*blocked));
            }
            Self::ChannelAdmin { link, signing_key } => {
                write_channel_admin(out, link, signing_key)?;
            }
            Self::ProfilePhoto { image, version } => {
                write_profile_photo(out, image, *version)?;
            }
            Self::DeliveryReceipt { until } => {
                out.push(KIND_DELIVERY_RECEIPT);
                out.extend_from_slice(until);
            }
            Self::KtHead { epoch, head } => {
                out.push(KIND_KT_HEAD);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(head);
            }
            // Остальное пишет `to_unpadded_bytes`; сюда оно не попадает.
            _ => return Err(GasAppError::Malformed),
        }
        Ok(())
    }

    /// Разбирает содержимое, пришедшее от собеседника.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — неизвестная версия или тип, обрыв
    /// данных, превышение предела. Все случаи дают одну ошибку:
    /// подробный разбор причины подсказывал бы, как собрать
    /// сообщение, которое пройдёт.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_unpadded_bytes(crate::padding::unpad(bytes)?)
    }

    /// Разбирает содержимое, с которого padding уже снят.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — неизвестная версия или тип, обрыв
    /// данных, превышение предела.
    pub fn from_unpadded_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);

        if reader.take_u8()? != CONTENT_VERSION {
            return Err(GasAppError::Malformed);
        }

        let content = match reader.take_u8()? {
            KIND_TEXT => Self::Text {
                body: reader.take_text()?,
                reply_to: reader.take_optional_id()?,
                id: reader.take_id()?,
            },
            KIND_ATTACHMENTS => {
                let body = reader.take_text()?;
                let reply_to = reader.take_optional_id()?;
                let count = reader.take_u8()? as usize;

                if count > MAX_ATTACHMENTS {
                    return Err(GasAppError::Malformed);
                }

                let mut descriptors = Vec::with_capacity(count);
                for _ in 0..count {
                    descriptors.push(reader.take_blob()?);
                }

                Self::Attachments {
                    body,
                    descriptors,
                    reply_to,
                    id: reader.take_id()?,
                }
            }
            KIND_REACTION => {
                let target = reader.take_id()?;
                let emoji = reader.take_blob()?;

                if emoji.len() > MAX_REACTION_BYTES {
                    return Err(GasAppError::Malformed);
                }

                Self::Reaction {
                    target,
                    emoji: String::from_utf8(emoji).map_err(|_| GasAppError::Malformed)?,
                }
            }
            KIND_EDIT => Self::Edit {
                target: reader.take_id()?,
                body: reader.take_text()?,
            },
            KIND_DELETE => Self::Delete {
                target: reader.take_id()?,
            },
            KIND_TYPING => Self::Typing {
                active: match reader.take_u8()? {
                    0 => false,
                    1 => true,
                    // Иное значение означает чужую реализацию:
                    // булев флаг имеет ровно два состояния.
                    _ => return Err(GasAppError::Malformed),
                },
            },
            KIND_READ_RECEIPT => Self::ReadReceipt {
                until: reader.take_id()?,
            },
            KIND_ACCESS_KEY => read_access_key(&mut reader)?,
            KIND_SENT => read_sent(&mut reader)?,
            KIND_HISTORY => read_history(&mut reader)?,
            KIND_BLOCK => Self::Block {
                blocked: match reader.take_u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(GasAppError::Malformed),
                },
            },
            KIND_CHANNEL_ADMIN => read_channel_admin(&mut reader)?,
            KIND_PROFILE_PHOTO => read_profile_photo(&mut reader)?,
            KIND_DELIVERY_RECEIPT => Self::DeliveryReceipt {
                until: reader.take_id()?,
            },
            KIND_KT_HEAD => {
                let (epoch, head) = take_kt_head(&mut reader)?;
                Self::KtHead { epoch, head }
            }
            KIND_KEYBOARD => {
                let target = reader.take_id()?;
                let keyboard = reader.take_blob()?;

                if keyboard.len() > crate::keyboard::MAX_KEYBOARD_BYTES {
                    return Err(GasAppError::Malformed);
                }

                Self::Keyboard { target, keyboard }
            }
            KIND_CALLBACK => {
                let target = reader.take_id()?;
                let data = reader.take_blob()?;

                if data.len() > crate::keyboard::MAX_DATA_BYTES {
                    return Err(GasAppError::Malformed);
                }

                Self::Callback { target, data }
            }
            KIND_DISAPPEARING_TIMER => Self::DisappearingTimer {
                seconds: take_disappearing_seconds(&mut reader)?,
            },
            _ => return Err(GasAppError::Malformed),
        };

        // Хвост означает, что сообщение собрано не нашим кодом.
        reader.expect_end()?;

        Ok(content)
    }
}

/// Таймер исчезающих: срок в секундах, ноль — «выключено» (отдельный
/// флаг был бы лишним состоянием, которое можно рассогласовать).
fn write_disappearing_timer(out: &mut Vec<u8>, seconds: Option<u32>) -> Result<()> {
    let value = seconds.unwrap_or(0);
    if value > MAX_DISAPPEARING_SECONDS || seconds == Some(0) {
        return Err(GasAppError::Malformed);
    }
    out.push(KIND_DISAPPEARING_TIMER);
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Записывает текст с проверкой предела.
fn write_text(out: &mut Vec<u8>, text: &str) -> Result<()> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(GasAppError::Malformed);
    }

    write_bytes(out, text.as_bytes())
}

/// Назначение администратором канала ([`Content::ChannelAdmin`]).
fn write_channel_admin(out: &mut Vec<u8>, link: &str, signing_key: &[u8; 32]) -> Result<()> {
    if link.len() > MAX_CHANNEL_LINK_BYTES {
        return Err(GasAppError::Malformed);
    }
    out.push(KIND_CHANNEL_ADMIN);
    write_bytes(out, link.as_bytes())?;
    out.extend_from_slice(signing_key);
    Ok(())
}

/// Блок данных к сообщению (клавиатура бота, нажатие кнопки).
fn write_targeted(
    out: &mut Vec<u8>,
    kind: u8,
    target: &[u8; MESSAGE_ID_LEN],
    data: &[u8],
    limit: usize,
) -> Result<()> {
    if data.len() > limit {
        return Err(GasAppError::Malformed);
    }
    out.push(kind);
    out.extend_from_slice(target);
    write_bytes(out, data)
}

fn write_profile_photo(out: &mut Vec<u8>, image: &[u8], version: u64) -> Result<()> {
    if image.len() > MAX_PROFILE_PHOTO_BYTES {
        return Err(GasAppError::Malformed);
    }
    out.push(KIND_PROFILE_PHOTO);
    out.extend_from_slice(&version.to_be_bytes());
    write_bytes(out, image)
}

fn read_profile_photo(reader: &mut Reader<'_>) -> Result<Content> {
    let version = u64::from_be_bytes(
        reader
            .take_slice(8)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)?,
    );
    let image = reader.take_blob()?;
    if image.len() > MAX_PROFILE_PHOTO_BYTES {
        return Err(GasAppError::Malformed);
    }
    Ok(Content::ProfilePhoto { image, version })
}

fn read_channel_admin(reader: &mut Reader<'_>) -> Result<Content> {
    let link = reader.take_blob()?;
    if link.len() > MAX_CHANNEL_LINK_BYTES {
        return Err(GasAppError::Malformed);
    }
    Ok(Content::ChannelAdmin {
        link: String::from_utf8(link).map_err(|_| GasAppError::Malformed)?,
        signing_key: reader
            .take_slice(32)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)?,
    })
}

/// Записывает блок с длиной.
fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| GasAppError::Malformed)?;

    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);

    Ok(())
}

/// Записывает необязательный идентификатор.
fn write_optional_id(out: &mut Vec<u8>, id: Option<&[u8; MESSAGE_ID_LEN]>) {
    match id {
        Some(value) => {
            // Признак наличия отдельным байтом: нулевой идентификатор
            // как «отсутствует» не годится, потому что он допустим.
            out.push(1);
            out.extend_from_slice(value);
        }
        None => out.push(0),
    }
}

/// Курсор с проверкой границ на каждом шаге.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Прочитано ли всё.
    const fn at_end(&self) -> bool {
        self.offset >= self.bytes.len()
    }

    fn take_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(len).ok_or(GasAppError::Malformed)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(GasAppError::Malformed)?;

        self.offset = end;

        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8> {
        self.take_slice(1)?
            .first()
            .copied()
            .ok_or(GasAppError::Malformed)
    }

    fn take_u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self
            .take_slice(4)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)?;

        Ok(u32::from_be_bytes(bytes))
    }

    fn take_blob(&mut self) -> Result<Vec<u8>> {
        let length = self.take_u32()? as usize;

        // Длина сверяется с остатком до выделения памяти: объявленный
        // размер в четыре гигабайта не должен приводить к попытке
        // зарезервировать их.
        let remaining = self
            .bytes
            .len()
            .checked_sub(self.offset)
            .ok_or(GasAppError::Malformed)?;

        if length > remaining {
            return Err(GasAppError::Malformed);
        }

        Ok(self.take_slice(length)?.to_vec())
    }

    fn take_text(&mut self) -> Result<String> {
        let bytes = self.take_blob()?;

        if bytes.len() > MAX_TEXT_BYTES {
            return Err(GasAppError::Malformed);
        }

        String::from_utf8(bytes).map_err(|_| GasAppError::Malformed)
    }

    fn take_id(&mut self) -> Result<[u8; MESSAGE_ID_LEN]> {
        self.take_slice(MESSAGE_ID_LEN)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)
    }

    /// Читает ключ доступа sealed sender.
    fn take_access_key(&mut self) -> Result<[u8; ACCESS_KEY_LEN]> {
        self.take_slice(ACCESS_KEY_LEN)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)
    }

    fn take_optional_id(&mut self) -> Result<Option<[u8; MESSAGE_ID_LEN]>> {
        match self.take_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.take_id()?)),
            _ => Err(GasAppError::Malformed),
        }
    }

    fn expect_end(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(GasAppError::Malformed)
        }
    }
}

/// Эпоха и вершина журнала ключей ([`Content::KtHead`]).
fn take_kt_head(reader: &mut Reader<'_>) -> Result<(u64, [u8; KT_HEAD_LEN])> {
    let epoch = u64::from_be_bytes(
        reader
            .take_slice(8)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)?,
    );
    let head = reader
        .take_slice(KT_HEAD_LEN)?
        .try_into()
        .map_err(|_| GasAppError::Malformed)?;

    Ok((epoch, head))
}

/// Срок таймера исчезающих сообщений: ноль — «выключено», больше года —
/// отказ (значение от собеседника, см. [`MAX_DISAPPEARING_SECONDS`]).
fn take_disappearing_seconds(reader: &mut Reader<'_>) -> Result<Option<u32>> {
    let value = u32::from_be_bytes(
        reader
            .take_slice(4)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)?,
    );

    if value > MAX_DISAPPEARING_SECONDS {
        return Err(GasAppError::Malformed);
    }

    Ok((value != 0).then_some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Вершина журнала переживает кодирование; обрезанная — отвергается.
    #[test]
    fn a_key_log_head_round_trips() {
        let content = Content::KtHead {
            epoch: 488_888,
            head: [0x5C; KT_HEAD_LEN],
        };
        let bytes = content.to_bytes().expect("кодирование");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);

        let unpadded = content.to_unpadded_bytes().expect("без дополнения");
        for cut in 1..unpadded.len() {
            assert!(
                Content::from_unpadded_bytes(unpadded.get(..cut).expect("срез")).is_err(),
                "обрезка {cut}"
            );
        }
    }

    /// Имя отправителя переживает кодирование, а его отсутствие —
    /// формат прежних версий — читается как «имени нет».
    #[test]
    fn access_key_carries_the_sender_username() {
        let with_name = Content::AccessKey {
            key: [7; ACCESS_KEY_LEN],
            sender_username: Some("алиса".to_owned()),
            device_list: None,
        };
        let bytes = with_name.to_bytes().expect("кодируется");
        assert_eq!(Content::from_bytes(&bytes).expect("читается"), with_name);

        let old_format = Content::AccessKey {
            key: [7; ACCESS_KEY_LEN],
            sender_username: None,
            device_list: None,
        };
        // Без дополнения: длина без имени — версия, тип и сам ключ,
        // ровно как у прежних версий.
        let bytes = old_format.to_unpadded_bytes().expect("кодируется");
        assert_eq!(
            bytes.len(),
            2 + ACCESS_KEY_LEN,
            "без имени формат обязан остаться прежним"
        );
        assert_eq!(
            Content::from_unpadded_bytes(&bytes).expect("читается"),
            old_format
        );
    }

    /// Таймер переживает кодирование; ноль — «выключено»; срок больше
    /// года и обрезанное сообщение отвергаются.
    #[test]
    fn a_disappearing_timer_round_trips() {
        for seconds in [None, Some(1), Some(3_600), Some(MAX_DISAPPEARING_SECONDS)] {
            let content = Content::DisappearingTimer { seconds };
            let bytes = content.to_bytes().expect("кодирование");
            assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
        }

        assert!(Content::DisappearingTimer { seconds: Some(0) }
            .to_bytes()
            .is_err());
        assert!(Content::DisappearingTimer {
            seconds: Some(MAX_DISAPPEARING_SECONDS + 1)
        }
        .to_bytes()
        .is_err());

        let mut too_long = vec![CONTENT_VERSION, KIND_DISAPPEARING_TIMER];
        too_long.extend_from_slice(&(MAX_DISAPPEARING_SECONDS + 1).to_be_bytes());
        assert!(Content::from_unpadded_bytes(&too_long).is_err());

        let unpadded = Content::DisappearingTimer { seconds: Some(60) }
            .to_unpadded_bytes()
            .expect("без дополнения");
        for cut in 1..unpadded.len() {
            assert!(
                Content::from_unpadded_bytes(unpadded.get(..cut).expect("срез")).is_err(),
                "обрезка {cut}"
            );
        }
    }

    fn id(value: u8) -> [u8; MESSAGE_ID_LEN] {
        [value; MESSAGE_ID_LEN]
    }

    #[test]
    fn text_round_trips() {
        let content = Content::Text {
            body: "привет".to_owned(),
            reply_to: None,
            id: id(0x2a),
        };

        let bytes = content.to_bytes().expect("сериализация");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
    }

    /// 🔐 Идентификатор, выбранный отправителем, доезжает до получателя,
    /// а текст без него — формат прежних версий — отвергается, а не
    /// читается с идентификатором, собранным из соседних байтов.
    #[test]
    fn text_carries_the_sender_id_and_is_rejected_without_it() {
        let full = Content::Text {
            body: "привет".to_owned(),
            reply_to: None,
            id: id(0x2a),
        }
        .to_unpadded_bytes()
        .expect("сериализация");

        match Content::from_unpadded_bytes(&full).expect("разбор") {
            Content::Text { id: received, .. } => assert_eq!(received, id(0x2a)),
            other => panic!("не текст: {other:?}"),
        }

        let without_id = full.get(..full.len() - MESSAGE_ID_LEN).expect("длина");
        assert!(Content::from_unpadded_bytes(without_id).is_err());
    }

    #[test]
    fn reply_round_trips() {
        let content = Content::Text {
            body: "ответ".to_owned(),
            reply_to: Some(id(7)),
            id: id(0x2a),
        };

        let bytes = content.to_bytes().expect("сериализация");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
    }

    #[test]
    fn attachments_round_trip() {
        let content = Content::Attachments {
            body: "смотри".to_owned(),
            descriptors: vec![vec![1, 2, 3], vec![4, 5]],
            reply_to: Some(id(9)),
            id: id(0x2a),
        };

        let bytes = content.to_bytes().expect("сериализация");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
    }

    #[test]
    fn reaction_round_trips() {
        let content = Content::Reaction {
            target: id(3),
            emoji: "👍".to_owned(),
        };

        let bytes = content.to_bytes().expect("сериализация");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
    }

    /// Пустая реакция снимает предыдущую.
    #[test]
    fn empty_reaction_removes() {
        let content = Content::Reaction {
            target: id(3),
            emoji: String::new(),
        };

        let bytes = content.to_bytes().expect("сериализация");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
    }

    #[test]
    fn edit_and_delete_round_trip() {
        for content in [
            Content::Edit {
                target: id(1),
                body: "исправлено".to_owned(),
            },
            Content::Delete { target: id(2) },
        ] {
            let bytes = content.to_bytes().expect("сериализация");

            assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
        }
    }

    /// 🔐 Неизвестный тип отвергается, а не игнорируется.
    ///
    /// Молчаливый пропуск означал бы, что сообщение от новой версии
    /// выглядит пустым: пользователь решил бы, что собеседник прислал
    /// пустоту, хотя тот прислал, например, опрос.
    #[test]
    fn unknown_kind_is_rejected() {
        let bytes = vec![CONTENT_VERSION, 99];

        assert!(matches!(
            Content::from_bytes(&bytes),
            Err(GasAppError::Malformed)
        ));
    }

    #[test]
    fn unknown_version_is_rejected() {
        let mut bytes = Content::Delete { target: id(1) }
            .to_bytes()
            .expect("сериализация");
        bytes[0] = CONTENT_VERSION.wrapping_add(1);

        assert!(Content::from_bytes(&bytes).is_err());
    }

    /// 🔐 Обрезка на любой позиции даёт ошибку, а не панику.
    ///
    /// Обрезанное сообщение может прислать кто угодно, а паника
    /// в разборе означает отказ в обслуживании.
    #[test]
    fn truncation_at_any_offset_is_an_error() {
        let full = Content::Attachments {
            body: "текст".to_owned(),
            descriptors: vec![vec![1, 2, 3]],
            reply_to: Some(id(5)),
            id: id(0x2a),
        }
        .to_bytes()
        .expect("сериализация");

        for cut in 0..full.len() {
            let truncated = full.get(..cut).expect("срез в границах");

            assert!(
                Content::from_bytes(truncated).is_err(),
                "обрезка до {cut} байт разобралась"
            );
        }
    }

    /// Лишние байты в хвосте отвергаются самим разбором.
    ///
    /// Проверяется `from_unpadded_bytes`, а не `from_bytes`: у второго
    /// лишний байт сломал бы длину бакета, и тест проходил бы, не
    /// проверяя разбор вовсе. Хвост обязан отвергаться **до** и
    /// **после** появления padding.
    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = Content::Delete { target: id(1) }
            .to_unpadded_bytes()
            .expect("сериализация");
        bytes.push(0);

        assert!(Content::from_unpadded_bytes(&bytes).is_err());
    }

    /// 🔐 Содержимое уходит в сеть дополненным до бакета.
    ///
    /// Это то самое свойство раздела 15.3, ради которого padding
    /// встроен в сериализацию: получить недополненные байты можно
    /// только вызвав `to_unpadded_bytes` явно.
    #[test]
    fn serialized_content_is_always_bucketed() {
        let cases = [
            Content::Text {
                body: "ок".to_owned(),
                reply_to: None,
                id: id(0x2a),
            },
            Content::Delete { target: id(1) },
            Content::Typing { active: true },
            Content::Text {
                body: "а".repeat(2000),
                reply_to: Some(id(2)),
                id: id(0x2a),
            },
        ];

        for content in cases {
            let bytes = content.to_bytes().expect("сериализация");

            assert!(
                crate::padding::BUCKETS.contains(&bytes.len()),
                "размер {} не из списка бакетов",
                bytes.len()
            );
            assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
        }
    }

    /// 🔐 Короткое и длинное сообщение одного бакета неразличимы.
    #[test]
    fn short_and_long_messages_look_the_same() {
        let short = Content::Text {
            body: "ок".to_owned(),
            reply_to: None,
            id: id(0x2a),
        }
        .to_bytes()
        .expect("сериализация");

        let long = Content::Text {
            body: "я не приду, потому что ".repeat(8),
            reply_to: None,
            id: id(0x2a),
        }
        .to_bytes()
        .expect("сериализация");

        assert_eq!(
            short.len(),
            long.len(),
            "длина сообщения видна по размеру шифротекста"
        );
    }

    /// Недополненные байты в сеть не принимаются.
    ///
    /// Отправитель, не применивший padding, отличим по размеру,
    /// и принимать от него молча значит поощрять утечку.
    #[test]
    fn unpadded_bytes_are_not_accepted_by_from_bytes() {
        let bytes = Content::Delete { target: id(1) }
            .to_unpadded_bytes()
            .expect("сериализация");

        assert!(Content::from_bytes(&bytes).is_err());
    }

    /// Огромная объявленная длина отвергается без выделения памяти.
    #[test]
    fn absurd_length_is_rejected() {
        let mut bytes = vec![CONTENT_VERSION, KIND_TEXT];
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());

        assert!(Content::from_bytes(&bytes).is_err());
    }

    #[test]
    fn oversized_text_is_rejected() {
        let content = Content::Text {
            body: "a".repeat(MAX_TEXT_BYTES + 1),
            reply_to: None,
            id: id(0x2a),
        };

        assert!(content.to_bytes().is_err());
    }

    #[test]
    fn too_many_attachments_are_rejected() {
        let content = Content::Attachments {
            body: String::new(),
            descriptors: vec![vec![1]; MAX_ATTACHMENTS + 1],
            reply_to: None,
            id: id(0x2a),
        };

        assert!(content.to_bytes().is_err());
    }

    /// Некорректный UTF-8 отвергается.
    ///
    /// Иначе текст сообщения попал бы в интерфейс как последовательность
    /// байтов, и поведение отрисовки стало бы непредсказуемым.
    #[test]
    fn invalid_utf8_is_rejected() {
        let mut bytes = vec![CONTENT_VERSION, KIND_TEXT];
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&[0xFF, 0xFE]);
        bytes.push(0);

        assert!(Content::from_bytes(&bytes).is_err());
    }

    #[test]
    fn typing_round_trips() {
        for active in [true, false] {
            let content = Content::Typing { active };
            let bytes = content.to_bytes().expect("сериализация");

            assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
        }
    }

    #[test]
    fn read_receipt_round_trips() {
        let content = Content::ReadReceipt { until: id(11) };
        let bytes = content.to_bytes().expect("сериализация");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
    }

    /// Копия отправленного переживает кодирование; вложенная копия —
    /// нет.
    #[test]
    fn a_sent_copy_round_trips() {
        let inner = Content::Text {
            body: "привет".to_owned(),
            reply_to: None,
            id: [3; 16],
        };
        for name in [None, Some("bob".to_owned())] {
            let content = Content::Sent {
                peer: [8; 32],
                peer_username: name,
                content: Box::new(inner.clone()),
            };
            let bytes = content.to_bytes().expect("кодируется");
            assert_eq!(Content::from_bytes(&bytes).expect("читается"), content);
        }
        let nested = Content::Sent {
            peer: [8; 32],
            peer_username: None,
            content: Box::new(Content::Sent {
                peer: [8; 32],
                peer_username: None,
                content: Box::new(inner),
            }),
        };
        assert!(nested.to_bytes().is_err());
    }

    /// История переживает кодирование; пустая, слишком длинная и
    /// вложенная в копию — нет; чужой флаг направления отвергается.
    #[test]
    fn history_round_trips_within_limits() {
        let item = |outgoing| HistoryItem {
            peer: [5; 32],
            peer_username: Some("bob".to_owned()),
            id: [1; 16],
            outgoing,
            sent_at_millis: 1_700_000_000_000,
            body: "старое сообщение".to_owned(),
        };
        let content = Content::History {
            items: vec![
                item(true),
                HistoryItem {
                    peer_username: None,
                    ..item(false)
                },
            ],
        };
        let bytes = content.to_bytes().expect("кодируется");
        assert_eq!(Content::from_bytes(&bytes).expect("читается"), content);

        assert!(Content::History { items: Vec::new() }.to_bytes().is_err());
        assert!(Content::History {
            items: vec![item(true); MAX_HISTORY_ITEMS + 1]
        }
        .to_bytes()
        .is_err());
        assert!(Content::Sent {
            peer: [8; 32],
            peer_username: None,
            content: Box::new(content.clone()),
        }
        .to_bytes()
        .is_err());

        // Флаг направления — только 0 или 1.
        let mut raw = Content::History {
            items: vec![item(true)],
        }
        .to_unpadded_bytes()
        .expect("кодируется");
        // Версия, вид, число (2), собеседник (32), имя (1 + 4 + 3), id (16).
        let flag = 1 + 1 + 2 + 32 + 1 + 4 + 3 + 16;
        *raw.get_mut(flag).expect("флаг") = 2;
        assert!(Content::from_unpadded_bytes(&raw).is_err());
    }

    /// Блокировка внутри копии переживает кодирование.
    #[test]
    fn a_profile_photo_and_a_delivery_receipt_round_trip() {
        for content in [
            Content::ProfilePhoto {
                image: vec![0xFF, 0xD8, 1, 2],
                version: 1_760_000_000_000,
            },
            Content::ProfilePhoto {
                image: Vec::new(),
                version: 7,
            },
            Content::DeliveryReceipt { until: [5; 16] },
        ] {
            let bytes = content.to_bytes().expect("кодируется");
            assert_eq!(Content::from_bytes(&bytes).expect("читается"), content);
        }
        assert!(Content::ProfilePhoto {
            image: vec![0; MAX_PROFILE_PHOTO_BYTES + 1],
            version: 1,
        }
        .to_bytes()
        .is_err());
    }

    #[test]
    fn a_channel_admin_grant_round_trips_but_never_as_a_copy() {
        let grant = Content::ChannelAdmin {
            link: "gasapp://channel/abc".to_owned(),
            signing_key: [7; 32],
        };
        let bytes = grant.to_bytes().expect("кодируется");
        assert_eq!(Content::from_bytes(&bytes).expect("читается"), grant);

        // 🔐 Копией своим устройствам ключ администратора не едет.
        let copy = Content::Sent {
            peer: [4; 32],
            peer_username: None,
            content: Box::new(grant),
        };
        assert!(copy.to_bytes().is_err());

        let too_long = Content::ChannelAdmin {
            link: "x".repeat(MAX_CHANNEL_LINK_BYTES + 1),
            signing_key: [7; 32],
        };
        assert!(too_long.to_bytes().is_err());
    }

    #[test]
    fn a_block_copy_round_trips() {
        for blocked in [true, false] {
            let content = Content::Sent {
                peer: [4; 32],
                peer_username: Some("eve".to_owned()),
                content: Box::new(Content::Block { blocked }),
            };
            let bytes = content.to_bytes().expect("кодируется");
            assert_eq!(Content::from_bytes(&bytes).expect("читается"), content);
        }
    }

    /// Список устройств едет в хвосте ключа доступа — с именем и без.
    #[test]
    fn access_key_carries_a_device_list() {
        for name in [None, Some("anna".to_owned())] {
            let content = Content::AccessKey {
                key: [9; ACCESS_KEY_LEN],
                sender_username: name,
                device_list: Some(vec![4; 300]),
            };
            let bytes = content.to_bytes().expect("кодируется");
            assert_eq!(Content::from_bytes(&bytes).expect("читается"), content);
        }
        let too_big = Content::AccessKey {
            key: [9; ACCESS_KEY_LEN],
            sender_username: None,
            device_list: Some(vec![4; MAX_DEVICE_LIST_BYTES + 1]),
        };
        assert!(too_big.to_bytes().is_err());
    }

    /// Ключ доступа sealed sender переживает сериализацию.
    #[test]
    fn access_key_round_trips() {
        let content = Content::AccessKey {
            key: [0x5Au8; ACCESS_KEY_LEN],
            sender_username: None,
            device_list: None,
        };
        let bytes = content.to_bytes().expect("сериализация");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
    }

    /// 🔐 Ключ доступа не виден в сериализованном виде без шифрования?
    ///
    /// Нет — и это правильно: содержимое здесь **не зашифровано**,
    /// шифрует его ратчет уровнем выше. Тест фиксирует именно это
    /// ожидание, чтобы никто не принял `to_bytes` за защиту.
    ///
    /// Проверяется другое: ключ уходит целиком и не обрезается.
    #[test]
    fn access_key_is_carried_whole() {
        let key = [0x33u8; ACCESS_KEY_LEN];
        let bytes = Content::AccessKey {
            key,
            sender_username: None,
            device_list: None,
        }
        .to_unpadded_bytes()
        .expect("сериализация");

        assert!(
            bytes.windows(ACCESS_KEY_LEN).any(|window| window == key),
            "ключ доступа потерялся при сериализации"
        );
    }

    /// Обрезанный ключ доступа отвергается, а не дополняется нулями.
    #[test]
    fn truncated_access_key_is_rejected() {
        let mut bytes = Content::AccessKey {
            key: [0x11u8; ACCESS_KEY_LEN],
            sender_username: None,
            device_list: None,
        }
        .to_unpadded_bytes()
        .expect("сериализация");

        bytes.truncate(bytes.len().saturating_sub(1));

        assert!(Content::from_unpadded_bytes(&bytes).is_err());
    }

    /// Булев флаг имеет ровно два состояния.
    ///
    /// Иное значение означает чужую реализацию, и принимать его
    /// как «истину» значило бы молча согласиться с чужим форматом.
    #[test]
    fn invalid_typing_flag_is_rejected() {
        let bytes = vec![CONTENT_VERSION, KIND_TYPING, 2];

        assert!(matches!(
            Content::from_bytes(&bytes),
            Err(GasAppError::Malformed)
        ));
    }
}
