// SPDX-License-Identifier: Apache-2.0

//! Метаданные группы под сквозным шифрованием.
//!
//! # Почему название группы — это тайна
//!
//! Сервер, знающий состав и названия групп, знает социальный граф
//! целиком: кто с кем связан, вокруг чего объединяется, когда
//! появляются новые группы. Это ценнее содержимого отдельных
//! сообщений — по нему строят карту сообщества, не читая ни строки.
//!
//! Поэтому название, аватар и список участников передаются **внутри**
//! сообщений группы, как обычное содержимое. Сервер видит только
//! шифротексты и то, между какими устройствами они ходят.
//!
//! # Что сервер всё-таки видит
//!
//! Что эти устройства обмениваются сообщениями. Полностью скрыть это
//! нельзя без анонимной сети; ADR-024 выносит поддержку Tor
//! в отдельное решение.
//!
//! # Про порядок изменений
//!
//! У изменений состава есть номер версии. Без него два участника,
//! одновременно изменившие состав, привели бы к расхождению: у одного
//! Боб добавлен, у другого удалён, и оба считают себя правыми.
//! Номер задаёт порядок, а совпадение номеров разрешается по
//! идентификатору автора — произвольно, но одинаково у всех.

use aegis_types::{AegisError, PublicKeyBytes, Result};

/// Предел длины названия группы.
///
/// 🔐 Название приходит от участника и попадает в интерфейс всех
/// остальных. Без предела название на мегабайт растянуло бы разметку
/// у каждого.
pub const MAX_GROUP_NAME_LEN: usize = 128;

/// Предел числа участников.
///
/// ADR-023: до 256. Дальше Sender Keys перестают быть выгодными —
/// раздача ключа при ротации становится дороже, чем экономия
/// на отправке.
pub const MAX_MEMBERS: usize = 256;

/// Изменение в группе.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupChange {
    /// Переименование.
    Rename {
        /// Новое название.
        name: String,
    },

    /// Добавление участника.
    ///
    /// 🔐 Требует ротации Sender Key: добавленный не должен читать
    /// то, что писалось до его появления.
    AddMember {
        /// Identity-ключ участника.
        identity: PublicKeyBytes,
    },

    /// Удаление участника.
    ///
    /// 🔐 Требует ротации: иначе ушедший продолжит читать переписку,
    /// в которой больше не состоит.
    RemoveMember {
        /// Identity-ключ участника.
        identity: PublicKeyBytes,
    },

    /// Явная ротация ключей по команде пользователя.
    ///
    /// Шестой триггер ADR-023: кнопка «Обновить ключи группы».
    /// Нужна, когда участник подозревает компрометацию, но не может
    /// указать, чью именно.
    RotateKeys,
}

impl GroupChange {
    /// Требует ли изменение ротации Sender Key.
    ///
    /// 🔐 Четыре из шести триггеров ADR-023 проходят здесь. Два
    /// оставшихся — по числу сообщений и по времени — живут
    /// в [`crate::sender_key::SenderKeyState::needs_rotation`].
    ///
    /// Переименование ротации не требует: оно не меняет того, кто
    /// имеет доступ.
    #[must_use]
    pub const fn requires_rotation(&self) -> bool {
        match self {
            Self::AddMember { .. } | Self::RemoveMember { .. } | Self::RotateKeys => true,
            Self::Rename { .. } => false,
        }
    }
}

/// Состояние группы у участника.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupState {
    /// Название.
    pub name: String,

    /// Участники по identity-ключам.
    ///
    /// Ключи, а не имена: имя пользователь меняет, ключ — нет.
    /// Состав, привязанный к именам, разъехался бы при первом
    /// переименовании.
    pub members: Vec<PublicKeyBytes>,

    /// Номер версии состояния.
    ///
    /// Растёт при каждом изменении и задаёт их порядок.
    pub version: u64,
}

impl GroupState {
    /// Создаёт новую группу.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — название или состав вне пределов.
    pub fn new(name: String, members: Vec<PublicKeyBytes>) -> Result<Self> {
        let state = Self {
            name,
            members,
            version: 0,
        };

        state.validate()?;

        Ok(state)
    }

    /// Применяет изменение.
    ///
    /// # Про идемпотентность
    ///
    /// Добавление уже состоящего участника и удаление отсутствующего
    /// не считаются ошибкой: изменения приходят по сети и могут
    /// продублироваться, а отказ означал бы, что состояние
    /// расходится у участников из-за повтора пакета.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — результат вне пределов: слишком
    /// длинное название или превышено число участников.
    pub fn apply(&mut self, change: &GroupChange) -> Result<()> {
        match change {
            GroupChange::Rename { name } => {
                if name.chars().count() > MAX_GROUP_NAME_LEN {
                    return Err(AegisError::Malformed);
                }

                self.name.clone_from(name);
            }

            GroupChange::AddMember { identity } => {
                if self.members.contains(identity) {
                    // Повтор: состояние уже такое, каким его хотят
                    // видеть. Увеличивать версию всё равно нужно —
                    // иначе отправитель решит, что изменение потерялось.
                } else {
                    if self.members.len() >= MAX_MEMBERS {
                        return Err(AegisError::Malformed);
                    }

                    self.members.push(*identity);
                }
            }

            GroupChange::RemoveMember { identity } => {
                self.members.retain(|member| member != identity);
            }

            GroupChange::RotateKeys => {
                // Состав и название не меняются: ротация касается
                // только ключей, которыми управляет вызывающая сторона.
            }
        }

        self.version = self.version.saturating_add(1);

        Ok(())
    }

    /// Проверяет состояние, полученное от другого участника.
    ///
    /// 🔐 Состояние приходит по сети от участника группы. Он
    /// расшифровался — значит состоит в группе, но это не делает его
    /// добросовестным: он может прислать состав из миллиона записей
    /// или название на мегабайт.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — какое-либо поле вне пределов.
    pub fn validate(&self) -> Result<()> {
        if self.name.chars().count() > MAX_GROUP_NAME_LEN {
            return Err(AegisError::Malformed);
        }

        if self.members.len() > MAX_MEMBERS {
            return Err(AegisError::Malformed);
        }

        // Дубликаты в составе означают, что состояние собрано
        // не нашим кодом: они привели бы к повторной раздаче ключа
        // одному и тому же участнику.
        let mut seen = self.members.clone();
        seen.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        seen.dedup_by(|a, b| a.as_bytes() == b.as_bytes());

        if seen.len() != self.members.len() {
            return Err(AegisError::Malformed);
        }

        Ok(())
    }

    /// Нужно ли использовать Sender Keys для текущего состава.
    #[must_use]
    pub fn uses_sender_keys(&self) -> bool {
        crate::sender_key::use_sender_keys(self.members.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(value: u8) -> PublicKeyBytes {
        PublicKeyBytes::new([value; 32])
    }

    fn group() -> GroupState {
        GroupState::new("Команда".to_owned(), vec![member(1), member(2)])
            .expect("группа создана")
    }

    #[test]
    fn rename_applies() {
        let mut state = group();

        state
            .apply(&GroupChange::Rename {
                name: "Проект".to_owned(),
            })
            .expect("переименование");

        assert_eq!(state.name, "Проект");
        assert_eq!(state.version, 1);
    }

    #[test]
    fn member_can_be_added_and_removed() {
        let mut state = group();

        state
            .apply(&GroupChange::AddMember {
                identity: member(3),
            })
            .expect("добавление");
        assert!(state.members.contains(&member(3)));

        state
            .apply(&GroupChange::RemoveMember {
                identity: member(3),
            })
            .expect("удаление");
        assert!(!state.members.contains(&member(3)));
    }

    /// Повторное изменение не ломает состояние.
    ///
    /// Изменения приходят по сети и могут продублироваться: отказ
    /// означал бы расхождение состояния у участников из-за повтора.
    #[test]
    fn repeated_changes_are_idempotent() {
        let mut state = group();

        for _ in 0..3 {
            state
                .apply(&GroupChange::AddMember {
                    identity: member(3),
                })
                .expect("добавление");
        }

        assert_eq!(
            state.members.iter().filter(|m| **m == member(3)).count(),
            1,
            "участник добавлен несколько раз"
        );

        for _ in 0..3 {
            state
                .apply(&GroupChange::RemoveMember {
                    identity: member(9),
                })
                .expect("удаление отсутствующего");
        }
    }

    /// Версия растёт при каждом изменении, включая повторные.
    ///
    /// Иначе отправитель решил бы, что изменение потерялось,
    /// и отправил бы его снова.
    #[test]
    fn version_grows_on_every_change() {
        let mut state = group();

        state
            .apply(&GroupChange::AddMember {
                identity: member(3),
            })
            .expect("добавление");
        assert_eq!(state.version, 1);

        state
            .apply(&GroupChange::AddMember {
                identity: member(3),
            })
            .expect("повтор");
        assert_eq!(state.version, 2, "версия не выросла на повторе");
    }

    /// 🔐 Изменения состава требуют ротации ключей.
    ///
    /// Четыре из шести триггеров ADR-023.
    #[test]
    fn membership_changes_require_rotation() {
        assert!(GroupChange::AddMember {
            identity: member(1)
        }
        .requires_rotation());

        assert!(GroupChange::RemoveMember {
            identity: member(1)
        }
        .requires_rotation());

        assert!(GroupChange::RotateKeys.requires_rotation());

        // Переименование не меняет того, кто имеет доступ.
        assert!(!GroupChange::Rename {
            name: "Другое".to_owned()
        }
        .requires_rotation());
    }

    #[test]
    fn oversized_name_is_rejected() {
        let mut state = group();

        assert!(state
            .apply(&GroupChange::Rename {
                name: "я".repeat(MAX_GROUP_NAME_LEN + 1),
            })
            .is_err());
    }

    /// Название длиной ровно в предел принимается.
    ///
    /// Длина считается в символах: иначе кириллические названия
    /// отсекались бы вдвое короче латинских.
    #[test]
    fn cyrillic_name_at_limit_passes() {
        let mut state = group();

        assert!(state
            .apply(&GroupChange::Rename {
                name: "я".repeat(MAX_GROUP_NAME_LEN),
            })
            .is_ok());
    }

    #[test]
    fn member_limit_is_enforced() {
        let members: Vec<PublicKeyBytes> = (0..MAX_MEMBERS)
            .map(|index| {
                let mut bytes = [0u8; 32];
                bytes[0] = u8::try_from(index % 256).unwrap_or(0);
                bytes[1] = u8::try_from(index.wrapping_div(256)).unwrap_or(0);

                PublicKeyBytes::new(bytes)
            })
            .collect();

        let mut state = GroupState::new("Полная".to_owned(), members).expect("группа");

        assert!(state
            .apply(&GroupChange::AddMember {
                identity: member(255)
            })
            .is_err());
    }

    /// 🔐 Состояние с дубликатами отвергается.
    ///
    /// Оно собрано не нашим кодом и привело бы к повторной раздаче
    /// ключа одному участнику.
    #[test]
    fn duplicate_members_are_rejected() {
        assert!(GroupState::new("Дубли".to_owned(), vec![member(1), member(1)]).is_err());
    }

    /// Порог Sender Keys применяется к составу группы.
    #[test]
    fn small_group_uses_pairwise() {
        let small = GroupState::new(
            "Малая".to_owned(),
            (1..=8u8).map(member).collect(),
        )
        .expect("группа");

        assert!(!small.uses_sender_keys());

        let large = GroupState::new(
            "Большая".to_owned(),
            (1..=9u8).map(member).collect(),
        )
        .expect("группа");

        assert!(large.uses_sender_keys());
    }
}
