// SPDX-License-Identifier: AGPL-3.0-only

//! Content-free push-уведомления.
//!
//! # Инвариант
//!
//! 🔐 Полезная нагрузка push **никогда** не содержит текста сообщения,
//! имени отправителя, идентификатора чата или аватара. Только флаг
//! «есть новое» (ADR-014).
//!
//! Причина: push проходит через Apple или Google. Всё, что попадёт
//! в нагрузку, они увидят и сохранят — а мессенджер, который отдаёт
//! посреднику имя собеседника, перестаёт быть тем, за что его выбрали.
//! Содержимое клиент забирает сам и расшифровывает локально.
//!
//! # Чего этот модуль не делает
//!
//! Не решает, показывать ли уведомление и что в нём написать: это
//! дело клиента. Сервер лишь будит приложение.
//!
//! # Про отсутствие сетевых вызовов
//!
//! Отправка объявлена трейтом [`PushProvider`], а не реализована
//! напрямую. Так сервер собирается и тестируется без ключей Apple
//! и Google, а замена провайдера — например, на `UnifiedPush` — не
//! требует правок в маршрутах.

use uuid::Uuid;

/// Отправитель push-уведомлений.
///
/// Реализации живут за границей крейта: боевая ходит в APNs и FCM,
/// тестовая пишет в память. Трейт нужен, чтобы маршруты не зависели
/// ни от той, ни от другой.
pub trait PushProvider: Send + Sync {
    /// Будит устройство.
    ///
    /// # Что уходит провайдеру
    ///
    /// Токен и пустая нагрузка. Ничего больше передавать нельзя —
    /// см. инвариант модуля.
    ///
    /// # Про игнорирование ошибок
    ///
    /// Возвращает `bool`, а не `Result`: отправителю сообщения
    /// безразлично, разбудили получателя или нет. Конверт уже в
    /// очереди, и клиент заберёт его при следующем запросе; провал
    /// push означает лишь задержку, а не потерю.
    ///
    /// `false` означает, что токен недействителен и его следует
    /// удалить.
    fn wake(&self, provider: &str, token: &str) -> bool;
}

/// Провайдер, который ничего не делает.
///
/// Используется по умолчанию: сервер обязан работать без ключей Apple
/// и Google, потому что foss-сборка клиента обходится WebSocket, а
/// разворачивать инстанс для друзей никто не должен заставлять через
/// регистрацию в Firebase.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoPush;

impl PushProvider for NoPush {
    fn wake(&self, _provider: &str, _token: &str) -> bool {
        // `true`, а не `false`: токен не признаётся недействительным.
        // Возврат `false` заставил бы вызывающую сторону удалить
        // рабочий токен только потому, что push не настроен.
        true
    }
}

/// Будит устройство, если у него есть токен.
///
/// Ошибки чтения базы и отказы провайдера подавляются намеренно:
/// см. пояснение у [`PushProvider::wake`]. Недействительный токен
/// удаляется, чтобы не хранить связь устройства с посредником,
/// не дающую ничего взамен.
pub async fn wake_device(pool: &sqlx::PgPool, provider: &dyn PushProvider, device_id: Uuid) {
    let Ok(Some(token)) = gasapp_server_db::repo::find_push_token(pool, device_id).await else {
        // Токена нет — устройство обходится WebSocket. Это штатный
        // случай для foss-сборки, а не ошибка.
        return;
    };

    if !provider.wake(&token.provider, &token.token) {
        let _ = gasapp_server_db::repo::delete_push_token(pool, device_id).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Провайдер, запоминающий вызовы.
    #[derive(Default)]
    struct RecordingProvider {
        calls: Mutex<Vec<(String, String)>>,
        result: bool,
    }

    impl PushProvider for RecordingProvider {
        fn wake(&self, provider: &str, token: &str) -> bool {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push((provider.to_owned(), token.to_owned()));
            }

            self.result
        }
    }

    /// 🔐 Провайдер получает только токен — ничего о сообщении.
    ///
    /// Проверка формы, а не поведения: сигнатура `wake` физически
    /// не позволяет передать текст или отправителя. Тест закрепляет
    /// это, чтобы будущая правка не расширила её «для удобства».
    #[test]
    fn provider_receives_only_token() {
        let provider = RecordingProvider {
            result: true,
            ..Default::default()
        };

        provider.wake("fcm", "token-123");

        let calls = provider.calls.lock().expect("мьютекс");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], ("fcm".to_owned(), "token-123".to_owned()));
    }

    /// Провайдер по умолчанию не признаёт токен недействительным.
    ///
    /// Иначе сервер без ключей Apple и Google удалял бы рабочие токены
    /// при каждой отправке.
    #[test]
    fn no_push_keeps_tokens() {
        assert!(NoPush.wake("fcm", "token"));
    }
}
