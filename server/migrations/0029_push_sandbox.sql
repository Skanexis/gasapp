-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Пуш-уведомления: провайдер `apns-sandbox`.
--
-- Сборка iOS, поставленная из Xcode (отладка), получает токен песочницы
-- APNs, а TestFlight и App Store — боевой. Токен одного окружения
-- в другом не действует, поэтому отправщику пушей
-- (`gasapp-server-admin push`) нужно знать, куда его слать.
--
-- `unified` (UnifiedPush) из списка не убирается: маршрут его не
-- принимает, а ограничение схемы — не место решать, будет ли он.

ALTER TABLE push_tokens DROP CONSTRAINT push_provider_known;
ALTER TABLE push_tokens ADD CONSTRAINT push_provider_known
    CHECK (provider IN ('fcm', 'apns', 'apns-sandbox', 'unified'));
