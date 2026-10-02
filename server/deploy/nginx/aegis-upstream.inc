# SPDX-License-Identifier: AGPL-3.0-only
#
# Связь балансировщика с узлами: /etc/nginx/aegis-upstream.inc.
# Подключается в каждом server{} AEGIS.

# 🔐 Узел проверяется, а не принимается любой.
#
# Прежде nginx ходил к узлам по TLS без проверки: тот, кто встал
# посреди внутренней сети хостера, предъявил бы свой сертификат и читал
# бы всё, что идёт к узлам. Теперь узел обязан предъявить сертификат
# внутреннего центра с именем aegis-node (internal-ca.sh server nodeN
# aegis-node 10.0.0.N).
proxy_ssl_verify              on;
proxy_ssl_verify_depth        2;
proxy_ssl_trusted_certificate /etc/aegis/pki/ca.pem;
proxy_ssl_name                aegis-node;
proxy_ssl_server_name         on;
# Узлы говорят только TLS 1.3 (aegis-server-api/src/tls.rs).
proxy_ssl_protocols           TLSv1.3;
proxy_ssl_session_reuse       on;

proxy_http_version 1.1;
proxy_set_header Host       $host;
proxy_set_header Upgrade    $http_upgrade;
proxy_set_header Connection $aegis_connection;

# 🔐 Адрес клиента узлу не передаётся — ни нашими заголовками, ни
# присланными самим клиентом (без этих строк nginx пропустил бы их
# как есть). Сервер адресов не хранит, и получать их ему нечего.
proxy_set_header X-Forwarded-For   "";
proxy_set_header X-Real-IP         "";
proxy_set_header Forwarded         "";
proxy_set_header X-Forwarded-Host  "";
proxy_set_header X-Forwarded-Proto "";

proxy_connect_timeout 5s;
# Неудачный узел — следующий. Только для отказов соединения и 502/503:
# запрос, который узел уже обработал (отправка, регистрация), повтор
# превратил бы в дубль, а nginx не повторяет POST сам.
proxy_next_upstream error timeout http_502 http_503;
proxy_next_upstream_tries 2;
