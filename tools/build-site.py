#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Собирает публичный сайт документов GasApp из Markdown.

    python tools/build-site.py [--out site] [--base-url https://gasapp.eu]

Магазины приложений требуют постоянные общедоступные адреса: политика
конфиденциальности, условия, правила сообщества, безопасность детей,
удаление аккаунта, поддержка. Их же открывает само приложение
(`core/Legal.kt`). Источник правды — Markdown в `docs/`; сайт — его
отражение, руками не правится.

Зависимостей нет намеренно: страницу, на которую ссылается анкета
магазина, должен уметь пересобрать любой, у кого есть Python.

Сборка падает, если страница ссылается на документ, которого на сайте
нет: битая ссылка в политике — повод для отказа в публикации.
"""

import argparse
import html
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Адрес страницы → (файл, раздел файла, язык, заголовок в меню).
# Раздел — заголовок второго уровня, под которым лежит публичный текст:
# в `docs/store/*.md` над ним стоят заметки для оператора, и на сайт
# они не попадают.
PAGES = {
    "privacy/": ("docs/legal/privacy-policy.en.md", None, "en", "Privacy Policy"),
    "terms/": ("docs/legal/terms-of-use.en.md", None, "en", "Terms of Use"),
    "community-guidelines/": ("docs/legal/community-guidelines.en.md", None, "en", "Community Guidelines"),
    "child-safety/": ("docs/store/child-safety-standards.md", "English", "en", "Child Safety"),
    "account-deletion/": ("docs/store/account-deletion.md", "English", "en", "Account Deletion"),
    "support/": ("docs/store/support.md", "English", "en", "Support"),
    "protocol/": ("docs/protocol/GASAPP-PROTOCOL-v1.md", None, "en", "Protocol"),
    "encryption/": ("docs/security/encryption-map.md", None, "en", "What Is Encrypted"),
    "ru/privacy/": ("docs/legal/privacy-policy.md", None, "ru", "Политика конфиденциальности"),
    "ru/terms/": ("docs/legal/terms-of-use.md", None, "ru", "Условия использования"),
    "ru/community-guidelines/": ("docs/legal/community-guidelines.md", None, "ru", "Правила сообщества"),
    "ru/child-safety/": ("docs/store/child-safety-standards.md", "Русский", "ru", "Безопасность детей"),
    "ru/account-deletion/": ("docs/store/account-deletion.md", "Русский", "ru", "Удаление аккаунта"),
    "ru/support/": ("docs/store/support.md", "Русский", "ru", "Поддержка"),
    "ru/data-retention/": ("docs/legal/data-retention-policy.md", None, "ru", "Что хранит сервер"),
    "ru/bots/": ("docs/bots.md", None, "ru", "Боты"),
}

MENU = {
    "en": ["privacy/", "terms/", "community-guidelines/", "child-safety/", "account-deletion/", "support/"],
    "ru": [
        "ru/privacy/",
        "ru/terms/",
        "ru/community-guidelines/",
        "ru/child-safety/",
        "ru/account-deletion/",
        "ru/support/",
    ],
}

# Та же страница на другом языке.
TWIN = {
    "documents/": "ru/documents/",
    "privacy/": "ru/privacy/",
    "terms/": "ru/terms/",
    "community-guidelines/": "ru/community-guidelines/",
    "child-safety/": "ru/child-safety/",
    "account-deletion/": "ru/account-deletion/",
    "support/": "ru/support/",
    "": "ru/",
}
TWIN.update({ru: en for en, ru in list(TWIN.items())})

STYLE = (ROOT / "tools/site.css").read_text(encoding="utf-8")
ASSETS_SOURCE = ROOT / "tools/site-assets"

# Значки — нарисованные SVG одной толщины (24 × 24, обводка 1.75), а не
# символы шрифта: на разных системах те выглядят по-разному.
ICONS = {
    "lock": '<rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8 10.5V7.8a4 4 0 0 1 8 0v2.7"/><path d="M12 14.5v2.5"/>',
    "user": '<circle cx="12" cy="8" r="3.6"/><path d="M4.8 20c.9-3.6 3.7-5.6 7.2-5.6s6.3 2 7.2 5.6"/>',
    "globe": '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17"/><path d="M12 3.5c2.4 2.4 3.6 5.2 3.6 8.5s-1.2 6.1-3.6 8.5c-2.4-2.4-3.6-5.2-3.6-8.5s1.2-6.1 3.6-8.5z"/>',
    "shield": '<path d="M12 3.2l7 2.7v5.6c0 4.4-2.9 7.8-7 9.3-4.1-1.5-7-4.9-7-9.3V5.9z"/><path d="M8.8 12.2l2.2 2.2 4.3-4.5"/>',
    "qr": '<rect x="4" y="4" width="6" height="6" rx="1.2"/><rect x="14" y="4" width="6" height="6" rx="1.2"/><rect x="4" y="14" width="6" height="6" rx="1.2"/><path d="M14 14h2.5v2.5H14zM18 18h2M20 14v2M14 20h2"/>',
    "timer": '<circle cx="12" cy="13" r="7.5"/><path d="M12 9v4l2.6 1.6M9.5 2.8h5"/>',
    "image": '<rect x="3.5" y="5" width="17" height="14" rx="2.5"/><circle cx="9" cy="10" r="1.6"/><path d="M20.5 16l-5-4.8-8.5 7.8"/>',
    "key": '<circle cx="8" cy="15" r="4"/><path d="M11 12.2L19 4.5M16 7.4l2.4 2.4M14 9.4l1.8 1.8"/>',
    "eye": '<path d="M2.8 12s3.4-6.3 9.2-6.3 9.2 6.3 9.2 6.3-3.4 6.3-9.2 6.3S2.8 12 2.8 12z"/><circle cx="12" cy="12" r="2.8"/>',
    "eyeoff": '<path d="M4 4l16 16"/><path d="M9.9 6c.7-.2 1.4-.3 2.1-.3 5.8 0 9.2 6.3 9.2 6.3a16 16 0 0 1-2.7 3.4M6.6 7.4C4.2 9 2.8 12 2.8 12s3.4 6.3 9.2 6.3c1.3 0 2.5-.3 3.6-.8"/>',
    "doc": '<path d="M7 3.5h7l4 4V20a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4.5a1 1 0 0 1 1-1z"/><path d="M14 3.5V8h4M9 12h6M9 15.5h6"/>',
    "code": '<path d="M8.5 7.5L4 12l4.5 4.5M15.5 7.5L20 12l-4.5 4.5M13.2 5.5l-2.4 13"/>',
    "bug": '<rect x="7" y="8" width="10" height="12" rx="5"/><path d="M12 12v8M7 13H3.5M20.5 13H17M7.6 17.2L4.5 19M16.4 17.2l3.1 1.8M9 8.2V6.5a3 3 0 0 1 6 0v1.7"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "arrow": '<path d="M7 17L17 7M9 7h8v8"/>',
    "menu": '<path d="M4 7h16M4 12h16M4 17h16"/>',
    "clock": '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
    "phone": '<rect x="6.5" y="2.8" width="11" height="18.4" rx="2.6"/><path d="M10.5 18h3"/>',
}


def icon(name, cls=""):
    attr = f' class="{cls}"' if cls else ""
    return (f'<svg{attr} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" '
            f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{ICONS[name]}</svg>')


# Тексты главной. Каждое утверждение — то же, что в политике
# конфиденциальности и в коде: сайт не обещает больше, чем приложение.
TEXT = {
    "en": {
        "tagline": "Encrypted messenger. Open source.",
        "documents": "Documents",
        "other": "Русский",
        "home": "Home",
        "menu": "Menu",
        "skip": "Skip to content",
        "on_this_page": "On this page",
        "reading": "min read",
        "nav_features": "Features",
        "nav_server": "What the server sees",
        "nav_faq": "Questions",
        "index_title": "Conversations the server can't read",
        "index_lead": "GasApp is an end-to-end encrypted messenger. No phone number, Tor built in, open source.",
        "store_soon": "Coming soon",
        "hero_note": "No ads, no analytics, no phone number.",
        "logo_alt": "GasApp",
        "promises": (
            ("lock", "Encrypted on your phone", "Messages and files are encrypted before they leave your device. The server passes them on and cannot read them."),
            ("user", "No phone number", "An account is a username and an email address. The server keeps only a hash of the address, never the address."),
            ("globe", "Tor, built in", "Turn Tor on in one tap and the server never sees your IP address. Bridges help where Tor is blocked."),
        ),
        "chat_title": "Private chats that feel like chats",
        "chat_lead": "Strong encryption should not get in the way. Everything that protects you works quietly in the background.",
        "chat_points": (
            ("qr", "Know who you are talking to", "Compare a safety number or scan a QR code once, and the app warns you if a contact's key ever changes."),
            ("timer", "Disappearing messages", "Set a timer for a chat, and its messages delete themselves on both phones when it runs out."),
            ("image", "Photos without the metadata", "Location, camera model and timestamps are stripped from a photo before it is encrypted."),
            ("key", "Backups only you can open", "A backup is encrypted with a recovery key that never leaves your hands. Not even we can open it."),
        ),
        "server_title": "What our server sees — and what it never does",
        "server_lead": "A messenger still needs a server. Here is everything ours learns, in plain words.",
        "sees_title": "The server sees",
        "sees": (
            "Your username and your public keys",
            "A hash of your email address — not the address",
            "Encrypted messages waiting for delivery, for at most 30 days",
            "That your phone is online, and its IP address on a direct connection — never written to logs",
            "If notifications are on: a push token, to wake your phone",
        ),
        "never_title": "The server never sees",
        "never": (
            "The text of your messages or the contents of your files",
            "Who sent a message — the sender is sealed",
            "Your contacts and your address book",
            "Your phone number — we never ask for it",
            "Your PIN or your encryption keys",
        ),
        "server_note": "Each line is checked against the source code. The full list is in the {privacy}.",
        "privacy_word": "privacy policy",
        "open_title": "Open source, documented in plain words",
        "open_lead": "The code is public, and so are the rules: the protocol, a map of what is encrypted, and a privacy policy that says what we cannot do as clearly as what we can.",
        "open_links": (
            ("code", "protocol/", "The GasApp protocol", "How keys are agreed and messages are encrypted"),
            ("shield", "encryption/", "What is encrypted", "Every piece of data and who can read it"),
            ("doc", "privacy/", "Privacy Policy", "What we collect, what we cannot see"),
            ("bug", ".well-known/security.txt", "Report a vulnerability", "Contacts and rules for security researchers"),
        ),
        "faq_title": "Questions",
        "faq": (
            ("Can GasApp read my messages?", "No. Messages are encrypted on your phone with keys that never leave it. The server keeps only encrypted envelopes until they are delivered, for at most 30 days."),
            ("Why do you need my email address?", "To send a one-time code when you create an account, so that one address makes one account. The server keeps only a hash of the address. The mail service that delivers the code does see it."),
            ("What if I lose my phone?", "With a backup and its recovery key you get your account back on a new phone. Without them nobody can recover your messages — us included."),
            ("Has GasApp been independently audited?", "Not yet. The code is open, the protocol is published, and every claim on this site points to where it can be checked. An independent audit is still ahead."),
            ("Does GasApp cost anything?", "No. There are no ads, no subscriptions and no in-app purchases."),
        ),
        "closing_title": "Say it privately",
        "closing_lead": "GasApp is coming to Android and iPhone.",
        "footer_lead": "An end-to-end encrypted messenger. No phone number, open source.",
        "footer_product": "GasApp",
        "footer_docs": "Documents",
        "footer_base": "© 2026 GasApp",
        "documents_lead": "Policies, support pages and technical documents for GasApp.",
        "policies": "Policies and support",
        "technical": "Technical details",
        "shot_welcome": "GasApp welcome screen",
        "shot_lock": "GasApp lock screen with a PIN keypad",
        "shot_security": "GasApp security center",
        "shot_contact": "Adding a contact by QR code in GasApp",
    },
    "ru": {
        "tagline": "Мессенджер со сквозным шифрованием. Открытый код.",
        "documents": "Документы",
        "other": "English",
        "home": "Главная",
        "menu": "Меню",
        "skip": "К содержимому",
        "on_this_page": "На этой странице",
        "reading": "мин чтения",
        "nav_features": "Возможности",
        "nav_server": "Что видит сервер",
        "nav_faq": "Вопросы",
        "index_title": "Переписка, которую не может прочитать даже сервер",
        "index_lead": "GasApp — мессенджер со сквозным шифрованием. Без номера телефона, со встроенным Tor и открытым кодом.",
        "store_soon": "Скоро",
        "hero_note": "Без рекламы, аналитики и номера телефона.",
        "logo_alt": "GasApp",
        "promises": (
            ("lock", "Шифруется на телефоне", "Сообщения и файлы шифруются до того, как покинут устройство. Сервер только передаёт их и прочитать не может."),
            ("user", "Без номера телефона", "Аккаунт — это имя и адрес почты. Сервер хранит только хеш адреса, а не сам адрес."),
            ("globe", "Tor встроен", "Включите Tor одним касанием — и сервер не увидит ваш IP-адрес. Где Tor блокируют, помогут мосты."),
        ),
        "chat_title": "Приватные чаты, которые ощущаются как обычные",
        "chat_lead": "Сильное шифрование не должно мешать. Всё, что вас защищает, работает тихо и само.",
        "chat_points": (
            ("qr", "Вы знаете, с кем говорите", "Сверьте код безопасности или отсканируйте QR-код один раз — и приложение предупредит, если ключ собеседника сменится."),
            ("timer", "Исчезающие сообщения", "Задайте таймер для чата — и его сообщения сами удалятся на обоих телефонах, когда срок выйдет."),
            ("image", "Фото без лишних данных", "Место съёмки, модель камеры и время удаляются из фото до шифрования."),
            ("key", "Копии, которые откроете только вы", "Резервная копия зашифрована ключом восстановления, который есть только у вас. Даже мы её не откроем."),
        ),
        "server_title": "Что видит наш сервер — и чего не увидит никогда",
        "server_lead": "Мессенджеру всё равно нужен сервер. Вот всё, что узнаёт наш, — простыми словами.",
        "sees_title": "Сервер видит",
        "sees": (
            "Ваше имя пользователя и открытые ключи",
            "Хеш адреса почты — не сам адрес",
            "Зашифрованные сообщения в очереди на доставку — не дольше 30 суток",
            "Что телефон в сети, а при прямом соединении — его IP-адрес; в журналы он не пишется",
            "Если уведомления включены — токен, чтобы разбудить телефон",
        ),
        "never_title": "Сервер не видит никогда",
        "never": (
            "Текст сообщений и содержимое файлов",
            "Кто отправил сообщение — отправитель запечатан",
            "Ваши контакты и адресную книгу",
            "Номер телефона — мы его не спрашиваем",
            "Ваш PIN и ключи шифрования",
        ),
        "server_note": "Каждая строка сверена с исходным кодом. Полный список — в {privacy}.",
        "privacy_word": "политике конфиденциальности",
        "open_title": "Открытый код и документы простыми словами",
        "open_lead": "Код открыт, правила — тоже: протокол, карта того, что шифруется, и политика конфиденциальности, которая так же ясно говорит, чего мы не можем, как и что можем.",
        "open_links": (
            ("code", "protocol/", "Протокол GasApp", "Как договариваются ключи и шифруются сообщения (англ.)"),
            ("shield", "encryption/", "Что шифруется", "Все данные и кто может их прочитать (англ.)"),
            ("doc", "ru/privacy/", "Политика конфиденциальности", "Что мы собираем и чего не видим"),
            ("bug", ".well-known/security.txt", "Сообщить об уязвимости", "Контакты и правила для исследователей"),
        ),
        "faq_title": "Вопросы",
        "faq": (
            ("Может ли GasApp прочитать мою переписку?", "Нет. Сообщения шифруются на телефоне ключами, которые его не покидают. Сервер хранит только зашифрованные конверты до доставки — не дольше 30 суток."),
            ("Зачем нужен адрес почты?", "Чтобы при создании аккаунта прислать одноразовый код: один адрес — один аккаунт. Сервер хранит только хеш адреса. Почтовая служба, которая доставляет письмо, адрес видит."),
            ("Что будет, если я потеряю телефон?", "С резервной копией и ключом восстановления вы вернёте аккаунт на новом телефоне. Без них восстановить переписку не сможет никто — и мы тоже."),
            ("Прошёл ли GasApp независимый аудит?", "Пока нет. Код открыт, протокол опубликован, и у каждого утверждения на этом сайте есть место, где его можно проверить. Независимый аудит ещё впереди."),
            ("Сколько стоит GasApp?", "Нисколько. В приложении нет рекламы, подписок и покупок."),
        ),
        "closing_title": "Скажите это приватно",
        "closing_lead": "GasApp скоро появится на Android и iPhone.",
        "footer_lead": "Мессенджер со сквозным шифрованием. Без номера телефона, с открытым кодом.",
        "footer_product": "GasApp",
        "footer_docs": "Документы",
        "footer_base": "© 2026 GasApp",
        "documents_lead": "Правила, страницы поддержки и технические документы GasApp.",
        "policies": "Правила и поддержка",
        "technical": "Технические подробности",
        "shot_welcome": "Приветствие GasApp",
        "shot_lock": "Вход в GasApp по PIN",
        "shot_security": "Центр безопасности GasApp",
        "shot_contact": "Добавление контакта по QR-коду в GasApp",
    },
}

class BuildError(Exception):
    pass


def section_of(text, name):
    """Текст под заголовком второго уровня `name` — до следующего такого же."""
    lines = text.split("\n")
    start = None
    for index, line in enumerate(lines):
        if line.strip() == f"## {name}":
            start = index + 1
            break
    if start is None:
        raise BuildError(f"нет раздела «## {name}»")

    end = len(lines)
    for index in range(start, len(lines)):
        if lines[index].startswith("## "):
            end = index
            break

    body = [re.sub(r"^#(#+ )", r"\1", line) for line in lines[start:end]]
    # Разделитель между языками в исходнике — не часть страницы.
    while body and body[-1].strip() in ("", "---"):
        body.pop()

    return "\n".join(body)


class Renderer:
    """Markdown в объёме, которым написаны документы проекта."""

    def __init__(self, source, page, links):
        self.source = source
        self.page = page
        self.links = links

    def href(self, target):
        if re.match(r"^(https?:|mailto:|#)", target):
            return target

        path, _, anchor = target.partition("#")
        resolved = (ROOT / self.source).parent.joinpath(path).resolve()
        try:
            relative = resolved.relative_to(ROOT).as_posix()
        except ValueError:
            relative = None

        candidates = self.links.get(relative, [])
        if not candidates:
            return None

        # Предпочесть страницу на языке текущей.
        language = PAGES[self.page][2]
        chosen = next((page for page in candidates if PAGES[page][2] == language), candidates[0])
        depth = self.page.count("/")

        return "../" * depth + chosen + (f"#{anchor}" if anchor else "")

    def inline(self, text):
        codes = []

        def stash(match):
            codes.append(f"<code>{html.escape(match.group(1))}</code>")
            return f"\x00{len(codes) - 1}\x00"

        text = re.sub(r"`([^`]+)`", stash, text)
        text = html.escape(text, quote=False)

        def link(match):
            label, target = match.group(1), html.unescape(match.group(2))
            address = self.href(target)
            if address is None:
                # Документ не публикуется: остаётся его название, без
                # ссылки в никуда.
                return label
            return f'<a href="{html.escape(address)}">{label}</a>'

        text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, text)
        text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"~~([^~]+)~~", r"<s>\1</s>", text)
        text = re.sub(r"(?<![\w*])\*([^*\s][^*]*)\*(?![\w*])", r"<em>\1</em>", text)

        return re.sub(r"\x00(\d+)\x00", lambda match: codes[int(match.group(1))], text)

    def render(self, text):
        text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
        lines = text.split("\n")
        out = []
        index = 0

        def paragraph(buffer):
            if buffer:
                out.append("<p>" + self.inline(" ".join(part.strip() for part in buffer)) + "</p>")
                buffer.clear()

        buffer = []
        while index < len(lines):
            line = lines[index]
            stripped = line.strip()

            if stripped.startswith("```"):
                paragraph(buffer)
                index += 1
                block = []
                while index < len(lines) and not lines[index].strip().startswith("```"):
                    block.append(lines[index])
                    index += 1
                index += 1
                out.append("<pre><code>" + html.escape("\n".join(block)) + "</code></pre>")
                continue

            if not stripped:
                paragraph(buffer)
                index += 1
                continue

            heading = re.match(r"^(#{1,5}) (.+)$", stripped)
            if heading:
                paragraph(buffer)
                level = len(heading.group(1))
                title = heading.group(2).strip()
                anchor = re.sub(r"[^\w\- ]", "", title.lower()).strip().replace(" ", "-")
                out.append(f'<h{level} id="{html.escape(anchor)}">{self.inline(title)}</h{level}>')
                index += 1
                continue

            if re.match(r"^(-{3,}|\*{3,})$", stripped):
                paragraph(buffer)
                out.append("<hr>")
                index += 1
                continue

            if stripped.startswith("|") and index + 1 < len(lines) and re.match(
                r"^\|[\s:|\-]+\|$", lines[index + 1].strip()
            ):
                paragraph(buffer)
                rows = []
                while index < len(lines) and lines[index].strip().startswith("|"):
                    rows.append(lines[index].strip())
                    index += 1
                out.append(self.table(rows))
                continue

            if stripped.startswith(">"):
                paragraph(buffer)
                quote = []
                while index < len(lines) and lines[index].strip().startswith(">"):
                    quote.append(re.sub(r"^\s*> ?", "", lines[index]))
                    index += 1
                out.append("<blockquote>" + self.render("\n".join(quote)) + "</blockquote>")
                continue

            if re.match(r"^(\s*)([-*]|\d+\.) ", line):
                paragraph(buffer)
                index = self.list(lines, index, out)
                continue

            buffer.append(line)
            index += 1

        paragraph(buffer)

        return "\n".join(out)

    def list(self, lines, index, out):
        first = re.match(r"^(\s*)([-*]|\d+\.) ", lines[index])
        indent = len(first.group(1))
        ordered = first.group(2)[0].isdigit()
        items = []

        while index < len(lines):
            line = lines[index]
            marker = re.match(r"^(\s*)([-*]|\d+\.) (.*)$", line)

            if marker and len(marker.group(1)) == indent:
                items.append([marker.group(3)])
                index += 1
            elif not line.strip():
                # Пустая строка внутри списка: продолжение — если дальше
                # идёт отступ либо новый пункт того же уровня.
                following = lines[index + 1] if index + 1 < len(lines) else ""
                again = re.match(r"^(\s*)([-*]|\d+\.) ", following)
                deeper = following.startswith(" " * (indent + 2)) and following.strip()
                if items and (deeper or (again and len(again.group(1)) == indent)):
                    items[-1].append("")
                    index += 1
                else:
                    break
            elif items and (len(line) - len(line.lstrip())) > indent:
                items[-1].append(line[indent + 2 :] if line.startswith(" " * (indent + 2)) else line.strip())
                index += 1
            else:
                break

        tag = "ol" if ordered else "ul"
        out.append(f"<{tag}>")
        for item in items:
            body = self.render("\n".join(item))
            # Пункт из одного абзаца — без обёртки: так список плотнее.
            if body.count("<p>") == 1 and body.startswith("<p>") and body.endswith("</p>"):
                body = body[3:-4]
            out.append(f"<li>{body}</li>")
        out.append(f"</{tag}>")

        return index

    def table(self, rows):
        def cells(row):
            return [cell.strip() for cell in re.split(r"(?<!\\)\|", row.strip().strip("|"))]

        head = cells(rows[0])
        parts = ['<div class="table"><table><thead><tr>']
        parts += [f"<th>{self.inline(cell)}</th>" for cell in head]
        parts.append("</tr></thead><tbody>")
        for row in rows[2:]:
            parts.append("<tr>" + "".join(f"<td>{self.inline(cell)}</td>" for cell in cells(row)) + "</tr>")
        parts.append("</tbody></table></div>")

        return "".join(parts)


def shell(page, language, title, body, base_url, description=None):
    depth = page.count("/")
    up = "../" * depth
    text = TEXT[language]
    home = "" if language == "en" else "ru/"
    is_home = page in ("", "ru/")
    assets = f"{up}assets"
    support = "support/" if language == "en" else "ru/support/"
    documents = "documents/" if language == "en" else "ru/documents/"
    current = ' aria-current="page"'

    def mark(item):
        return current if item == page else ""

    twin = TWIN.get(page)
    language_link = (
        f'<a class="language-link" href="{up}{twin}" hreflang="{"ru" if language == "en" else "en"}" '
        f'lang="{"ru" if language == "en" else "en"}">{text["other"]}</a>'
        if twin is not None
        else ""
    )
    anchor = "" if is_home else f"{up}{home}"
    primary = (
        f'<a href="{anchor}#features">{html.escape(text["nav_features"])}</a>'
        f'<a href="{anchor}#server">{html.escape(text["nav_server"])}</a>'
        f'<a href="{up}{documents}"{mark(documents)}>{html.escape(text["documents"])}</a>'
        f'<a href="{up}{support}"{mark(support)}>{html.escape(PAGES[support][3])}</a>'
    )
    mobile = primary + "".join(
        f'<a href="{up}{item}"{mark(item)}>{html.escape(PAGES[item][3])}</a>'
        for item in MENU[language]
        if item != support
    ) + language_link

    if not is_home:
        word_count = len(re.findall(r"\b[\w'-]+\b", re.sub(r"<[^>]+>", " ", html.unescape(body))))
        reading_minutes = max(1, (word_count + 219) // 220)
        headings = re.findall(r'<h2 id="([^"]+)">(.*?)</h2>', body)
        toc_links = "".join(
            f'<a href="#{html.escape(anchor_id)}">{html.escape(html.unescape(re.sub(r"<[^>]+>", "", label)))}</a>'
            for anchor_id, label in headings
        )
        body = re.sub(r"^<h1\b[^>]*>.*?</h1>\s*", "", body, count=1, flags=re.S)
        toc = (
            f'<aside class="toc"><nav aria-label="{text["on_this_page"]}"><b>{text["on_this_page"]}</b>'
            f'{toc_links}<a class="back-link" href="{up}{home}">← {text["home"]}</a></nav></aside>'
            if toc_links
            else "<div></div>"
        )
        mobile_toc = (
            f'<details class="mobile-toc"><summary>{text["on_this_page"]}</summary>'
            f'<nav aria-label="{text["on_this_page"]}">{toc_links}</nav></details>'
            if toc_links
            else ""
        )
        body = (
            '<div class="wrap doc-main"><div class="document-layout"><article class="article">'
            f'<div class="breadcrumbs"><a href="{up}{home}">{text["home"]}</a><span aria-hidden="true">/</span>'
            f'<span>{html.escape(title)}</span></div>'
            f'<header class="article-header"><h1>{html.escape(title)}</h1>'
            f'<div class="article-meta"><span>{icon("clock")}{reading_minutes} {text["reading"]}</span></div></header>'
            f'{mobile_toc}<div class="article-body">{body}</div></article>{toc}</div></div>'
        )

    canonical_url = f"{base_url.rstrip('/')}/{page}" if base_url else ""
    canonical = f'<link rel="canonical" href="{canonical_url}">' if base_url else ""
    alternate = (
        f'<link rel="alternate" hreflang="{"ru" if language == "en" else "en"}" href="{base_url.rstrip("/")}/{twin}">'
        if base_url and twin is not None
        else ""
    )
    summary = description or f"{title} — GasApp. {text['tagline']}"
    og_image = f'{base_url.rstrip("/")}/assets/og-image.jpg' if base_url else f"{assets}/og-image.jpg"
    page_title = f"GasApp — {title}" if is_home else f"{title} — GasApp"
    style = STYLE.replace("ASSETS", assets)
    script = (
        "<script>(()=>{const h=document.querySelector('.site-header');if(!h)return;"
        "const f=()=>h.classList.toggle('scrolled',scrollY>24);f();addEventListener('scroll',f,{passive:true})})()</script>"
        if is_home
        else ""
    )

    return f"""<!doctype html>
<html lang="{language}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0E1238">
<title>{html.escape(page_title)}</title>
<meta name="description" content="{html.escape(summary)}">
{canonical}
{alternate}
<meta property="og:type" content="website">
<meta property="og:site_name" content="GasApp">
<meta property="og:title" content="{html.escape(page_title)}">
<meta property="og:description" content="{html.escape(summary)}">
<meta property="og:image" content="{og_image}">
{f'<meta property="og:url" content="{canonical_url}">' if base_url else ""}
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" type="image/png" sizes="64x64" href="{assets}/favicon-64.png">
<link rel="apple-touch-icon" href="{assets}/apple-touch-icon.png">
<link rel="preload" href="{assets}/fonts/rubik_black.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="{assets}/fonts/inter_regular.woff2" as="font" type="font/woff2" crossorigin>
<style>{style}</style>
</head>
<body class="{"home" if is_home else "doc"}">
<a class="skip-link" href="#content">{text["skip"]}</a>
<header class="site-header"><div class="wrap header-inner">
<a class="brand" href="{up}{home}"><img src="{assets}/gas-logo.webp" width="61" height="34" alt="">GasApp</a>
<nav class="site-nav" aria-label="{text["menu"]}">{primary}{language_link}</nav>
<details class="mobile-nav"><summary>{icon("menu")}{text["menu"]}</summary><nav aria-label="{text["menu"]}">{mobile}</nav></details>
</div></header>
<main id="content">
{body}
</main>
{footer(page, language)}
{script}
</body>
</html>
"""


def footer(page, language):
    up = "../" * page.count("/")
    text = TEXT[language]
    home = "" if language == "en" else "ru/"
    assets = f"{up}assets"
    product = (
        f'<a href="{up}{home}#features">{html.escape(text["nav_features"])}</a>'
        f'<a href="{up}{home}#server">{html.escape(text["nav_server"])}</a>'
        f'<a href="{up}{home}#faq">{html.escape(text["nav_faq"])}</a>'
        f'<a href="{up}{"documents/" if language == "en" else "ru/documents/"}">{html.escape(text["documents"])}</a>'
    )
    documents = "".join(
        f'<a href="{up}{item}">{html.escape(PAGES[item][3])}</a>' for item in MENU[language]
    )
    twin = TWIN.get(page)
    language_link = f'<a href="{up}{twin}">{text["other"]}</a>' if twin is not None else ""
    return (
        '<footer><div class="wrap"><div class="footer-inner">'
        f'<div class="footer-brand"><img src="{assets}/gas-logo.webp" width="71" height="40" alt="GasApp">'
        f'<p>{html.escape(text["footer_lead"])}</p></div>'
        f'<div class="footer-col"><h4>{html.escape(text["footer_product"])}</h4>{product}</div>'
        f'<div class="footer-col"><h4>{html.escape(text["footer_docs"])}</h4>{documents}</div>'
        f'</div><div class="footer-base"><span>{text["footer_base"]}</span>{language_link}</div></div></footer>'
    )


def store_badges(text):
    soon = html.escape(text["store_soon"])
    return (
        '<div class="hero-actions">'
        f'<span class="store" aria-disabled="true">{icon("phone")}<span><small>Google Play</small><b>{soon}</b></span></span>'
        f'<span class="store" aria-disabled="true">{icon("phone")}<span><small>App Store</small><b>{soon}</b></span></span>'
        "</div>"
    )


def index_page(language, base_url):
    text = TEXT[language]
    page = "" if language == "en" else "ru/"
    up = "../" * page.count("/")
    assets = f"{up}assets"

    def shot(name, alt, cls):
        return (
            f'<div class="phone {cls}"><img src="{assets}/screens/{name}.webp" width="1206" height="2622" '
            f'loading="{"eager" if cls == "center" else "lazy"}" alt="{html.escape(alt)}"></div>'
        )

    promises = "".join(
        f'<div class="promise">{icon(name)}<h3>{html.escape(title)}</h3><p>{html.escape(body)}</p></div>'
        for name, title, body in text["promises"]
    )
    points = "".join(
        f'<li>{icon(name)}<span><b>{html.escape(title)}</b>{html.escape(body)}</span></li>'
        for name, title, body in text["chat_points"]
    )
    sees = "".join(f"<li>{html.escape(line)}</li>" for line in text["sees"])
    never = "".join(f"<li>{html.escape(line)}</li>" for line in text["never"])
    privacy = "privacy/" if language == "en" else "ru/privacy/"
    note = html.escape(text["server_note"]).replace(
        "{privacy}", f'<a href="{up}{privacy}">{html.escape(text["privacy_word"])}</a>'
    )
    links = "".join(
        f'<li><a href="{up}{href}">{icon(name)}<span>{html.escape(title)}<small>{html.escape(detail)}</small></span>'
        f'{icon("arrow", "arrow")}</a></li>'
        for name, href, title, detail in text["open_links"]
    )
    faq = "".join(
        f"<details><summary>{html.escape(question)}{icon('plus')}</summary><p>{html.escape(answer)}</p></details>"
        for question, answer in text["faq"]
    )

    body = (
        '<section class="hero"><div class="wrap hero-inner">'
        f'<img class="hero-logo" src="{assets}/gas-logo.webp" width="1200" height="675" alt="{text["logo_alt"]}" fetchpriority="high">'
        f'<h1>{html.escape(text["index_title"])}</h1>'
        f'<p class="lead">{html.escape(text["index_lead"])}</p>'
        f"{store_badges(text)}"
        f'<p class="hero-note">{html.escape(text["hero_note"])}</p>'
        '<div class="phones">'
        + shot("lock", text["shot_lock"], "center")
        + "</div></div></section>"
        f'<div class="wrap"><div class="promises">{promises}</div></div>'
        f'<section id="features" class="section"><div class="wrap split">'
        f'<div class="media"><img class="app-icon" src="{assets}/app-icon.webp" width="512" height="512" alt="" loading="lazy"></div>'
        f'<div><div class="section-title"><h2>{html.escape(text["chat_title"])}</h2><p>{html.escape(text["chat_lead"])}</p></div>'
        f'<ul class="points">{points}</ul></div></div></section>'
        f'<section id="server" class="section"><div class="wrap">'
        f'<div class="section-title"><h2>{html.escape(text["server_title"])}</h2><p>{html.escape(text["server_lead"])}</p></div>'
        '<div class="ledger">'
        f'<div class="ledger-col sees"><h3>{icon("eye")}{html.escape(text["sees_title"])}</h3><ul>{sees}</ul></div>'
        f'<div class="ledger-col never"><h3>{icon("eyeoff")}{html.escape(text["never_title"])}</h3><ul>{never}</ul></div>'
        f'</div><p class="ledger-note">{note}</p></div></section>'
        f'<section id="open" class="section"><div class="wrap open">'
        f'<div class="section-title"><h2>{html.escape(text["open_title"])}</h2><p>{html.escape(text["open_lead"])}</p></div>'
        f'<ul class="doc-links">{links}</ul></div></section>'
        f'<section id="faq" class="section"><div class="wrap"><div class="section-title"><h2>{html.escape(text["faq_title"])}</h2></div>'
        f'<div class="faq">{faq}</div></div></section>'
        '<div class="wrap"><section class="closing">'
        f'<img src="{assets}/gas-logo.webp" width="1200" height="675" alt="" loading="lazy">'
        f'<h2>{html.escape(text["closing_title"])}</h2><p>{html.escape(text["closing_lead"])}</p>'
        f"{store_badges(text)}</section></div>"
    )
    if language == "en" and re.search(r"[А-Яа-яЁё]", re.sub(r'lang="ru"[^>]*>[^<]*', "", body)):
        raise BuildError("English home page contains untranslated Cyrillic text")

    return shell(page, language, text["index_title"], body, base_url, description=text["index_lead"])


def documents_page(language, base_url):
    text = TEXT[language]
    page = "documents/" if language == "en" else "ru/documents/"
    prefix = "../" * page.count("/")
    extra = [item for item, entry in PAGES.items() if entry[2] == language and item not in MENU[language]]
    if language == "ru":
        extra += ["protocol/", "encryption/"]
    russian_link_titles = {
        "protocol/": "Протокол (англ.)",
        "encryption/": "Что шифруется (англ.)",
    }

    def label(item):
        return russian_link_titles.get(item, PAGES[item][3]) if language == "ru" else PAGES[item][3]

    def links(items):
        return '<div class="document-index-grid">' + "".join(
            f'<a class="document-index-item" href="{prefix}{item}">{icon("doc")}'
            f'<span>{html.escape(label(item))}</span>{icon("arrow", "arrow")}</a>'
            for item in items
        ) + "</div>"

    body = (
        f'<h1>{html.escape(text["documents"])}</h1><p>{html.escape(text["documents_lead"])}</p>'
        f'<div class="document-index"><h2 id="policies">{html.escape(text["policies"])}</h2>{links(MENU[language])}'
        f'<h2 id="technical">{html.escape(text["technical"])}</h2>{links(extra)}</div>'
    )
    return shell(page, language, text["documents"], body, base_url, description=text["documents_lead"])


def build(out, base_url):
    links = {}
    for page, (source, _, _, _) in PAGES.items():
        links.setdefault(source, []).append(page)

    for page, (source, section, language, title) in PAGES.items():
        path = ROOT / source
        if not path.exists():
            raise BuildError(f"{source}: файла нет")

        text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
        if section:
            text = f"# {title}\n\n" + section_of(text, section)

        body = Renderer(source, page, links).render(text)
        if language == "en":
            checked_body = body
            if page == "protocol/":
                # These two Cyrillic letters illustrate a username homograph.
                if body.count("аlice") != 1 or body.count("<code>а</code>") != 1:
                    raise BuildError(f"{source}: protocol homograph example changed")
                checked_body = body.replace("аlice", "alice").replace("<code>а</code>", "<code>a</code>")
            if re.search(r"[А-Яа-яЁё]", checked_body):
                raise BuildError(f"{source}: untranslated Cyrillic text on an English page")
        # 🔴 Заглушка адреса на опубликованной странице — отказ магазина.
        for placeholder in ("<домен>", "<domain>", "&lt;домен&gt;", "&lt;domain&gt;"):
            if placeholder in body:
                raise BuildError(f"{source}: на странице осталась заглушка {placeholder}")

        target = out / page / "index.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(shell(page, language, title, body, base_url), encoding="utf-8", newline="\n")

    (out / "index.html").write_text(index_page("en", base_url), encoding="utf-8", newline="\n")
    (out / "ru").mkdir(parents=True, exist_ok=True)
    (out / "ru" / "index.html").write_text(index_page("ru", base_url), encoding="utf-8", newline="\n")
    for language, page in (("en", "documents/"), ("ru", "ru/documents/")):
        target = out / page / "index.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(documents_page(language, base_url), encoding="utf-8", newline="\n")

    # Картинки, шрифты, значки сайта — как есть (tools/site-assets).
    assets = out / "assets"
    for item in ASSETS_SOURCE.rglob("*"):
        if item.is_file():
            target = assets / item.relative_to(ASSETS_SOURCE)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(item.read_bytes())
    # Снимки — настоящие, из прогона в симуляторе (tools/mac-check.sh).
    for screen in ("lock",):
        if not (assets / "screens" / f"{screen}.webp").exists():
            raise BuildError(f"нет снимка экрана tools/site-assets/screens/{screen}.webp")

    # RFC 9116: куда сообщать об уязвимостях.
    well_known = out / ".well-known"
    well_known.mkdir(parents=True, exist_ok=True)
    security = (ROOT / "docs/security/security.txt").read_text(encoding="utf-8")
    (well_known / "security.txt").write_text(security, encoding="utf-8", newline="\n")

    (out / "robots.txt").write_text(
        "User-agent: *\nAllow: /\n" + (f"Sitemap: {base_url.rstrip('/')}/sitemap.xml\n" if base_url else ""),
        encoding="utf-8",
        newline="\n",
    )
    if base_url:
        urls = "".join(
            f"<url><loc>{base_url.rstrip('/')}/{page}</loc></url>" for page in ["", "ru/", "documents/", "ru/documents/", *PAGES]
        )
        (out / "sitemap.xml").write_text(
            f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>\n',
            encoding="utf-8",
            newline="\n",
        )
    # GitHub Pages: не обрабатывать сайт Jekyll'ом (иначе пропадёт .well-known).
    (out / ".nojekyll").write_text("", encoding="utf-8")

    return len(PAGES) + 4


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default="site")
    parser.add_argument("--base-url", default="https://gasapp.eu")
    arguments = parser.parse_args()

    try:
        count = build(ROOT / arguments.out, arguments.base_url)
    except BuildError as error:
        print(f"::error::сайт не собран: {error}", file=sys.stderr)
        return 1

    print(f"OK: {count} страниц в {arguments.out}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
