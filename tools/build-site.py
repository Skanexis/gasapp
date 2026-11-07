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

TEXT = {
    "en": {
        "tagline": "Encrypted messenger. Open source.",
        "documents": "Documents",
        "more": "More",
        "other": "Russian",
        "footer": "GasApp · Make space for better conversations.",
        "index_title": "Make space for better conversations.",
        "index_lead": "Message the people who matter, share moments and follow channels you love. GasApp brings it together in a private, open-source messenger.",
        "explore": "Explore GasApp",
        "security": "Browse documents",
        "essentials": "Everything you need to connect.",
        "essentials_lead": "A simple place for messages, channels and more.",
        "documents_lead": "Find the policies, support pages and technical documents for GasApp.",
        "policies": "Policies and support",
        "technical": "Technical details",
        "home": "Home",
        "menu": "Menu",
        "skip": "Skip to content",
        "on_this_page": "ON THIS PAGE",
        "document": "GASAPP / DOCUMENTATION",
        "reading": "min read",
        "preview_chats": "CHATS",
        "preview_chat": "Conversation",
        "preview_channel": "Channels",
        "preview_name": "Alex",
        "preview_first": "Hey! Ready for later?",
        "preview_second": "Absolutely. See you there ✨",
        "preview_status": "A LITTLE SPACE FOR EVERY CONVERSATION",
        "features": (("01 / CHAT", "Your conversations", "Keep in touch one to one, with messages and files protected by end-to-end encryption."), ("02 / CHANNELS", "Follow what matters", "Discover channels through a link, QR code or @name. Enjoy posts, reactions and search."), ("03 / YOUR WAY", "More control", "Choose a username, turn on Tor in the app, and keep your files in an encrypted vault.")),
        "proof": (("Personal chats", "Messages and files together"), ("Channels", "Posts, reactions and discovery"), ("Your account", "A username you choose")),
    },
    "ru": {
        "tagline": "Мессенджер со сквозным шифрованием. Открытый код.",
        "documents": "Документы",
        "more": "Ещё",
        "other": "English",
        "footer": "GasApp · Больше места для общения.",
        "index_title": "Больше места для общения.",
        "index_lead": "Пишите близким, делитесь моментами и читайте интересные каналы. GasApp объединяет всё это в приватном мессенджере с открытым кодом.",
        "explore": "Возможности GasApp",
        "security": "Документы",
        "essentials": "Общаться легко.",
        "essentials_lead": "Сообщения, каналы и полезные возможности в одном месте.",
        "documents_lead": "Здесь собраны правила, страницы поддержки и технические документы GasApp.",
        "policies": "Правила и поддержка",
        "technical": "Технические подробности",
        "home": "Главная",
        "menu": "Меню",
        "skip": "К содержимому",
        "on_this_page": "НА ЭТОЙ СТРАНИЦЕ",
        "document": "GASAPP / ДОКУМЕНТЫ",
        "reading": "мин чтения",
        "preview_chats": "ЧАТЫ",
        "preview_chat": "Разговор",
        "preview_channel": "Каналы",
        "preview_name": "Алекс",
        "preview_first": "Привет! Сегодня увидимся?",
        "preview_second": "Конечно. До встречи ✨",
        "preview_status": "МЕСТО ДЛЯ КАЖДОГО РАЗГОВОРА",
        "features": (("01 / ЧАТ", "Личные разговоры", "Общайтесь один на один: сообщения и файлы защищены сквозным шифрованием."), ("02 / КАНАЛЫ", "Следите за интересным", "Находите каналы по ссылке, QR-коду или @имени. Читайте записи, ставьте реакции и пользуйтесь поиском."), ("03 / ВАШ ВЫБОР", "Больше контроля", "Выберите имя пользователя, включайте Tor в приложении и храните файлы в зашифрованном хранилище.")),
        "proof": (("Личные чаты", "Сообщения и файлы"), ("Каналы", "Записи, реакции и поиск"), ("Ваш аккаунт", "Имя выбираете вы")),
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


def shell(page, language, title, body, base_url):
    depth = page.count("/")
    up = "../" * depth
    text = TEXT[language]
    home = "" if language == "en" else "ru/"

    menu = "".join(
        '<a href="{}"{}>{}</a>'.format(
            up + item, ' aria-current="page"' if item == page else "", html.escape(PAGES[item][3])
        )
        for item in MENU[language]
    )
    twin = TWIN.get(page)
    if twin is not None:
        menu += f'<a class="language-link" href="{up}{twin}" hreflang="{"ru" if language == "en" else "en"}">{text["other"]}</a>'

    is_home = page in ("", "ru/")
    if is_home:
        home_menu = (
            f'<a href="#features">{html.escape(text["explore"])}</a>'
            f'<a href="{up}{"documents/" if language == "en" else "ru/documents/"}">{html.escape(text["documents"])}</a>'
            f'<a href="{up}{"support/" if language == "en" else "ru/support/"}">{html.escape(PAGES["support/" if language == "en" else "ru/support/"][3])}</a>'
        )
        if twin is not None:
            home_menu += f'<a class="language-link" href="{up}{twin}" hreflang="{"ru" if language == "en" else "en"}">{text["other"]}</a>'
    else:
        home_menu = menu
    if not is_home:
        word_count = len(re.findall(r"\b[\w'-]+\b", re.sub(r"<[^>]+>", " ", html.unescape(body))))
        reading_minutes = max(1, (word_count + 219) // 220)
        headings = re.findall(r'<h2 id="([^"]+)">(.*?)</h2>', body)
        toc_links = "".join(
            f'<a href="#{html.escape(anchor)}">{html.escape(html.unescape(re.sub(r"<[^>]+>", "", label)))}</a>'
            for anchor, label in headings
        )
        body = re.sub(r'^<h1\b[^>]*>.*?</h1>\s*', '', body, count=1, flags=re.S)
        body = (
            '<div class="document-layout">'
            f'<details class="mobile-toc"><summary>{text["on_this_page"]}</summary>'
            f'<nav aria-label="{text["on_this_page"]}">{toc_links}</nav></details>'
            '<article class="article">'
            f'<div class="breadcrumbs"><a href="{up}{home}">{text["home"]}</a><span>/</span><span>{html.escape(title)}</span></div>'
            f'<div class="article-header"><span class="eyebrow">{text["document"]}</span><h1>{html.escape(title)}</h1>'
            f'<div class="article-meta"><span class="reading-time">◷ {reading_minutes} {text["reading"]}</span>'
            f'<span>{html.escape(text["tagline"])}</span></div></div><div class="article-body">{body}</div></article>'
            f'<aside class="toc"><nav aria-label="{text["on_this_page"]}"><b>{text["on_this_page"]}</b>'
            f'<div class="toc-links">{toc_links}</div><a class="back-link" href="{up}{home}">← {text["home"]}</a>'
            '</nav></aside></div>'
        )

    canonical = f'<link rel="canonical" href="{base_url.rstrip("/")}/{page}">' if base_url else ""

    return f"""<!doctype html>
<html lang="{language}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0c1027">
<title>{html.escape(title)} — GasApp</title>
<meta name="description" content="{html.escape(title)} — GasApp. {html.escape(text["tagline"])}">
{canonical}
<style>{STYLE}</style>
</head>
<body>
<a class="skip-link" href="#content">{text["skip"]}</a>
<header class="site-header"><div class="header-inner">
<a class="brand" href="{up}{home}"><span class="brand-mark">✦</span>GasApp <small>MESSENGER</small></a>
<nav class="site-nav" aria-label="{text["menu"]}">{home_menu}</nav>
<details class="mobile-nav"><summary>{text["menu"]}</summary><nav aria-label="{text["documents"]}">{menu}</nav></details>
</div></header>
<main id="content">
{body}
</main>
<footer><span>{text["footer"]}</span><a href="{up}{'support/' if language == 'en' else 'ru/support/'}">{PAGES['support/' if language == 'en' else 'ru/support/'][3]}</a></footer>
</body>
</html>
"""


def index_page(language, base_url):
    text = TEXT[language]
    page = "" if language == "en" else "ru/"
    prefix = "" if language == "en" else "../"
    documents = "documents/" if language == "en" else "ru/documents/"
    body = (
        f'<section class="hero"><div><div class="eyebrow">GasApp / {text["tagline"]}</div>'
        f'<h1>{text["index_title"]}</h1><p>{text["index_lead"]}</p>'
        f'<div class="hero-actions"><a class="button primary" href="#features">{text["explore"]}</a>'
        f'<a class="button secondary" href="{prefix}{documents}">{text["security"]}</a></div></div>'
        '<div class="hero-art" aria-hidden="true"><div class="preview-scene">'
        '<div class="preview-glow"></div><div class="app-preview">'
        f'<div class="preview-top"><span class="preview-wordmark">✦ GasApp</span><span class="preview-top-label">{html.escape(text["preview_chat"])}</span></div>'
        '<div class="preview-main"><div class="preview-side">'
        f'<span class="preview-side-label">{html.escape(text["preview_chats"])}</span>'
        f'<div class="preview-person"><span class="preview-avatar">A</span><span><b>{html.escape(text["preview_name"])}</b><small>●</small></span></div>'
        f'<div class="preview-person preview-person-muted"><span class="preview-avatar">✦</span><span><b>{html.escape(text["preview_channel"])}</b><small>···</small></span></div>'
        '</div><div class="preview-conversation">'
        f'<div class="preview-conversation-head"><span class="preview-avatar">A</span><b>{html.escape(text["preview_name"])}</b><span class="preview-dots">•••</span></div>'
        f'<div class="preview-bubble incoming">{html.escape(text["preview_first"])}</div>'
        f'<div class="preview-bubble outgoing">{html.escape(text["preview_second"])}</div>'
        '<div class="preview-compose"><span>＋</span><i></i><span>➤</span></div></div></div></div>'
        f'<div class="preview-caption"><span>✦</span>{html.escape(text["preview_status"])}</div>'
        '</div></div></section>'
        '<div class="proof-strip">'
        + ''.join(f'<div><b>{html.escape(name)}</b><span>{html.escape(detail)}</span></div>' for name, detail in text['proof'])
        + '</div>'
        f'<section id="features" class="home-section"><div class="section-heading"><h2>{text["essentials"]}</h2><p>{text["essentials_lead"]}</p></div>'
        '<div class="feature-grid">'
        + ''.join(
            f'<article class="feature-card"><span class="eyebrow">{html.escape(number)}</span>'
            f'<h3>{html.escape(title)}</h3><p>{html.escape(description)}</p></article>'
            for number, title, description in text['features']
        )
        + '</div></section>'
    )
    if language == "en" and re.search(r"[А-Яа-яЁё]", body):
        raise BuildError("English home page contains untranslated Cyrillic text")

    return shell(page, language, text["index_title"], body, base_url)


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
            f'<a class="document-index-item" href="{prefix}{item}"><span class="document-index-number">{index:02d}</span>'
            f'<span>{html.escape(label(item))}</span>'
            '<span class="document-index-arrow" aria-hidden="true">↗</span></a>'
            for index, item in enumerate(items, 1)
        ) + '</div>'

    body = (
        f'<h1>{html.escape(text["documents"])}</h1><p>{html.escape(text["documents_lead"])}</p>'
        f'<h2 id="policies">{html.escape(text["policies"])}</h2>{links(MENU[language])}'
        f'<h2 id="technical">{html.escape(text["technical"])}</h2>{links(extra)}'
    )
    return shell(page, language, text["documents"], body, base_url)


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
