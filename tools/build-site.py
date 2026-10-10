#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Собирает публичный сайт документов GasApp из Markdown.

    python tools/build-site.py [--out site] [--base-url https://gasapp.chat]

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
    "privacy/": "ru/privacy/",
    "terms/": "ru/terms/",
    "community-guidelines/": "ru/community-guidelines/",
    "child-safety/": "ru/child-safety/",
    "account-deletion/": "ru/account-deletion/",
    "support/": "ru/support/",
    "": "ru/",
}
TWIN.update({ru: en for en, ru in list(TWIN.items())})

STYLE = """
:root{--bg:#fbfaf7;--ink:#1b1d22;--soft:#5a6070;--line:#dcd9d0;--accent:#0b5cad;--card:#fff;--code:#f1efe8}
@media (prefers-color-scheme:dark){:root{--bg:#14161b;--ink:#e9e7e1;--soft:#a2a8b6;--line:#2c313b;--accent:#7db7ff;--card:#1b1e25;--code:#22262f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:17px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header,main,footer{max-width:46rem;margin:0 auto;padding:0 16px}
header{padding-top:20px;padding-bottom:12px;border-bottom:1px solid var(--line)}
header .brand{font-weight:700;font-size:1.15rem;color:var(--ink);text-decoration:none}
nav{margin-top:8px;display:flex;flex-wrap:wrap;gap:4px 16px;font-size:.92rem}
nav a{color:var(--soft);text-decoration:none}
nav a[aria-current]{color:var(--ink);font-weight:600}
nav a:hover,a:hover{text-decoration:underline}
main{padding-top:8px;padding-bottom:48px}
h1{font-size:1.9rem;line-height:1.2;margin:1.4rem 0 .6rem}
h2{font-size:1.35rem;margin:2rem 0 .5rem;padding-top:.4rem;border-top:1px solid var(--line)}
h3{font-size:1.1rem;margin:1.5rem 0 .4rem}
h4{font-size:1rem;margin:1.2rem 0 .3rem}
a{color:var(--accent)}
p,ul,ol,blockquote,pre,.table{margin:.7rem 0}
ul,ol{padding-left:1.4rem}
li{margin:.25rem 0}
blockquote{margin-left:0;padding:.2rem 1rem;border-left:4px solid var(--line);color:var(--soft)}
code{background:var(--code);padding:.1em .3em;border-radius:4px;font:0.9em ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere}
pre{background:var(--code);padding:12px 14px;border-radius:8px;overflow-x:auto}
pre code{background:none;padding:0}
.table{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.93rem}
th,td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}
th{background:var(--card)}
hr{border:0;border-top:1px solid var(--line);margin:2rem 0}
footer{padding-top:16px;padding-bottom:40px;border-top:1px solid var(--line);color:var(--soft);font-size:.88rem}
.cards{list-style:none;padding:0;display:grid;gap:10px}
.cards a{display:block;padding:12px 14px;background:var(--card);border:1px solid var(--line);border-radius:10px;text-decoration:none;color:var(--ink);font-weight:600}
"""

TEXT = {
    "en": {
        "tagline": "Encrypted messenger. Open source.",
        "documents": "Documents",
        "more": "More",
        "other": "Русский",
        "footer": "GasApp is open source. This site is generated from the documents in the repository.",
        "index_title": "GasApp — documents",
        "index_lead": "GasApp is an end-to-end encrypted messenger with channels. "
        "These are the documents that describe what it does with your data and what the rules are.",
    },
    "ru": {
        "tagline": "Мессенджер со сквозным шифрованием. Открытый код.",
        "documents": "Документы",
        "more": "Ещё",
        "other": "English",
        "footer": "Код GasApp открыт. Сайт собран из документов в репозитории.",
        "index_title": "GasApp — документы",
        "index_lead": "GasApp — мессенджер со сквозным шифрованием и каналами. "
        "Здесь документы о том, что он делает с вашими данными и какие действуют правила.",
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
        menu += f'<a href="{up}{twin}" hreflang="{"ru" if language == "en" else "en"}">{text["other"]}</a>'

    canonical = f'<link rel="canonical" href="{base_url.rstrip("/")}/{page}">' if base_url else ""

    return f"""<!doctype html>
<html lang="{language}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} — GasApp</title>
<meta name="description" content="{html.escape(title)} — GasApp. {html.escape(text["tagline"])}">
{canonical}
<style>{STYLE}</style>
</head>
<body>
<header>
<a class="brand" href="{up}{home}">GasApp</a>
<nav aria-label="{text["documents"]}">{menu}</nav>
</header>
<main>
{body}
</main>
<footer>{text["footer"]}</footer>
</body>
</html>
"""


def index_page(language, base_url):
    text = TEXT[language]
    page = "" if language == "en" else "ru/"
    extra = [item for item, entry in PAGES.items() if entry[2] == language and item not in MENU[language]]
    # Документы, написанные только на одном языке, видны с обеих страниц.
    if language == "en":
        extra += ["ru/data-retention/", "ru/bots/"]
    else:
        extra += ["protocol/", "encryption/"]

    def cards(items):
        prefix = "" if language == "en" else "../"
        return "".join(
            f'<li><a href="{prefix}{item}">{html.escape(PAGES[item][3])}</a></li>' for item in items
        )

    body = (
        f"<h1>{text['index_title']}</h1><p>{text['index_lead']}</p>"
        f"<h2>{text['documents']}</h2><ul class=\"cards\">{cards(MENU[language])}</ul>"
        f"<h2>{text['more']}</h2><ul class=\"cards\">{cards(extra)}</ul>"
    )

    return shell(page, language, text["index_title"], body, base_url)


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
            f"<url><loc>{base_url.rstrip('/')}/{page}</loc></url>" for page in ["", "ru/", *PAGES]
        )
        (out / "sitemap.xml").write_text(
            f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>\n',
            encoding="utf-8",
            newline="\n",
        )
    # GitHub Pages: не обрабатывать сайт Jekyll'ом (иначе пропадёт .well-known).
    (out / ".nojekyll").write_text("", encoding="utf-8")

    return len(PAGES) + 2


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default="site")
    parser.add_argument("--base-url", default="https://gasapp.chat")
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
