#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// UI kit → design/icons/ (extracted SVG symbols).
//
// Зачем извлекать, а не копировать руками:
// UI kit — источник правды по дизайну (раздел 20 плана). Скопированные
// вручную символы расходятся с оригиналом через месяц, и расхождение
// незаметно: путь «почти тот же». Извлечение делает расхождение
// невозможным, а CI проверяет, что извлечённое совпадает
// с закоммиченным.
//
// Запуск:  node tools/extract-icons.mjs [--check]
//   --check  не писать файлы, а сравнить с существующими (режим для CI)

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const UI_KIT = join(ROOT, "design", "secure-messenger-ui-kit.html");
const ICONS_DIR = join(ROOT, "design", "icons");

const checkOnly = process.argv.includes("--check");

if (!existsSync(ICONS_DIR)) {
  mkdirSync(ICONS_DIR, { recursive: true });
}

// --- Извлечение всех символов <symbol id="..."> ------------------------------

const html = readFileSync(UI_KIT, "utf8");

// Находим все символы с их содержимым
const symbolMatches = html.matchAll(/<symbol\s+id="([^"]+)"[^>]*>[\s\S]*?<\/symbol>/g);
const symbols = Array.from(symbolMatches, match => ({
  id: match[1],
  full: match[0]
}));

console.log(`Найдено ${symbols.length} символов в UI kit`);

// Нормализация: замена жёстко заданных fill/stroke на currentColor
function normalizeSymbolContent(content) {
  // Заменяем fill="знaчение" на fill="currentColor"
  // Заменяем stroke="знaчение" на stroke="currentColor"
  // Но оставляем fill="none" и stroke="none" как есть
  return content
    .replace(/fill\s*=\s*"(#[^"]*|rgb\([^)]*\)|hsl\([^)]*\)|[a-zA-Z]+)"/g, 'fill="currentColor"')
    .replace(/stroke\s*=\s*"(#[^"]*|rgb\([^)]*\)|hsl\([^)]*\)|[a-zA-Z]+)"/g, 'stroke="currentColor"')
    .replace(/fill\s*=\s*'(#[^']*|rgb\([^)]*\)|hsl\([^)]*\)|[a-zA-Z]+)'/g, "fill='currentColor'")
    .replace(/stroke\s*=\s*'(#[^']*|rgb\([^)]*\)|hsl\([^)]*\)|[a-zA-Z]+)'/g, "stroke='currentColor'");
}

// Проверяем или извлекаем символы
if (checkOnly) {
  // Режим проверки: сравниваем с существующими файлами
  let allGood = true;

  for (const { id, full } of symbols) {
    const normalized = normalizeSymbolContent(full);
    const fileName = `${id}.svg`; // IDs already appear to be in kebab-case
    const filePath = join(ICONS_DIR, fileName);

    if (existsSync(filePath)) {
      const existing = readFileSync(filePath, "utf8");
      if (existing !== normalized) {
        console.error(`��❌ Расхождение в ${fileName}:`);
        console.error(`  Ожидается:\n${normalized}`);
        console.error(`  Существует:\n${existing}`);
        allGood = false;
      }
    } else {
      console.error(`��❌ Файл не найден: ${fileName}`);
      allGood = false;
    }
  }

  if (allGood) {
    console.log("��✅ Все символы соответствуют ожидаемым");
    process.exit(0);
  } else {
    console.log("��❌ Обнаружены расхождения");
    process.exit(1);
  }
} else {
  // Режим извлечения: создаём/обновляем файлы
  for (const { id, full } of symbols) {
    const normalized = normalizeSymbolContent(full);
    const fileName = `${id}.svg`; // IDs already appear to be in kebab-case
    const filePath = join(ICONS_DIR, fileName);

    writeFileSync(filePath, normalized, "utf8");
    console.log(`��✅ Извлечён: ${fileName}`);
  }

  console.log(`\nИзвлечено ${symbols.length} символов в ${ICONS_DIR}`);
}
