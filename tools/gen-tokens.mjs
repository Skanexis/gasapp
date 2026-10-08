#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// UI kit → design/gasapp.tokens.json → Swift / Kotlin / CSS.
//
// Зачем генерировать, а не переписывать руками:
// UI kit — источник правды по дизайну (раздел 20 плана). Скопированные
// вручную значения расходятся с оригиналом через месяц, и расхождение
// незаметно: цвет «почти тот же». Генерация делает расхождение
// невозможным, а CI проверяет, что сгенерированное совпадает
// с закоммиченным.
//
// Запуск:  node tools/gen-tokens.mjs [--check]
//   --check  не писать файлы, а сравнить с существующими (режим для CI)

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const UI_KIT = join(ROOT, "design", "secure-messenger-ui-kit.html");
const OUT_JSON = join(ROOT, "design", "gasapp.tokens.json");
const OUT_DIR = join(ROOT, "design", "generated");

const checkOnly = process.argv.includes("--check");

// --- Разбор CSS-переменных из блока :root -----------------------------------

const html = readFileSync(UI_KIT, "utf8");
const rootMatch = html.match(/:root\s*\{([\s\S]*?)\}/);
if (!rootMatch) {
  console.error("не найден блок :root в UI kit");
  process.exit(1);
}

const cssVars = new Map();
for (const [, name, value] of rootMatch[1].matchAll(/--([a-z0-9-]+)\s*:\s*([^;]+);/g)) {
  cssVars.set(name, value.trim());
}

function css(name) {
  const value = cssVars.get(name);
  if (value === undefined) {
    console.error(`переменная --${name} отсутствует в UI kit`);
    process.exit(1);
  }
  return value;
}

// --- Модель токенов ---------------------------------------------------------
//
// Имена намеренно семантические (`text.primary`), а не примитивные
// (`gray.100`): раздел 20.1 плана требует, чтобы дизайнер и разработчик
// говорили о роли цвета, а не о его оттенке.

const tokens = {
  $schema: "https://design-tokens.github.io/community-group/format/",
  $description:
    "Design tokens GasApp. Сгенерировано из design/secure-messenger-ui-kit.html — не редактировать вручную.",
  color: {
    bg: {
      base: css("bg"),
      raised: css("bg2"),
      card: css("card"),
      hover: css("hov"),
    },
    line: css("line"),
    text: {
      primary: css("tx"),
      secondary: css("tx2"),
      muted: css("tx3"),
      disabled: css("tx4"),
    },
    accent: {
      base: css("ac"),
      hover: css("ac-h"),
      pressed: css("ac-p"),
      on: css("on-ac"),
      dim: css("ac-dim"),
      line: css("ac-lin"),
    },
    status: {
      success: css("ok"),
      warning: css("warn"),
      error: css("err"),
      info: css("info"),
      successDim: css("ok-dim"),
      warningDim: css("warn-dim"),
      errorDim: css("err-dim"),
    },
  },
  radius: {
    input: parseInt(css("r-inp"), 10),
    button: parseInt(css("r-btn"), 10),
    card: parseInt(css("r-card"), 10),
    sheet: parseInt(css("r-sheet"), 10),
  },
  // 8-точечная сетка; 4 — единственный микрошаг (раздел 20.1)
  space: [4, 8, 16, 24, 32, 40, 48, 64],
  motion: { fast: 150, base: 200, slow: 250, ease: "cubic-bezier(0, 0, .2, 1)" },
  size: {
    buttonSmall: 40,
    buttonMedium: 48,
    buttonLarge: 56,
    input: 48,
    listRowMin: 64,
    listRowMax: 72,
    avatar: [40, 48, 64, 88],
    icon: [16, 20, 24, 32],
    touchTarget: 48,
    screenMargin: 16,
  },
  typography: {
    display: { size: 32, lineHeight: 40, weight: 700 },
    h1: { size: 28, lineHeight: 36, weight: 700 },
    h2: { size: 24, lineHeight: 32, weight: 600 },
    h3: { size: 20, lineHeight: 28, weight: 600 },
    h4: { size: 17, lineHeight: 24, weight: 600 },
    body: { size: 15, lineHeight: 22, weight: 400 },
    caption: { size: 13, lineHeight: 18, weight: 400 },
    button: { size: 15, lineHeight: 16, weight: 600 },
    label: { size: 12, lineHeight: 16, weight: 600 },
  },
};

// --- Вспомогательное --------------------------------------------------------

/** Преобразует CSS-цвет в компоненты RGBA 0..1 для Swift и Compose. */
function parseColor(value) {
  const hex = value.match(/^#([0-9a-fA-F]{6})$/);
  if (hex) {
    const n = parseInt(hex[1], 16);
    return { r: (n >> 16) & 255, g: (n >> 8) & 255, b: n & 255, a: 1 };
  }
  const rgba = value.match(/^rgba?\(([^)]+)\)$/);
  if (rgba) {
    const parts = rgba[1].split(",").map((p) => p.trim());
    return {
      r: Number(parts[0]),
      g: Number(parts[1]),
      b: Number(parts[2]),
      a: parts[3] === undefined ? 1 : Number(parts[3]),
    };
  }
  console.error(`не удалось разобрать цвет: ${value}`);
  process.exit(1);
}

/** Все цвета в виде плоского списка [путь, значение]. */
function flatColors(node = tokens.color, prefix = []) {
  const out = [];
  for (const [key, value] of Object.entries(node)) {
    if (typeof value === "string") {
      out.push([[...prefix, key], value]);
    } else {
      out.push(...flatColors(value, [...prefix, key]));
    }
  }
  return out;
}

const camel = (parts) =>
  parts
    .map((p, i) => (i === 0 ? p : p.charAt(0).toUpperCase() + p.slice(1)))
    .join("");

const HEADER_NOTE = [
  "Сгенерировано tools/gen-tokens.mjs из design/secure-messenger-ui-kit.html.",
  "НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ — правки будут затёрты при следующей генерации.",
  "Источник правды по дизайну — UI kit (раздел 20 плана).",
];

// --- Swift ------------------------------------------------------------------

function renderSwift() {
  const lines = [
    "// SPDX-License-Identifier: Apache-2.0",
    ...HEADER_NOTE.map((l) => `// ${l}`),
    "",
    "import SwiftUI",
    "",
    "/// Дизайн-токены GasApp.",
    "public enum GasAppTokens {",
    "",
    "    // MARK: - Colors",
    "",
    "    public enum Color {",
  ];

  for (const [path, value] of flatColors()) {
    const { r, g, b, a } = parseColor(value);
    lines.push(
      `        /// \`${value}\``,
      `        public static let ${camel(path)} = SwiftUI.Color(` +
        `.sRGB, red: ${(r / 255).toFixed(4)}, green: ${(g / 255).toFixed(4)}, ` +
        `blue: ${(b / 255).toFixed(4)}, opacity: ${a})`,
    );
  }

  lines.push("    }", "", "    // MARK: - Radius", "", "    public enum Radius {");
  for (const [key, value] of Object.entries(tokens.radius)) {
    lines.push(`        public static let ${key}: CGFloat = ${value}`);
  }

  lines.push("    }", "", "    // MARK: - Spacing", "", "    public enum Space {");
  for (const value of tokens.space) {
    lines.push(`        public static let s${value}: CGFloat = ${value}`);
  }

  lines.push("    }", "", "    // MARK: - Motion", "", "    public enum Motion {");
  lines.push(`        public static let fast: Double = ${tokens.motion.fast / 1000}`);
  lines.push(`        public static let base: Double = ${tokens.motion.base / 1000}`);
  lines.push(`        public static let slow: Double = ${tokens.motion.slow / 1000}`);
  lines.push("        /// Единственная кривая системы — ease out.");
  lines.push("        public static let ease = SwiftUI.Animation.timingCurve(0, 0, 0.2, 1)");

  lines.push("    }", "", "    // MARK: - Typography", "", "    public enum Typography {");
  for (const [key, t] of Object.entries(tokens.typography)) {
    lines.push(
      `        public static let ${key} = (size: CGFloat(${t.size}), ` +
        `lineHeight: CGFloat(${t.lineHeight}), weight: Font.Weight.${swiftWeight(t.weight)})`,
    );
  }

  lines.push("    }", "", "    // MARK: - Sizes", "", "    public enum Size {");
  for (const [key, value] of Object.entries(tokens.size)) {
    if (Array.isArray(value)) {
      lines.push(`        public static let ${key}: [CGFloat] = [${value.join(", ")}]`);
    } else {
      lines.push(`        public static let ${key}: CGFloat = ${value}`);
    }
  }
  lines.push("    }", "}", "");

  return lines.join("\n");
}

function swiftWeight(w) {
  return { 400: "regular", 500: "medium", 600: "semibold", 700: "bold" }[w] ?? "regular";
}

// --- Kotlin -----------------------------------------------------------------

function renderKotlin() {
  const lines = [
    "// SPDX-License-Identifier: Apache-2.0",
    ...HEADER_NOTE.map((l) => `// ${l}`),
    "",
    "package org.gasapp.ui.theme",
    "",
    "import androidx.compose.ui.graphics.Color",
    "import androidx.compose.ui.text.font.FontWeight",
    "import androidx.compose.ui.unit.dp",
    "import androidx.compose.ui.unit.sp",
    "",
    "/** Дизайн-токены GasApp. */",
    "object GasAppTokens {",
    "",
    "    object Colors {",
  ];

  for (const [path, value] of flatColors()) {
    const { r, g, b, a } = parseColor(value);
    const argb =
      (Math.round(a * 255) << 24) | (r << 16) | (g << 8) | b;
    const hex = (argb >>> 0).toString(16).toUpperCase().padStart(8, "0");
    lines.push(`        /** \`${value}\` */`, `        val ${camel(path)} = Color(0x${hex})`);
  }

  lines.push("    }", "", "    object Radius {");
  for (const [key, value] of Object.entries(tokens.radius)) {
    lines.push(`        val ${key} = ${value}.dp`);
  }

  lines.push("    }", "", "    object Space {");
  for (const value of tokens.space) {
    lines.push(`        val s${value} = ${value}.dp`);
  }

  lines.push("    }", "", "    object Motion {");
  lines.push(`        const val FAST_MS = ${tokens.motion.fast}`);
  lines.push(`        const val BASE_MS = ${tokens.motion.base}`);
  lines.push(`        const val SLOW_MS = ${tokens.motion.slow}`);

  lines.push("    }", "", "    object Typography {");
  for (const [key, t] of Object.entries(tokens.typography)) {
    lines.push(
      `        val ${key} = TypeStyle(${t.size}.sp, ${t.lineHeight}.sp, FontWeight(${t.weight}))`,
    );
  }

  lines.push("    }", "", "    object Size {");
  for (const [key, value] of Object.entries(tokens.size)) {
    if (Array.isArray(value)) {
      lines.push(`        val ${key} = listOf(${value.map((v) => `${v}.dp`).join(", ")})`);
    } else {
      lines.push(`        val ${key} = ${value}.dp`);
    }
  }
  lines.push("    }", "}", "");

  lines.push(
    "",
    "/** Типографический стиль: размер, интерлиньяж, начертание. */",
    "data class TypeStyle(",
    "    val size: androidx.compose.ui.unit.TextUnit,",
    "    val lineHeight: androidx.compose.ui.unit.TextUnit,",
    "    val weight: FontWeight,",
    ")",
    "",
  );

  return lines.join("\n");
}

// --- CSS --------------------------------------------------------------------

function renderCss() {
  const lines = [
    "/* SPDX-License-Identifier: Apache-2.0",
    ...HEADER_NOTE.map((l) => `   ${l}`),
    "*/",
    ":root {",
  ];
  for (const [path, value] of flatColors()) {
    lines.push(`  --gasapp-${path.join("-")}: ${value};`);
  }
  for (const [key, value] of Object.entries(tokens.radius)) {
    lines.push(`  --gasapp-radius-${key}: ${value}px;`);
  }
  for (const value of tokens.space) {
    lines.push(`  --gasapp-space-${value}: ${value}px;`);
  }
  lines.push("}", "");
  return lines.join("\n");
}

// --- Запись или проверка ----------------------------------------------------

const outputs = [
  [OUT_JSON, `${JSON.stringify(tokens, null, 2)}\n`],
  [join(OUT_DIR, "GasAppTokens.swift"), renderSwift()],
  [join(OUT_DIR, "GasAppTokens.kt"), renderKotlin()],
  [join(OUT_DIR, "tokens.css"), renderCss()],
];

if (!checkOnly) mkdirSync(OUT_DIR, { recursive: true });

let stale = 0;
for (const [path, content] of outputs) {
  if (checkOnly) {
    const current = existsSync(path) ? readFileSync(path, "utf8") : null;
    if (current !== content) {
      console.error(`устарел: ${path}`);
      stale++;
    }
  } else {
    writeFileSync(path, content, "utf8");
    console.log(`записан: ${path}`);
  }
}

if (checkOnly) {
  if (stale > 0) {
    console.error(
      `\n${stale} файл(ов) не соответствуют UI kit. Запустите: node tools/gen-tokens.mjs`,
    );
    process.exit(1);
  }
  console.log("токены соответствуют UI kit");
} else {
  console.log(`\nцветов: ${flatColors().length}, переменных прочитано из UI kit: ${cssVars.size}`);
}
