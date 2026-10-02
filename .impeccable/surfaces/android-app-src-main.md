---
version: 1
slug: "android-app-src-main"
primary_target: "android/app/src/main"
related_targets: []
---

# Android app — core screens

Scope: lock (PIN), chat list, chat, onboarding (registration), security center.
Mode: Operate. Audience: people at risk (journalists, activists, censored networks), dark rooms, often waiting on Tor.
Constraints: keep the kit's dark theme; no "hacker" look (no neon terminals, skulls, matrix green); palette may change; Material/Android conventions stay (system Back, 48dp targets, sp type, Remove-animations honored); no new heavy dependencies — platform APIs only; must stay smooth on weak phones.

## Direction contract

THESIS: AEGIS is a security document you carry, not a terminal. The screens borrow the grammar of intaglio security printing (passports, banknotes): fine-line guilloche, deep printing inks, one luminous ink for action. It refuses the category default of near-black plus a single neon cyan.

OWN-WORLD: ground of deep ink-navy (not black) in tonal steps; one periwinkle "ink" accent for action and outgoing speech; status inks green / amber / red kept semantic; a fine-line guilloche rosette drawn in code as the brand mark (hairline strokes, low alpha), never as decoration on every surface — on lock, onboarding welcome, empty chat list, security center only. Inter for all text.

STORY: the person opens the app and meets the seal; entering the PIN visibly turns it; the seal opens into their conversations. In the list they always see how they are connected (Tor / direct). In the chat their words are ink on paper. The security center shows protection as the seal itself: each check is one ring of the rosette, inked when passed.

FIRST VIEWPORT: lock screen — rosette ~260dp centered in the upper half, PIN dots on its horizontal axis inside it, title above, keypad below without key backgrounds, "Forgot PIN" quiet at the bottom.

SIGNATURE INTERACTION: each digit turns the rosette one notch (spring); a correct PIN opens it (scale-out + fade) into the chat list; a wrong PIN shakes it and tints its strokes red for a beat. Motion is skipped when the system disables animations.

FORM: refinement of the incumbent kit world raised to an own world ("intaglio"); position 1 of own list; seed key: none (established-world refinement, code-led, no image generation).

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
