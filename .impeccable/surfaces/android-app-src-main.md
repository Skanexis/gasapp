---
version: 1
slug: "android-app-src-main"
primary_target: "android/app/src/main"
related_targets: []
---
# Android app — core screens

Scope: onboarding (welcome, username + email, PIN, email code), lock (PIN), chat list, chat, channels list, channel, security center.

Mode: Operate. Audience: people who message and follow channels on a phone, often waiting on Tor; the app may be inspected by someone else.

Constraints: always dark; Material/Android conventions stay (system Back, 48dp targets, sp type, Remove-animations honoured); no new heavy dependencies — platform APIs only; must stay smooth on weak phones; no "hacker" look; the interface holds no keys and does no cryptography; nothing on screen may promise what the product lacks (calls, voice, groups, push, an independent audit).

## Direction contract

THESIS: GasApp is a night camp, not a terminal and not a casino. A clearing under a starry indigo sky, with one warm thing that glows — gold. The owner's reference (cartoon night forest, chunky yellow-orange 3D lettering with a red-brown outline) sets the world; the owner's decision "game accent" sets how far it goes.

OWN-WORLD: night-indigo ground in tonal steps; Camp Gold as the single action colour with dark-brown text; a chunky bottom edge on the primary action only; a code-drawn night scene and a sign-painted wordmark on entry surfaces (welcome, lock, empty top-level lists); Rubik Black for signs, Inter for reading. Conversations, channel feeds and settings stay flat and calm in the same palette. Status colours green / orange / red stay semantic.

STORY: the person arrives at the camp (welcome scene with the wordmark, later the owner's mascot), names themselves and gives an email, sets a PIN, goes to fetch the code from their mail and is brought back to the same step. Inside, the bottom bar shows where they are in gold; chats and channels read calmly; empty lists show the clearing and a gold token for what is missing. Coming back, the night sky sits behind the PIN and the gold medallion turns with each digit.

FIRST VIEWPORT: welcome — full-bleed night scene 232dp with the tilted wordmark, heading, three plain promises, the audit warning, a chunky gold "Create account".

SIGNATURE INTERACTION: the primary button is a physical thing — a gold face on a darker lip that sinks 3dp under the finger. On the lock screen the medallion still turns a notch per digit and opens on a correct PIN.

FORM: replacement world ("Night Camp") for the incumbent "Intaglio Document", by the owner's brief and reference image, 2026-10-07; scope chosen by the owner: "game accent". Code-led: scene and wordmark are drawn in code; the mascot and optional raster art come from the owner (`design/art/README.md`).

FINISH: built and inspected on the emulator in two bounded rounds (2026-10-08, phone, EN and RU): welcome, username + email, PIN, code, chats empty, channels empty and filled, premium notice, create-channel dialog, channel with a post, share dialog, lock. Not inspected: tablet, font scale 1.3, security center, settings. The finish review subagent was not run; DESIGN.md is written by hand and its sidecar (`.impeccable/design.json`) still needs regenerating with `/impeccable document`.
