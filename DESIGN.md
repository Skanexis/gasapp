---
name: GasApp
description: Encrypted messenger staged as a night camp - indigo starry ground, one gold action colour with a chunky bottom edge, a code-drawn pine clearing and a sign-painted wordmark on the entry surfaces only.
colors:
  night-indigo: "#0E1238"
  night-raised: "#141A4A"
  night-card: "#1B2259"
  night-hover: "#252E70"
  hairline: "#343E85"
  star-white: "#F5F6FF"
  text-secondary: "#C2C8F0"
  text-muted: "#A3ABDD"
  text-disabled: "#6670AD"
  camp-gold: "#FFCB2E"
  camp-gold-hover: "#FFDA66"
  camp-gold-pressed: "#F0A800"
  on-gold: "#2B1600"
  gold-edge: "#B86A00"
  gold-edge-deep: "#7A2E00"
  camp-gold-dim: "rgba(255,203,46,0.14)"
  camp-gold-line: "rgba(255,203,46,0.40)"
  own-bubble: "#3A45B8"
  own-bubble-meta: "#D5DAFF"
  verified-green: "#4ADE94"
  caution-orange: "#FF9A4D"
  alarm-red: "#FF7A85"
  info-sky: "#7FB8FF"
  verified-green-dim: "rgba(74,222,148,0.13)"
  caution-orange-dim: "rgba(255,154,77,0.13)"
  alarm-red-dim: "rgba(255,122,133,0.13)"
typography:
  display:
    fontFamily: "Rubik, sans-serif"
    fontSize: "32px"
    fontWeight: 900
    lineHeight: "40px"
  headline:
    fontFamily: "Rubik, sans-serif"
    fontSize: "28px"
    fontWeight: 900
    lineHeight: "36px"
  headline-sm:
    fontFamily: "Inter, sans-serif"
    fontSize: "24px"
    fontWeight: 600
    lineHeight: "32px"
  title:
    fontFamily: "Inter, sans-serif"
    fontSize: "20px"
    fontWeight: 600
    lineHeight: "28px"
  title-sm:
    fontFamily: "Inter, sans-serif"
    fontSize: "17px"
    fontWeight: 600
    lineHeight: "24px"
  body:
    fontFamily: "Inter, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: "22px"
  caption:
    fontFamily: "Inter, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: "18px"
  button:
    fontFamily: "Rubik, sans-serif"
    fontSize: "15px"
    fontWeight: 700
    lineHeight: "16px"
  label:
    fontFamily: "Inter, sans-serif"
    fontSize: "12px"
    fontWeight: 600
    lineHeight: "16px"
  mono:
    fontFamily: "monospace"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: "22px"
rounded:
  input: "12px"
  button: "14px"
  card: "16px"
  composer: "22px"
  sheet: "24px"
  bubble-tail: "6px"
spacing:
  xs: "4px"
  s: "8px"
  m: "16px"
  l: "24px"
  xl: "32px"
  2xl: "40px"
  3xl: "48px"
  4xl: "64px"
components:
  button-primary:
    backgroundColor: "{colors.camp-gold}"
    textColor: "{colors.on-gold}"
    typography: "{typography.button}"
    rounded: "{rounded.button}"
    padding: "0 24px 4px"
    height: "48px"
  button-primary-hover:
    backgroundColor: "{colors.camp-gold-hover}"
    textColor: "{colors.on-gold}"
  button-primary-pressed:
    backgroundColor: "{colors.camp-gold-pressed}"
    textColor: "{colors.on-gold}"
  button-secondary:
    backgroundColor: "{colors.night-card}"
    textColor: "{colors.star-white}"
    typography: "{typography.button}"
    rounded: "{rounded.button}"
    padding: "0 24px"
    height: "48px"
  button-ghost:
    textColor: "{colors.camp-gold}"
    typography: "{typography.button}"
    rounded: "{rounded.button}"
    padding: "0 24px"
    height: "48px"
  input:
    backgroundColor: "{colors.night-card}"
    textColor: "{colors.star-white}"
    typography: "{typography.body}"
    rounded: "{rounded.input}"
    padding: "12px 16px"
    height: "48px"
  composer:
    backgroundColor: "{colors.night-card}"
    textColor: "{colors.star-white}"
    typography: "{typography.body}"
    rounded: "{rounded.composer}"
  bubble-outgoing:
    backgroundColor: "{colors.own-bubble}"
    textColor: "{colors.star-white}"
    typography: "{typography.body}"
    rounded: "{rounded.card}"
    width: "280px"
  bubble-incoming:
    backgroundColor: "{colors.night-card}"
    textColor: "{colors.star-white}"
    typography: "{typography.body}"
    rounded: "{rounded.card}"
    width: "280px"
  channel-post:
    backgroundColor: "{colors.night-card}"
    textColor: "{colors.star-white}"
    typography: "{typography.body}"
    rounded: "{rounded.card}"
    padding: "12px 16px 10px"
  card:
    backgroundColor: "{colors.night-card}"
    rounded: "{rounded.card}"
    padding: "16px"
  sheet:
    backgroundColor: "{colors.night-raised}"
    rounded: "{rounded.sheet}"
  pill-ok:
    backgroundColor: "{colors.verified-green-dim}"
    textColor: "{colors.verified-green}"
    rounded: "12px"
    padding: "0 10px"
    height: "24px"
  pill-warn:
    backgroundColor: "{colors.caution-orange-dim}"
    textColor: "{colors.caution-orange}"
    rounded: "12px"
    padding: "0 10px"
    height: "24px"
  pill-error:
    backgroundColor: "{colors.alarm-red-dim}"
    textColor: "{colors.alarm-red}"
    rounded: "12px"
    padding: "0 10px"
    height: "24px"
  nav-tab-selected:
    backgroundColor: "{colors.camp-gold-dim}"
    textColor: "{colors.camp-gold}"
    rounded: "15px"
  list-row:
    padding: "0 16px"
    height: "64px"
---

# Design System: GasApp

## Overview

**Creative North Star: "Night Camp"**

GasApp is a clearing in a pine forest at night: a deep indigo sky full of stars, a moon, dark firs, and one warm thing that glows — gold. The world comes from the owner's reference (a cartoon night-forest scene with chunky yellow-orange 3D lettering outlined in red-brown) and replaces the previous "Intaglio Document" world on 2026-10-07, together with the rename from AEGIS to GasApp.

The owner's decision is **"game accent", not a full game skin.** The camp is staged where a person arrives or waits — onboarding welcome, lock screen, empty top-level lists — and in the controls that carry the primary action: chunky gold buttons with a darker bottom edge that sink when pressed, a gold floating button, a gold token holding the section icon. Conversations, channel feeds and settings stay calm: same palette, flat surfaces, Inter, no scenery. A person reading a message or changing a security setting is not playing.

Three things are still owed by the owner and have slots waiting: the **mascot** (a transparent PNG shown on the welcome scene), optional raster replacements for the code-drawn scene, and the app icon. `design/art/README.md` lists files, sizes and rules. Until they arrive the app is complete without them.

**Key Characteristics:**
- Night-indigo ground in four tonal steps plus a 1dp hairline; never black.
- One action colour, Camp Gold, with dark-brown text on it; status colours green / orange / red keep their security meaning.
- Chunky depth on primary actions only: a 4dp darker bottom edge that collapses on press. Everything else is flat.
- Rubik Black for the wordmark, screen titles and big headings; Rubik Bold for button labels; Inter for everything a person reads; monospace for anything compared character by character.
- A code-drawn night scene (`NightSceneView`) and a sign-painted wordmark (`WordmarkView`) on entry surfaces only.
- Always dark. Motion skipped entirely when the system disables animations.

## Colors

A night-sky palette: blue-violet indigo ground, one gold, three semantic status colours and a sky blue for neutral information. UI tokens are generated from `design/secure-messenger-ui-kit.html` into `design/gasapp.tokens.json` and mirrored in `res/values/colors.xml` (enforced by `DesignTokensTest`). Scene paints live in `NightSceneView` and wordmark paints in `WordmarkView`: they are illustration colours, not interface tokens.

### Primary
- **Camp Gold** (#FFCB2E): the single action colour. Primary buttons, the send button, floating buttons, filled PIN dots, focused-field strokes, cursor, selected tab, the seal's inked rings. 9.7:1 or better on every surface.
- **Gold Hover / Pressed** (#FFDA66 / #F0A800): hover-focus and pressed faces of gold surfaces only.
- **On-Gold Brown** (#2B1600): text and icons on gold. 11.4:1 on Camp Gold, 8.5:1 on the pressed face.
- **Gold Edge** (#B86A00) and **Deep Edge** (#7A2E00): the bottom lip of chunky controls. Not in the token file: they belong to one component, not to the palette.
- **Gold Dim / Line** (14% / 40% alpha): tinted backplates (selected tab pill, connecting strip, focus halo) and the focused composer stroke.

### Secondary
- **Own Bubble Indigo** (#3A45B8): the fill of the person's own outgoing messages, with Star White text (7.2:1) and #D5DAFF meta (5.6:1). Brighter than every surface so the side of the conversation reads without a label, and deliberately not gold.

### Tertiary (status)
- **Verified Green** (#4ADE94): "verified / passed" only.
- **Caution Orange** (#FF9A4D): "needs attention" and direct (non-Tor) connection. Moved from amber to orange so it can never be read as the gold action colour.
- **Alarm Red** (#FF7A85): errors, wrong PIN, destructive actions. At least 4.9:1 on every surface.
- **Info Sky** (#7FB8FF): neutral information. It was the accent in the previous world; it is now its own colour.
- Each status colour has a 13% dim variant used only as the backplate of its own pill or notice.

### Neutral
- **Night Indigo** (#0E1238): window, app bar, status and navigation bars.
- **Raised Indigo** (#141A4A): sheets, panels, bottom navigation, channel header and composer row.
- **Card Indigo** (#1B2259): cards, grouped lists, inputs, incoming bubbles, channel posts, secondary buttons, dialogs.
- **Hover Indigo** (#252E70): ripples, keypad press halos, the seal track.
- **Hairline** (#343E85): 1dp strokes on cards, inputs, sheets and dividers; empty PIN dots.
- **Star White** (#F5F6FF): primary text.
- **Secondary Text** (#C2C8F0): subtitles, previews, captions. At least 7.5:1 on every surface.
- **Muted Text** (#A3ABDD): time stamps, hints, group headers. At least 5.5:1 even on Hover Indigo.
- **Disabled Text** (#6670AD): disabled controls only; never for readable text.

### Scene paints (illustration, not tokens)
Sky #070A26 → #141F66 → #2A3F9E at the horizon; stars #F5F6FF; moon #F4F7FF shading to #A9B8E8 with a soft glow; far firs #123D3A, near firs #0A2422; clearing #2C7A2F darkening to #0F331C. Wordmark fill #FFEE7A → #FFCB2E → #FF9A1F, outline #4A1600, extruded edge #7A2E00.

### Avatar colours
Six colours assigned by name hash, drawn as initials over a 16% fill of the same colour. Set in code (`ui/Avatars.kt`), not tokens. They never include green, orange or red.

### Named Rules
**The One Gold Rule.** Camp Gold is the only action colour. If something is tappable and primary, it is gold; if it is not, it is not gold. Gold never fills a reading surface: not a message bubble, not a channel post, not a card.

**The Semantic Colours Rule.** Green means verified, orange means attention, red means error or danger. They never decorate. The forest in the scene is green, which is why the scene never sits next to a status icon.

**The Indigo Not Black Rule.** The ground is Night Indigo in tonal steps. Pure black appears only as the camera scrim on the QR scanner.

## Typography

**Display Font:** Rubik 900 and 700 (bundled in `res/font`, subset to Latin and Cyrillic, SIL OFL 1.1 — `design/fonts/Rubik-OFL.txt`)
**Body Font:** Inter 400 / 600 / 700 (bundled)
**Mono Font:** platform monospace, for safety numbers, keys, the recovery key, channel links and the email code

**Character:** A compact, rounded heavy grotesque does the signage — it is the closest bundled voice to the reference's chunky lettering that also carries Cyrillic at the same weight and stays narrow enough for Russian headings. A sober grotesque does the reading. The two never swap: Rubik is never body text, Inter is never a screen title.

### Hierarchy
- **Display** (Rubik 900, 32/40sp): reserved.
- **Headline** (Rubik 900, 28/36sp): top-level screen titles (Chats, Channels, Contacts, Settings), onboarding step titles, the lock title.
- **Headline Small** (Inter 600, 24/32sp): section titles inside flows. The welcome heading and empty-state titles take Rubik 900 at this and the next size down.
- **Title** (Inter 600, 20/28sp) and **Title Small** (Inter 600, 17/24sp): nested app-bar titles, card headings, contact and channel names.
- **Body** (Inter 400, 15/22sp): messages, channel posts, descriptions, inputs. Bubbles cap at 280dp wide; channel posts span the feed.
- **Caption** (Inter 400, 13/18sp): previews, notes, helper text, in Secondary or Muted.
- **Button** (Rubik 700, 15sp; 16sp large, 14sp small): sentence case, never all caps.
- **Label** (Inter 600, 12/16sp): group headers and field labels; uppercase with 0.1em tracking in Muted.

### Named Rules
**The Sign And The Letter Rule.** Rubik is for signs: the wordmark, the title of the place you are in, the label on a button. Everything a person reads for its content is Inter.

**The Mono For Verification Rule.** Anything a person compares character by character is monospace, and the style sets both the platform and AppCompat font attributes so the theme font cannot override it.

**The Gradient Belongs To The Wordmark Rule.** The yellow-to-orange fill with a dark outline and an extruded edge exists in exactly one place, `WordmarkView`. Headings and buttons are solid.

## Layout

Single-column phone layout. Screen margin 16dp (24dp inside onboarding); spacing from the 4 / 8 / 16 / 24 / 32 / 40 / 48 / 64dp scale. List rows 64–72dp; touch targets never below 48dp; type in sp. Dialogs cap at 340dp.

The welcome scene is full-bleed: the page carries no side padding, and each block under the scene sets its own. It is 232dp tall so that, in Russian, the audit warning still starts above the fixed buttons on a 6-inch phone.

The chat list carries a connection strip under the app bar whenever the app is not connected through Tor or a proxy: Gold Dim with a 2dp gold progress line while connecting; Raised Indigo with orange text and a full orange rule for a direct connection or blocked Tor.

## Elevation & Depth

Two systems, kept apart.

**Tonal steps** for every surface: Night Indigo ground, Raised Indigo for sheets and bars, Card Indigo for cards, inputs and bubbles, Hover Indigo for press feedback, each edged by a 1dp Hairline. No shadows. Focus adds a 4dp Gold Dim halo plus a 1dp gold stroke.

**The chunky edge** for the primary action only: the gold face sits 4dp above a Gold Edge lip of the same shape; pressing drops the face 3dp so the lip all but disappears. It is drawn with two stacked rounded rectangles (`btn_pri_*`, `bg_fab`, `bg_token`), costs nothing at runtime, and the label is centred on the face, not on the whole control.

### Named Rules
**The One Raised Thing Rule.** On any screen at most one kind of control has the chunky edge: the primary button, or the floating button, or the empty-state token. Secondary, ghost, outline, danger and ok buttons, inputs, cards and list rows are flat.

## Shapes

Gently rounded, tiered by role: inputs 12dp, buttons 14dp, cards, dialogs, channel posts 16dp, floating buttons 18dp, composer 22dp, sheets and the empty-state scene card 24dp. Message bubbles are 16dp with a 6dp tail corner on the speaker's side. Pills are 24dp capsules; avatars, PIN dots, the send button and the token are circles.

## Components

### Buttons
- **Primary:** Camp Gold face, Gold Edge lip, On-Gold Brown label in Rubik 700. Heights 40 / 48 / 56dp including the 4dp lip. Hover and focus lighten the face; pressed darkens it and sinks it. Loading keeps the face and shows a spinner in the label colour.
- **Secondary:** Card Indigo fill, Star White label. **Outline:** transparent with a 1dp Hairline. **Ghost:** gold label, no fill. **Danger / Ok:** status fills, only where the action carries that meaning. All flat, all Rubik 700.
- **Floating button:** 52 × 56dp gold with the same lip, 18dp corners; one per screen (new chat, new channel).

### Night scene (signature)
`components/NightSceneView`: a vertical sky gradient, deterministic stars (the same sky every time), a moon with three craters and a soft glow, two rows of firs and a lit clearing. Geometry is built once per size; a frame is one gradient, at most ninety circles and three paths. Every sixth star twinkles, repainting at most 15 times a second. Options: no moon, sky only, no fade, rounded corners.

- **Welcome:** full-bleed, 232dp, forest and moon, bottom faded into the ground; the wordmark sits in its middle, tilted 4 degrees. When the owner's mascot exists it stands in the clearing and the wordmark moves to the top.
- **Lock:** sky only, no moon, 420dp behind the title and the seal, settling straight into Night Indigo so the PIN dots keep their contrast.
- **Empty top-level lists:** a 216 × 136dp scene card with 24dp corners and the gold token overlapping its bottom edge.
- **Accessibility:** hidden from screen readers; it carries mood only.

### Wordmark
`components/WordmarkView`: the product name in Rubik 900, drawn in code — extruded Deep Edge layers, a dark outline, a yellow-to-orange fill. Sharp at any density and translated with the string. It is the heading of the welcome screen for screen readers.

### Gold token
A 56dp gold circle with the lip, holding the section icon in On-Gold Brown. Marks what an empty list is waiting for (a chat, a channel).

### Seal
The code-drawn rosette (`components/GuillocheView`) survives from the previous world as a **gold medallion** on the lock screen and the security center, where its behaviour carries meaning: each PIN digit turns it a notch, a correct PIN opens it, a wrong PIN shakes it and flashes it red; in the security center each ring is one check. It left the welcome screen and the empty chat list, which now belong to the scene.

### Inputs / Fields
Card Indigo fill, 1dp Hairline, 12dp corners, 48dp minimum height. Focus: 4dp Gold Dim halo plus a 1dp gold stroke. Error: 1dp Alarm Red stroke, with the error text replacing the helper under the field rather than adding to it. The email code field is monospace with wide tracking.

### Navigation
- **Bottom navigation:** Chats, Channels, Contacts, Settings on Raised Indigo. The selected tab is gold on a Gold Dim pill. The Calls tab stays hidden: the product has no calls.
- **App bar:** Night Indigo; top-level screens carry a Rubik 900 title at 28sp, nested screens a quieter 18sp title with a back arrow.

### Message bubbles
- **Outgoing:** Own Bubble Indigo with Star White text, meta in #D5DAFF. 6dp tail corner bottom right.
- **Incoming:** Card Indigo with Star White text. 6dp tail corner bottom left.
- New messages rise 14dp and fade in over 240ms.

### Channel posts
A full-width Card Indigo sheet with 16dp corners, the text in Body, the author's time under it in Muted caption, right-aligned. A post is not a reply in a conversation, so it is not a bubble and has no tail. The author sees a composer row; a reader sees one line saying that only the author can post.

### Onboarding steps
Three steps under a three-segment progress bar: username and email, PIN, the code from the email. Segments fill gold as steps complete. Restoring from a backup shows one step and hides the bar. The resend control counts down in its own label.

## Do's and Don'ts

### Do:
- **Do** use Camp Gold (#FFCB2E) as the only action colour, with On-Gold Brown (#2B1600) on it.
- **Do** give the chunky edge to the primary action and to nothing else on the screen.
- **Do** keep conversations, channel feeds and settings flat and calm, in the same palette.
- **Do** set screen titles and button labels in Rubik and everything read for content in Inter.
- **Do** set safety numbers, keys, links and codes in monospace.
- **Do** keep touch targets at 48dp or larger and all type in sp.
- **Do** skip all motion — star twinkle, seal movement, message rise — when the system disables animations.
- **Do** record where every raster file came from in `design/art/README.md` before it ships.

### Don't:
- **Don't** fill a reading surface with gold: no gold bubbles, posts or cards.
- **Don't** use green, orange or red for anything but their security meaning, and don't place the scene next to a status icon.
- **Don't** put the night scene, the wordmark or the token inside a conversation, a channel feed, settings or a dialog.
- **Don't** use gradient or outlined text anywhere but the wordmark.
- **Don't** use pure black as a surface, and don't follow the system light theme; the app is always dark.
- **Don't** use a "hacker" look: no terminal green, neon cyan on black, glitch, matrix or skull imagery.
- **Don't** let the playful look promise what the product does not have: no calls, voice, groups or push; no "unbreakable", no implied audit.
- **Don't** ship a mascot cut out with a circle or a rectangle; it needs a real alpha contour.
- **Don't** draw text into illustrations other than the wordmark; the app speaks two languages.
- **Don't** use Disabled Text (#6670AD) for anything a person must read.
