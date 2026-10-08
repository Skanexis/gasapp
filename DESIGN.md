---
name: GasApp
description: Encrypted messenger drawn as an intaglio security document - deep ink-navy ground, one periwinkle ink, a code-drawn guilloche seal.
colors:
  ink-navy: "#0F1629"
  ink-navy-raised: "#151D34"
  ink-navy-card: "#1B2442"
  ink-navy-hover: "#242F52"
  hairline: "#2E3A5C"
  paper-white: "#F2F4FC"
  text-secondary: "#B4BCD6"
  text-muted: "#8E99B8"
  text-disabled: "#5A6585"
  periwinkle-ink: "#8FA5FF"
  periwinkle-hover: "#A8B9FF"
  periwinkle-pressed: "#7890F5"
  on-ink: "#0A1030"
  on-ink-meta: "rgba(10,16,48,0.75)"
  periwinkle-dim: "rgba(143,165,255,0.14)"
  periwinkle-line: "rgba(143,165,255,0.40)"
  verified-green: "#3DD598"
  caution-amber: "#F0B84C"
  alarm-red: "#FF6B78"
  verified-green-dim: "rgba(61,213,152,0.13)"
  caution-amber-dim: "rgba(240,184,76,0.13)"
  alarm-red-dim: "rgba(255,107,120,0.13)"
typography:
  display:
    fontFamily: "Inter, sans-serif"
    fontSize: "32px"
    fontWeight: 700
    lineHeight: "40px"
  headline:
    fontFamily: "Inter, sans-serif"
    fontSize: "28px"
    fontWeight: 700
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
    fontFamily: "Inter, sans-serif"
    fontSize: "15px"
    fontWeight: 600
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
    backgroundColor: "{colors.periwinkle-ink}"
    textColor: "{colors.on-ink}"
    typography: "{typography.button}"
    rounded: "{rounded.button}"
    padding: "0 24px"
    height: "48px"
  button-primary-hover:
    backgroundColor: "{colors.periwinkle-hover}"
    textColor: "{colors.on-ink}"
  button-primary-pressed:
    backgroundColor: "{colors.periwinkle-pressed}"
    textColor: "{colors.on-ink}"
  button-secondary:
    backgroundColor: "{colors.ink-navy-card}"
    textColor: "{colors.paper-white}"
    typography: "{typography.button}"
    rounded: "{rounded.button}"
    padding: "0 24px"
    height: "48px"
  button-ghost:
    textColor: "{colors.periwinkle-ink}"
    typography: "{typography.button}"
    rounded: "{rounded.button}"
    padding: "0 24px"
    height: "48px"
  input:
    backgroundColor: "{colors.ink-navy-card}"
    textColor: "{colors.paper-white}"
    typography: "{typography.body}"
    rounded: "{rounded.input}"
    padding: "12px 16px"
    height: "48px"
  composer:
    backgroundColor: "{colors.ink-navy-card}"
    textColor: "{colors.paper-white}"
    typography: "{typography.body}"
    rounded: "{rounded.composer}"
  bubble-outgoing:
    backgroundColor: "{colors.periwinkle-ink}"
    textColor: "{colors.on-ink}"
    typography: "{typography.body}"
    rounded: "{rounded.card}"
    width: "280px"
  bubble-incoming:
    backgroundColor: "{colors.ink-navy-card}"
    textColor: "{colors.paper-white}"
    typography: "{typography.body}"
    rounded: "{rounded.card}"
    width: "280px"
  card:
    backgroundColor: "{colors.ink-navy-card}"
    rounded: "{rounded.card}"
    padding: "16px"
  sheet:
    backgroundColor: "{colors.ink-navy-raised}"
    rounded: "{rounded.sheet}"
  pill-ok:
    backgroundColor: "{colors.verified-green-dim}"
    textColor: "{colors.verified-green}"
    rounded: "12px"
    padding: "0 10px"
    height: "24px"
  pill-warn:
    backgroundColor: "{colors.caution-amber-dim}"
    textColor: "{colors.caution-amber}"
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
    backgroundColor: "{colors.periwinkle-dim}"
    textColor: "{colors.periwinkle-ink}"
    rounded: "15px"
  list-row:
    padding: "0 16px"
    height: "64px"
---

# Design System: GasApp

## Overview

**Creative North Star: "The Intaglio Document"**

GasApp is a security document the person carries, not a terminal. The screens borrow the grammar of intaglio security printing (passports, banknotes): a ground of deep printing inks in tonal steps, fine-line guilloche drawn in hairline strokes, and exactly one luminous ink, periwinkle, reserved for action and for the person's own words. It deliberately refuses the category default of near-black plus a single neon cyan, and refuses the "hacker" register entirely: no terminal green, no glitch, no skulls.

The density is that of a calm, conventional Android messenger: 16dp screen margins, 64-72dp list rows, 48dp touch targets, sp type that scales with the system. The document character lives in three places only: the palette (ink-navy ground, never black), the outgoing speech bubble (periwinkle ink with dark text, "ink on paper"), and the guilloche seal, which appears on four surfaces and nowhere else. Everything else is quiet, so waiting on Tor reads as a normal state rather than a failure.

Motion is short, decelerating and functional: the seal turns one notch per PIN digit, opens on a correct PIN, shakes and flashes red on a wrong one; new messages rise 14dp into place. All of it is skipped when the system has animations removed, and none of it may cost frames on a weak phone.

Provenance: this world is a code-led refinement of the incumbent UI-kit world (`design/secure-messenger-ui-kit.html`, `design/gasapp.tokens.json`) raised to an own world, "intaglio". The concept-seed roll was waived (no seed key) on the owner's explicit brief "можно даже отклониться чуть от UI kit и сделать что то красивее и эффектнее но без лагов и перегрузки" (allowed to deviate a bit from the kit, more beautiful and striking, without lag or overload), with confirmed constraints: keep the kit's dark theme, no "hacker" look, a new palette allowed, Android screens only. No image generation was used, no comps were produced, and no shipping rasters exist: the launcher icon, backgrounds and the seal are XML vectors or code-drawn.

**Key Characteristics:**
- Deep ink-navy ground in four tonal steps plus a 1dp hairline; no shadows.
- One action ink (periwinkle); status inks green / amber / red carry security meaning only.
- Code-drawn guilloche rosette as the brand mark, on lock, onboarding welcome, empty chat list and security center only.
- Inter for all interface text; monospace for anything a human verifies character by character.
- Always dark; the theme never follows system light mode.
- Motion skipped entirely when the system disables animations.

## Colors

A night-press palette: blue-violet printing inks on a navy ground, with one luminous periwinkle and three semantic status inks. Tokens are generated from the UI kit into `design/gasapp.tokens.json` and mirrored byte-for-byte in `res/values/colors.xml` (enforced by DesignTokensTest).

### Primary
- **Periwinkle Ink** (#8FA5FF): the single action ink. Primary buttons, the send button, the FAB, filled PIN dots, focused-field strokes, cursor and selection handles, selected tab, inked seal rings, and the fill of the person's own outgoing bubbles. Holds at least 5.6:1 against every surface.
- **Periwinkle Hover / Pressed** (#A8B9FF / #7890F5): hover-focus and pressed states of periwinkle surfaces only.
- **On-Ink Navy** (#0A1030): text and icons sitting on periwinkle (button labels, outgoing message text). Outgoing message meta (time, ticks) uses it at 75% alpha, measured 5.0:1.
- **Periwinkle Dim / Line** (14% / 40% alpha): tinted backplates (selected tab pill, E2E chip, connecting strip, focus halo) and the focused composer stroke.

### Tertiary (status inks)
- **Verified Green** (#3DD598): "verified / passed" only. Verified contacts, passed checks, an all-clear security seal.
- **Caution Amber** (#F0B84C): "needs attention" and direct (non-Tor) connection. Warning notices, the direct-connection strip text and rule (about 10:1 on the raised ground).
- **Alarm Red** (#FF6B78): errors, wrong PIN, destructive actions. At least 4.76:1 on all surfaces.
- Each has a 13% dim variant used only as the backplate of its own pill or notice.

### Neutral
- **Ink Navy** (#0F1629): window, app bar, status and navigation bars. Never pure black.
- **Raised Navy** (#151D34): sheets, panels, the direct-connection strip, disabled composer.
- **Card Navy** (#1B2442): cards, grouped lists, inputs, incoming bubbles, secondary buttons, dialogs, toasts.
- **Hover Navy** (#242F52): ripples, keypad press halos, seal track.
- **Hairline** (#2E3A5C): 1dp strokes on cards, inputs, sheets and dividers; empty PIN dots; faint (un-inked) seal rings.
- **Paper White** (#F2F4FC): primary text.
- **Secondary Text** (#B4BCD6): subtitles, previews, captions. At least 6.9:1 on every surface.
- **Muted Text** (#8E99B8): time stamps, counters, hints, group headers. At least 4.61:1 even on Hover Navy.
- **Disabled Text** (#5A6585): disabled controls only; never for readable text.

### Avatar Inks
Six pastel inks assigned by name hash (periwinkle #8FA5FF, sea #5ED3C9, rose #F59AB8, apricot #F5B08A, lilac #C4A9FF, sky #7FC4F5), drawn as the initials color over a 16% fill of the same ink. Set in code (`ui/Avatars.kt`), not tokens.

### Named Rules
**The One Ink Rule.** Periwinkle is the only action color. If something is tappable and primary, it is periwinkle; if it is not, it is not periwinkle. No second accent.

**The Semantic Inks Rule.** Green means verified, amber means attention, red means error or danger. They never decorate, and avatar inks never include green, amber or red, so a contact's color can never read as a security state.

**The Navy Not Black Rule.** The ground is ink-navy (#0F1629) in tonal steps. Pure black appears only as the camera scrim on the QR scanner.

## Typography

**Body Font:** Inter (bundled in `res/font`: 400, 600, 700)
**Label/Mono Font:** platform monospace, for safety numbers, keys, recovery key and links

**Character:** One sober grotesque at three weights carries the whole interface; hierarchy comes from size and weight, never from a second display face. Monospace is a verification requirement, not a style: proportional type merges look-alike characters and breaks positional comparison.

### Hierarchy
- **Display** (700, 32/40sp): reserved; rarely used on screen.
- **Headline** (700, 28/36sp): large screen titles (the collapsing large title, onboarding welcome).
- **Headline Small** (600, 24/32sp): section-level titles inside flows and the lock title.
- **Title** (600, 20/28sp) and **Title Small** (600, 17/24sp): app-bar titles, card headings, contact names.
- **Body** (400, 15/22sp): messages, descriptions, inputs. Bubbles cap at 280dp wide.
- **Caption** (400, 13/18sp): previews, notes, helper text, in Secondary or Muted ink.
- **Button** (600, 15sp): sentence case, never all caps.
- **Label** (600, 12/16sp): group headers above grouped lists and field labels; uppercase with 0.1em tracking in Muted ink.

### Named Rules
**The Line-Height-Travels-With-Size Rule.** Every step is size, line height and weight together (Android `lineSpacingExtra` = token line height minus size). Taking the size alone is how screens look "close but wrong".

**The Mono For Verification Rule.** Anything a person compares character by character (safety number, key, recovery key) is set in monospace, and the style sets both the platform and AppCompat font attributes so Inter cannot override it.

## Layout

Single-column phone layout. Screen margin 16dp; spacing from the 4 / 8 / 16 / 24 / 32 / 40 / 48 / 64dp scale, referenced by name in layouts, never as raw numbers. List rows are 64-72dp tall with 16dp side padding; touch targets are never below 48dp; type is in sp and scales with the system. Dialogs cap at 340dp wide. On short screens (landscape phone) explanatory banners collapse to two lines; from 600dp height they show in full.

Scrolling containers disable the platform default focus highlight; focus is shown by the component's own focus state instead.

The chat list carries a connection strip directly under the app bar whenever the app is not connected through Tor or a proxy: on Periwinkle Dim with a 2dp periwinkle progress line while connecting; on Raised Navy with amber text and a full amber rule for a direct connection or blocked Tor. It hides only when Tor or the proxy is connected.

## Elevation & Depth

Flat. No shadows anywhere (`stateListAnimator` is null on buttons). Depth is tonal: Ink Navy ground, Raised Navy for sheets and panels, Card Navy for cards, inputs and incoming bubbles, Hover Navy for press feedback, each edged by a 1dp Hairline stroke. Focus adds a 4dp Periwinkle Dim halo plus a 1dp periwinkle stroke rather than lifting the element.

### Named Rules
**The Tonal Steps Rule.** A surface is raised by moving one navy step lighter and adding a hairline, never by a shadow or a glow.

## Shapes

Gently rounded, tiered by role: inputs 12dp, buttons 14dp, cards, dialogs and panels 16dp, composer field 22dp, sheets 24dp on the top corners only. Message bubbles are 16dp with a 6dp tail corner on the speaker's side (bottom right for outgoing, bottom left for incoming). Pills are 24dp tall capsules; avatars, PIN dots (14dp), the send button and keypad press halos (60dp) are circles. Borders are always 1dp. The guilloche seal is the only ornamental geometry in the system.

## Components

### Buttons
Calm, solid and flat.
- **Shape:** 14dp corners; heights 40 / 48 / 56dp (small / medium / large).
- **Primary:** Periwinkle Ink fill, On-Ink Navy label, 600 weight, 24dp side padding (32dp large, 16dp small).
- **Hover / Focus / Pressed:** Periwinkle Hover on hover and focus, Periwinkle Pressed when pressed; disabled uses its own muted drawable. No elevation change.
- **Secondary:** Card Navy fill, Paper White label. **Outline:** transparent with a 1dp Hairline stroke, for actions equal in weight to a refusal. **Ghost:** periwinkle label, no fill. **Danger / Ok:** status-ink fills with 700-weight labels, only where the action carries that meaning.

### Chips and Pills
- **Style:** 24dp capsule, 11sp 600 label with 0.04em tracking, status ink on its 13% dim backplate (ok, warn, error, accent, neutral variants).
- **Use:** state badges only (verified, attention, E2E). Day separators in chat are Card Navy capsules.

### Cards / Containers
- **Corner Style:** 16dp.
- **Background:** Card Navy for grouped lists and action tiles (with Hover Navy ripple); Raised Navy for informational panels.
- **Shadow Strategy:** none; see Elevation & Depth.
- **Border:** 1dp Hairline.
- **Internal Padding:** 16dp.

### Inputs / Fields
- **Style:** Card Navy fill, 1dp Hairline stroke, 12dp corners, 48dp min height, 16dp side and 12dp vertical padding, body type, Muted hint.
- **Focus:** 4dp Periwinkle Dim halo plus 1dp Periwinkle stroke.
- **Error / Disabled:** 1dp Alarm Red stroke; disabled moves to its own quieter drawable.
- **Composer:** 22dp capsule on Card Navy, focus stroke Periwinkle Line, with a circular periwinkle send button (Periwinkle Pressed when pressed, Card Navy when disabled).

### Navigation
- **Bottom navigation:** icon plus label tabs on Ink Navy. The selected tab is Periwinkle Ink on a Periwinkle Dim pill (15dp corners). Inactive labels must hold 4.5:1.
- **Scope:** the Calls tab is hidden; the product has no calls and the interface must not promise them.
- **App bar:** Ink Navy, 48dp icon buttons, large collapsing 28sp title on top-level screens.

### Message Bubbles
- **Outgoing:** Periwinkle Ink fill with On-Ink Navy text, meta at 75% On-Ink Navy. Max width 280dp, 6dp tail corner bottom right.
- **Incoming:** Card Navy fill with Paper White text, 6dp tail corner bottom left.
- **Delivery ticks:** pending / single / double / failed icons, each with a spoken label for TalkBack. The time placeholder is sized in sp so it scales with the text.
- **Arrival:** new messages rise 14dp and fade in over 240ms, decelerating.

**The Ink On Paper Rule.** The person's own words are printed in periwinkle ink with dark text. Outgoing bubbles never use a dim or translucent accent and never use light text on periwinkle.

### Guilloche Seal (signature)
A code-drawn rosette (`components/GuillocheView`): concentric rings, each made of wavy strands with phase offset, 0.9dp round-capped hairline strokes, wave count rising toward the rim. Inked rings are drawn in the ink color at about 50% alpha, the rest in Hairline. A central window (fraction of the radius) holds content. Paths are computed once per size; rotation is a view property applied by the GPU, and movement runs with a hardware layer.
- **Lock:** 288dp seal, four rings of three strands; PIN dots sit on its horizontal axis inside the window. Each digit turns it 15 degrees with an overshoot spring (320ms); clearing settles it back (420ms); a correct PIN opens it (scale to 1.7, rotate 60 degrees, fade, 380ms) and the chat list fades in; a wrong PIN shakes it (8dp, 380ms) and flashes its ink red (520ms).
- **Onboarding welcome:** 168dp seal with the shield icon in its window; rings ink one by one on first show only.
- **Empty chat list:** 152dp seal, window 0.5.
- **Security center:** a counting seal, one single-strand ring per check with gaps (0.45) between rings so the checks can be counted; passed rings ink one by one (70ms per ring) in the verdict color, green when all pass and amber otherwise, matching the score number.
- **Accessibility:** the seal is hidden from screen readers; every state it shows is also stated in text.

**The Four Seals Rule.** The rosette appears on the lock screen, onboarding welcome, empty chat list and security center, and nowhere else. It is the mark, not a texture.

**The Still When Asked Rule.** Every animation (seal turn, open, reject, ink-in, message rise, strip progress) is skipped and jumps to its end state when the system has animations disabled.

## Do's and Don'ts

### Do:
- **Do** use Periwinkle Ink (#8FA5FF) as the only action color, with On-Ink Navy (#0A1030) text on it.
- **Do** raise surfaces by navy tonal steps plus a 1dp Hairline (#2E3A5C) stroke.
- **Do** reference spacing, radius and type by token name; keep layouts free of raw numbers.
- **Do** keep touch targets at 48dp or larger and all type in sp.
- **Do** set safety numbers, keys and recovery keys in monospace.
- **Do** show the connection route on the chat list whenever Tor or a proxy is not connected.
- **Do** give every status icon (delivery ticks, verification) a spoken label.
- **Do** skip all motion when the system disables animations, and run seal movement on a hardware layer.

### Don't:
- **Don't** use a "hacker" look: no terminal green, neon cyan on black, glitch, matrix or skull imagery.
- **Don't** use pure black as a surface; the ground is Ink Navy (#0F1629).
- **Don't** use green, amber or red for anything but their security meaning, and don't add them to avatar inks.
- **Don't** place the guilloche seal outside lock, onboarding welcome, empty chat list and security center.
- **Don't** add shadows or glows for elevation.
- **Don't** follow the system light theme; the app is always dark.
- **Don't** show calls, voice, groups or push affordances; the product has none.
- **Don't** use Disabled Text (#5A6585) for anything a person must read.
- **Don't** add raster imagery or heavy visual libraries; marks and backgrounds are vectors or code-drawn.
