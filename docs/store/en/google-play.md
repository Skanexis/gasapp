<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Google Play — answers for Play Console

**Version:** 2026-10-26. Build: flavor `gms`, `applicationId
org.gasapp.app.gms`, `targetSdk 36`, `minSdk 28` (Android 9+).

Every answer below was checked against the code on this date
(`docs/security/encryption-map.md`). If the code changes, re-check: a Data
safety form that disagrees with the app is a policy violation, not a typo.

---

## 1. App setup

| Play Console section | Answer |
|---|---|
| Category | **Communication** |
| Free / paid | Free. No in-app purchases |
| Ads | **No ads** |
| App access | Registration required — reviewer instructions in § 5 |
| Government app | No |
| Financial features | No |
| Health | No |
| News app | No |
| VPN app | No: `VpnService` is not used. Tor serves only the app's own traffic (in-process SOCKS) |
| Uses AI / generative AI | No |

---

## 2. Data safety

**Does the app collect or share any of the required user data types?** —
**Yes** (collects). No sharing with third parties.

| Data type | Collected | Shared | Required | Purpose | Why |
|---|---|---|---|---|---|
| Personal info → **User IDs** | Yes | No | Yes | App functionality, account management, fraud prevention and security | The username is stored on the server: people find each other by it |
| Personal info → **Email address** | Yes | No ¹ | Yes | Account management, fraud prevention and security | An account is created after confirming an address with a code. The server keeps a keyed hash of it, not the address |
| **Device or other IDs** | Yes | No | Yes | App functionality | A random device identifier created by the app (not Android ID, not an advertising ID): the server delivers envelopes to it |
| App activity → **App interactions** | Yes | No | Optional | App functionality, fraud prevention | Which channels the account follows, how far it has read, its reactions. Stored so that subscriber counts and views cannot be inflated |
| App activity → **Other user-generated content** | Yes | No | Optional | App functionality | Only for a channel its owner makes **public** (`@name`): the owner hands the server the channel key, so the server can read that channel's title and posts |
| **Photos and videos**, **Files and docs** | Yes | No | Optional | App functionality | Only attachments of a **public** channel, for the same reason |

¹ The e-mail with the code is sent by a mail service acting as our
processor. Under Google's definitions a transfer to a service provider
processing data on the developer's behalf is not "sharing" — **provided a
data-processing agreement exists**. Sign it and name the service in the
Privacy Policy before answering "No".

Do **not** tick "data is processed ephemerally" for the e-mail: its hash is
kept until the account is deleted.

**Not declared — and why** (re-read Google's help wording when filling in):

* **Private messages, their photos and files, contacts.** End-to-end
  encrypted on the device; the server stores ciphertext it cannot read and
  deletes it on delivery (30 days at most). Data that is end-to-end
  encrypted and unreadable by the developer is not "collected" under Data
  safety rules. Contacts live only on the device.
* **Content of channels without a public name** (link-only and closed).
  Encrypted with a key the server does not have.
* **Location.** Not collected or shared.
* **IP address.** The app connects directly by default, so the server
  sees the address while a connection is open; it does not log or store
  it. Tor, built into the app, hides it when the user turns it on.
* **Diagnostics, analytics, crash logs.** No SDK of any kind
  (`tools/check-no-telemetry.sh` in CI).
* **Push token (`gms` build, Google Play).** Declare "Device or other IDs":
  **collected** (the server stores the FCM token linked to the device) and
  **shared** with Google (Firebase Cloud Messaging delivers the constant
  "New messages" signal, with no text or sender). Purpose: "App
  functionality"; **optional** — turned off in Settings → Notifications.
  Processed ephemerally? No — kept until notifications are turned off or
  the account is deleted. The `foss` build sends nothing to Google
  (see "Push notifications" in the privacy policy).

### Security practices

| Question | Answer |
|---|---|
| Data is encrypted in transit | **Yes** — TLS 1.3 with certificate pinning; inside Tor when the user turns it on |
| Users can request data deletion | **Yes** — in the app: Settings → Privacy → Delete account; web page — § 6 |
| Committed to the Play Families policy | No (not for children) |
| Independent security review (MASA) | ⚠️ **No.** Do not tick until one is done |

---

## 3. Content rating (IARC questionnaire)

Category: **Social networking, messaging, communication**.

| Question | Answer |
|---|---|
| Violence, fear, sexual content, profanity, drugs, gambling | No — the app itself contains none |
| Users can interact / communicate | **Yes** |
| Users can exchange images, files | **Yes** |
| User-generated content is shared publicly | **Yes** — channels |
| Shares the user's location with others | No |
| Digital purchases | No |
| Unrestricted internet access (browser) | No |

---

## 4. Target audience and content

| Question | Answer |
|---|---|
| Target age groups | **16-17** and **18 and over**. The Terms of Use require 16: the highest age of digital consent in the EU (GDPR Art. 8), so parental consent is never needed. Do not tick any group under 16 |
| Could the app appeal to children | No ⚠️ — re-read this against the final icon and screenshots: the visual style is playful. If the answer could honestly be "yes", the store may ask for a neutral-age screen |

**Anonymous / random chat (policy in force since 2026-08-26).** GasApp is
**not** an anonymous or random chat app as Google defines them: its core
function is not connecting strangers at random, and identities are not
deliberately hidden — an account requires a verified e-mail address and a
persistent username, and a first message from a new person arrives as a
request the user must accept. If Play Console asks, answer accordingly. The
16+ declaration above excludes children regardless.

---

## 5. App access (reviewer instructions)

Choose "All or some functionality is restricted" and paste:

```text
GasApp needs no phone number. To create an account you need an email
address that you can read:
1. Open the app and tap "Create account".
2. Choose any free username and enter your email address. The links to
   the Terms of Use and Privacy Policy are on this screen.
3. Choose a 6-digit PIN. Leave "Connect through Tor" off (the
   default): the app connects at once. With Tor on, the first connection
   takes 20-60 seconds, up to 2-3 minutes on networks that block Tor.
4. A 6-digit code is emailed to you (check the spam folder). You may
   leave the app to read it; when you come back and enter your PIN, the
   app returns to the code screen. Enter the code.

MESSAGING: tap the pencil button and enter the username
"gasapp_review_1". It is monitored during review and will reply.

CHANNELS: the "Channels" tab reads one-to-many channels. Tap the link
icon, choose "Paste a link" and paste our test channel link:
<PASTE THE TEST CHANNEL LINK HERE BEFORE SUBMITTING>
Creating channels and bots needs a premium account, granted by us by
hand; nothing is sold in the app.

SAFETY TOOLS (user-generated content):
- A new sender's first message arrives as a chat request: Accept/Decline.
- Block or report a person: open the chat, contact menu > Block / Report.
- Report a channel: open the channel, menu (three dots) > Report channel.
- Terms, Community Guidelines, Privacy Policy: Settings > About > Terms
  and documents.

NOTES:
- Messages are end-to-end encrypted; the server cannot read them.
- Notifications: the Google Play build is woken through Firebase Cloud Messaging and shows "New messages" without the text or sender; the server sends at most one signal per device per minute. On a phone without Google Play services the app checks for new messages about every 15 minutes instead, and with Tor on that check does not run.
- Account deletion: Settings > Privacy > Delete account (immediate).
- Tor is optional: Settings > Privacy > Network > Tor (built in).
  It hides the IP address from the server.
```

Before submitting: register the review accounts on the production server,
make one premium, create the test channel, and keep the app open on one of
them during review.

---

## 6. Account deletion

Google requires deletion **in the app and** by a web link.

* **In the app:** Settings → Privacy → Delete account (two confirmations,
  immediate, the app shows what was removed).
* **Web link:** `https://gasapp.eu/account-deletion/`.

🔴 **Submission blocker.** An account cannot be deleted from the web by design:
there is no password and no e-mail sign-in — a deletion request is signed by
the device key. The page explains this honestly and gives two paths:
deletion in the app, and automatic deletion after 12 months without
connecting. Neither is a web path for submitting a deletion request.
Google's current guidance explicitly requires a web resource where someone
who uninstalled the app can request deletion without reinstalling it.
Do not submit the Data safety deletion answer as compliant until a secure
request and verification process exists and this page describes it.

---

## 7. Permissions

| Permission | Why | Declaration |
|---|---|---|
| `INTERNET`, `ACCESS_NETWORK_STATE` | Network | None |
| `CAMERA` | Scanning a QR code (add a contact, verify a safety number, join a channel). Requested at the moment of scanning | None (ordinary runtime permission) |
| `VIBRATE`, `WAKE_LOCK` | Notifications, finishing a request with the screen off | None |

No sensitive permissions (SMS, call log, all-files access, location,
contacts, `QUERY_ALL_PACKAGES`, exact alarms, foreground services,
accessibility) — no Play Console declarations are needed. Contacts are
never read from the phone book, so the 2026 Contacts Permissions policy
does not apply.

---

## 8. User-generated content and child safety

| Requirement | Where it is met |
|---|---|
| Users accept terms of use | Sign-up screen links the Terms of Use and Privacy Policy; creating an account is acceptance |
| Published rules for content | `https://gasapp.eu/community-guidelines/` |
| In-app reporting of users and content | Contact menu → Report; channel menu → Report channel |
| Blocking | Contact menu → Block; leave a channel |
| Ongoing moderation | Operator console (`docs/ops/admin-center.md`): reports reviewed within 24 hours; accounts and channels can be removed |
| CSAE prohibited in published standards | `https://gasapp.eu/child-safety/` and the Community Guidelines |
| CSAM process and legal reporting | Described on the child-safety page (NCMEC / INHOPE) |
| Child safety point of contact | `abuse@gasapp.eu` — enter it in Play Console → Child safety |

Limit to state honestly if asked: private messages are end-to-end
encrypted, so moderation acts on accounts and channels after a report, not
on message content.

---

## 9. Release

| Step | What matters |
|---|---|
| Developer account | **Personal** → closed testing with **at least 12 testers for 14 consecutive days** before production access |
| App registration | The app must be registered in Play Console under a verified developer (requirement in force since 2026-09-30) |
| Signing | Play App Signing; the upload key is separate and kept by the owner |
| Format | App Bundle: `./gradlew :app:bundleGmsRelease -PgasappDocsUrl=https://gasapp.eu …` — as its own command. 16 KB page check: `tools/check-16kb-pages.py` |
| Version | `versionCode` grows with every upload; for the beta use `versionName` `0.9.x` |
| Countries | All except **France** (owner's decision, 2026-10-10: no French encryption declaration is filed) |
| Production TLS pins | ⚠️ **Blocker:** `release/res/xml/network_security_config.xml` still holds placeholders |

---

## 10. Graphics

| Asset | Requirement |
|---|---|
| Icon | 512 × 512 PNG, 32-bit, up to 1 MB |
| Feature graphic | 1024 × 500 JPG/PNG, no transparency |
| Phone screenshots | 2–8, side 320–3840 px, aspect ratio up to 2:1. Screens: chat list, a conversation, key verification (QR), Security Centre, a channel, privacy settings |
| Tablet screenshots | Not needed until tablets are declared |

Use test accounts with invented conversations: no real names or messages in
the listing.
