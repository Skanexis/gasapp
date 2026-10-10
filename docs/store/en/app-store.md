<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# App Store — answers for App Store Connect

**Version:** 2026-10-10.

> ⚠️ **Nothing to submit yet.** The iOS app is a skeleton (`ios/`) and iOS
> is postponed. This document prepares the submission; before submitting,
> go through § 6 again against the real iOS build. Builds must use the
> iOS 26 SDK (Xcode 26 or later).

---

## 1. App Privacy

| Category → type | Collected | Linked to user | Tracking | Purpose |
|---|---|---|---|---|
| Identifiers → **User ID** | Yes | Yes | No | App Functionality |
| Identifiers → **Device ID** | Yes | Yes | No | App Functionality |
| Contact Info → **Email Address** | Yes | Yes | No | App Functionality (account creation; one address — one account). The server keeps a keyed hash, not the address |
| Usage Data → **Product Interaction** | Yes | Yes | No | App Functionality (which channels the account follows, read position, reactions) |
| User Content → **Other User Content** | Yes | Yes | No | App Functionality — only for a channel its owner makes public: the server can then read its title, posts and files |

Everything else — **not collected**:

* **Messages, photos and files in private conversations** — end-to-end
  encrypted; the server holds ciphertext it cannot read until delivery
  (30 days at most). Apple does not require disclosing data the developer
  cannot read; re-check the wording of "App privacy details" when filling
  in.
* **Content of channels without a public name** — encrypted with a key the
  server does not have.
* **Contacts** — on the device only; the address book is never read.
* **Location, Diagnostics, Browsing History, Purchases** — none; there is
  no SDK of any kind.

Tracking: **No**. App Tracking Transparency is not needed.

---

## 2. Export compliance

The app encrypts content (not only HTTPS), so the "authentication only" and
"HTTPS only" exemptions do not apply.

| Where | Answer |
|---|---|
| `Info.plist` | `ITSAppUsesNonExemptEncryption = YES` |
| Uses encryption? | Yes |
| Proprietary or non-standard algorithms? | **No** — standard only: X25519, Ed25519, ML-KEM-1024 (FIPS 203), ML-DSA-65 (FIPS 204), AES-256-GCM, XChaCha20-Poly1305, SHA-2, HKDF, Argon2id |
| Standard algorithms **not provided by the OS** | **Yes** (the Rust core implements them). App Store Connect asks for a French encryption declaration only if the app is distributed in France — it is not, see the next row |
| France | ✅ Owner's decision, 2026-10-10: **France is excluded from distribution** (App Store Connect → Pricing and Availability → deselect France; Google Play → Production → Countries/regions → remove France). No ANSSI declaration is filed. France can be added back only after a declaration is filed |
| United States (BIS) | The source code is public → before the first release, one e-mail notice to `crypt@bis.doc.gov` and `enc@nsa.gov` with the repository URL (EAR §742.15(b)). No CCATS is needed for standard algorithms |

Supporting document for any question: `https://gasapp.chat/encryption/`.

⚠️ This is not legal advice: check the current EAR and ANSSI rules before
submitting.

---

## 3. Age rating

| Questionnaire item | Answer |
|---|---|
| Violence, sexual content, profanity, gambling, drugs, horror | None |
| **User-Generated Content** | **Yes** |
| **Messaging and Chat** | **Yes** |
| **Social media capabilities** (required since September 2026) | **Yes** — public channels can be found by name and followed, and readers react to posts: user-generated content surfaced through discovery. The app gets the Social Media descriptor and at least 13+ |
| Social media capabilities disabled for users under 13 | Not applicable — the Terms of Use require users to be 16 or older |
| Unrestricted Web Access | No |
| Age assurance / parental controls | No |
| Made for Kids | No |

Expected result: the highest tier Apple assigns to unmoderated messaging.
The Terms of Use require users to be 16 or older; set the age rating
override to 16+ if the calculated rating is lower. If Apple calculates
18+, that rating stands in the store - it cannot be lowered by hand.

---

## 4. Review Notes (paste as is)

```text
GasApp is an end-to-end encrypted messenger with one-to-many channels.
Accounts need no phone number: a user picks a username, confirms an
email address with a 6-digit code and sets a 6-digit PIN. The email is
used only to create the account; the server keeps a hash of it.

HOW TO TEST
1. Tap "Create account", choose any free username, enter an email
   address you can read, then choose a PIN.
2. Leave "Connect through Tor" off (the default) - the app connects
   at once. A 6-digit code is then emailed to you - enter it.
3. Messaging: tap the pencil button and enter the username
   "gasapp_review_1". It is monitored during review and will reply.
4. Channels: on the Channels tab tap the link icon, "Paste a link", and
   paste: <PASTE THE TEST CHANNEL LINK HERE BEFORE SUBMITTING>

A demo account to sign in with is not possible by design: there are no
passwords; each device holds its own keys.

USER-GENERATED CONTENT (Guideline 1.2)
Private messages are end-to-end encrypted, so neither we nor the server
can read or filter them. Users are protected by:
- chat requests: a new sender's first message must be accepted first;
- Block: contact menu > Block;
- Report a person: contact menu > Report;
- Report a channel: channel menu > Report channel;
- Terms of Use and Community Guidelines accepted at sign-up, with zero
  tolerance for objectionable content: https://gasapp.chat/terms/
- we review reports within 24 hours and remove offending accounts and
  channels; contact: abuse@gasapp.chat.

ENCRYPTION
Standard algorithms only. Details: https://gasapp.chat/encryption/
Source code is public: <repository URL>.

ACCOUNT DELETION
Settings > Privacy > Delete account. Deletion is immediate.

NOT IN THIS VERSION
No calls, no group chats, no push notifications, no purchases.
```

The 24-hour line is an operator **commitment**: do not send it without a
read `abuse@` mailbox and a person on duty.

---

## 5. Review guidelines — status

| Guideline | Status | To do |
|---|---|---|
| **1.2 UGC: filtering/blocking** | ✅ Android (Block, chat requests) · 🔴 iOS | Port to iOS |
| **1.2 UGC: reporting** | ✅ Android (people and channels) · 🔴 iOS | Port to iOS; staff the mailbox |
| **1.2 UGC: published contact, terms with zero tolerance** | ✅ Terms, Guidelines, Support pages | Publish the site |
| **2.1 completeness, demo** | 🟡 | Review accounts on the production server |
| **2.5.1 public APIs only** | ✅ by design | Verify on the iOS build |
| **3.1.1 purchases** | ✅ none; premium is granted by hand and nothing is sold | — |
| **4.7 downloaded code** | ✅ none. Bots run on their owners' machines, not in the app | — |
| **5.1.1 privacy policy** | ✅ in the listing and in the app | Publish the site |
| **5.1.1(v) account deletion in app** | ✅ Android · 🔴 iOS | Port to iOS |
| **5.1.2 data sharing incl. third-party AI** | ✅ none | — |
| **Export compliance** | 🟡 | § 2 |
| **Unique name** | 🟡 | Check "GasApp" for conflicts (`../listing.md`) |

---

## 6. Before submitting — check on the iOS build

* The feature list in the description matches iOS (biometric unlock,
  account deletion, Tor on iOS, channels, reporting).
* `Info.plist`: `NSCameraUsageDescription` ("Scan a contact's QR code to
  verify their key"), `NSFaceIDUsageDescription`; no other usage strings.
* `PrivacyInfo.xcprivacy`: the data types of § 1 and reasons for every
  required-reason API in use (for example `UserDefaults` — `CA92.1`).
* Links to Terms, Privacy Policy and Community Guidelines on the sign-up
  screen and in Settings, as on Android.
* Screenshots: 6.9" (1320 × 2868) required; 13" iPad only if iPad is
  declared.
* URLs in App Store Connect: Privacy Policy `https://gasapp.chat/privacy/`,
  Support `https://gasapp.chat/support/`, Marketing — the site root.
