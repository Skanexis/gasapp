<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# GasApp — store submission pack (English)

**Version:** 2026-10-10. Everything a reviewer or the person filling in the
consoles needs, in English. The Russian originals in `docs/store/` remain
the working notes; where they differ from this pack, this pack is newer.

| Document | What it is for |
|---|---|
| [`google-play.md`](google-play.md) | Play Console answers: Data safety, content rating, target audience, app access, UGC, child safety, release |
| [`app-store.md`](app-store.md) | App Store Connect answers: App Privacy, age rating, export compliance, Review Notes |
| [`../listing.md`](../listing.md) | Store listing texts (EN and RU), length-checked by `tools/check-store-listing.py` |
| [`../../security/encryption-map.md`](../../security/encryption-map.md) | What is encrypted, with what, and where the code is — the factual basis for every answer |

## Public pages the stores ask for

Built from this repository by `python tools/build-site.py` and deployed by
`.github/workflows/pages.yml`. **Every URL must be live before submission**:
both stores open them during review.

| Page | URL | Required by |
|---|---|---|
| Privacy Policy | `https://gasapp.chat/privacy/` | Both (listing + in-app) |
| Terms of Use | `https://gasapp.chat/terms/` | Play UGC policy; Apple 1.2 |
| Community Guidelines | `https://gasapp.chat/community-guidelines/` | Play UGC policy; Apple 1.2 |
| Child safety standards | `https://gasapp.chat/child-safety/` | Play Child Safety Standards |
| Account deletion | `https://gasapp.chat/account-deletion/` | Play account-deletion policy |
| Support | `https://gasapp.chat/support/` | Apple (Support URL), Play |
| What is encrypted | `https://gasapp.chat/encryption/` | Reviewers, export-compliance questions |
| `security.txt` | `https://gasapp.chat/.well-known/security.txt` | Good practice (RFC 9116) |

The same pages open from inside the app: **Settings → About → Terms and
documents**, and from the sign-up screen before an account is created. The
app is built with `-PgasappDocsUrl=https://gasapp.chat`.

## Requirements checked on 2026-10-10

| # | Requirement | Source | Status in GasApp |
|---|---|---|---|
| 1 | New apps and updates target **Android 16 (API 36)** from 2026-08-31 | [Play target API](https://support.google.com/googleplay/android-developer/answer/11926878) | ✅ `targetSdk 36`, `compileSdk 36` |
| 2 | 16 KB page-size support for native code | Play / Android 15+ | ✅ checked by `tools/check-16kb-pages.py` |
| 3 | **Anonymous / random chat apps** must block minors with Play Console tools; child-safety standards extended to them (from 2026-08-26) | [Policy announcement 2026-07-15](https://support.google.com/googleplay/android-developer/answer/17134731), [deadlines](https://support.google.com/googleplay/android-developer/table/12921780) | ✅ **Not such an app**: an account needs a verified e-mail, people are found by a username or a link they were given, there is no random matching and no hidden-identity mode. The word "anonymous" was removed from the listing keywords. Target audience is declared 18+ anyway |
| 4 | **Child Safety Standards**: published CSAE prohibition, in-app reporting, CSAM process, named contact | [Developer Program Policy](https://support.google.com/googleplay/android-developer/answer/17190352) | ✅ page + in-app Report for people and channels; 🟡 the `abuse@` mailbox and an on-call person must exist |
| 5 | **User-generated content**: terms accepted by users, published content rules, in-app reporting and blocking, ongoing moderation | same | ✅ Terms + Guidelines linked at sign-up; Report/Block for people; **Report channel** added 2026-10-10; operator console handles both |
| 6 | **Account deletion** in the app and by a web link | same | ✅ in-app; web page explains why deletion is device-signed (see `google-play.md` § 6) |
| 7 | **Data safety form** matches the app | Play Console | ✅ `google-play.md` § 2, rebuilt from `encryption-map.md` |
| 8 | Third-party AI integrations fall under User Data policy | Policy announcement 2026-07-15 | ✅ none: no AI, no analytics, no ads, no crash SDK (`tools/check-no-telemetry.sh`) |
| 9 | All apps **registered in Play Console** (developer verification), from 2026-09-30 | deadlines table | 🟡 operator: done when the app is created in a verified developer account |
| 10 | Personal developer accounts: **closed test, 12 testers for 14 days** before production | Play Console | 🟡 operator |
| 11 | Apps built with the **iOS 26 SDK / Xcode 26** (since 2026-04-28) | [App Store submission requirements](https://developer.apple.com/news/) | 🔴 iOS app is a skeleton; build with Xcode 26 when it exists |
| 12 | Age rating questionnaire incl. **social media capability** questions (required from September 2026) | [Apple news 2026-07-09](https://developer.apple.com/news/?id=tlur8uvi) | ✅ answers in `app-store.md` § 3: public channels found by search = yes |
| 13 | **Export compliance**: non-exempt standard encryption → French declaration or exclude France; US self-classification notice for open source | [Apple export compliance](https://developer.apple.com/help/app-store-connect/reference/export-compliance-documentation-for-encryption) | 🟡 operator: e-mail notice to BIS/NSA before first release; decide on France (`app-store.md` § 2) |
| 14 | Guideline 1.2 (UGC): filter/report/block, published contact; 5.1.1(v) in-app account deletion; privacy manifest | App Store Review Guidelines | ✅ on Android; 🔴 to be carried to iOS |

## What still blocks submission (operator, not code)

1. **A production server** with its domain, and the release build pointed at
   it with real TLS pins (`release/res/xml/network_security_config.xml` still
   holds placeholders).
2. **The site live at `https://gasapp.chat`** (or another domain — then
   change it in `tools/build-site.py --base-url`, the e-mail addresses in the
   documents, and `-PgasappDocsUrl`).
3. **Mailboxes that are read**: `support@`, `abuse@`, `privacy@`,
   `security@`. The documents promise answers within 2 working days and
   abuse review within 24 hours.
4. **A mail service** for sign-up codes, with a data-processing agreement,
   named in the Privacy Policy.
5. **Review accounts** `gasapp_review_1` / `_2` on the production server, one
   of them premium with a test channel, and someone watching them during
   review.
6. **Screenshots and feature graphic** (`google-play.md` § 10).
7. **Decisions**: who handles reports; whether France is in the country list;
   confirm the 18+ age declaration.

## Speeding up review

* Paste the reviewer instructions exactly (`google-play.md` § 5,
  `app-store.md` § 4): the first Tor connection takes up to a minute, and a
  reviewer who is not told so reports the app as broken.
* Keep the demo account answering during review.
* Do not claim what is not true today: no independent audit, no calls, no
  groups, no push. Reviewers compare the listing with the app.
* Link the open source repository and the encryption page in the notes: it
  answers most encryption questions before they are asked.
