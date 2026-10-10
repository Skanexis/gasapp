<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# What is encrypted in GasApp — and what is not

**Version:** 2026-10-10. A map for users, reviewers and auditors: every
kind of data GasApp handles, who can read it, and where the code is. It is
also the factual basis for the store questionnaires (Data safety, App
Privacy, export compliance).

> ⚠️ GasApp has not had an independent security audit. Every row below can
> be checked against the source code named in it.

## In one paragraph

Private messages, attachments, buttons and reactions in chats are
end-to-end encrypted between devices; the server relays ciphertext it
cannot read. Channel content is encrypted with a channel key the server
does not have — unless the owner makes the channel public, which hands the
server the key. Everything on the device is in an encrypted database. All
traffic is TLS 1.3 with a pinned certificate, by default inside Tor. The
server knows account names, a hash of the e-mail address, who subscribes
to which channel, and timing — the full list is at the end.

## Data in transit

| Link | Protection | Code |
|---|---|---|
| App ↔ server | TLS 1.3 only (1.2 refused), certificate pinning, no cleartext traffic allowed by the manifest | `server/gasapp-server-api/src/tls.rs`, `android/.../network_security_config.xml` |
| App ↔ network | Tor by default (embedded Arti, onion service of the server when configured); direct connection only by explicit choice | `crates/gasapp-tor` |
| Every authenticated request | Signed by the device key over method, path, time and body hash; stale or altered requests are refused | `crates/gasapp-net/src/auth.rs`, `server/gasapp-server-api/src/authz.rs` |
| Bot engine ↔ server | TLS 1.3 with public-CA validation; **no Tor, no pinning** | `crates/gasapp-bot/src/http.rs` |

## Private conversations (end-to-end)

| Data | Who can read it | How | Code |
|---|---|---|---|
| Message text, replies, edits, deletions | The two devices | PQXDH key agreement (X25519 + ML-KEM-1024), Double Ratchet, AES-256-GCM | `crates/gasapp-protocol/src/pqxdh.rs`, `double_ratchet.rs` |
| Attachments (photos, files, voice) | The two devices | Random per-file key, XChaCha20-Poly1305 in chunks, size padded; the key travels inside the encrypted message | `crates/gasapp-media/src/attachment.rs` |
| Buttons under a message and button presses | The two devices | Ordinary message content kinds inside the same session | `crates/gasapp-protocol/src/keyboard.rs` |
| Who sent a message | Recipient only | Sealed sender: the envelope hides the sender from the server (X25519 + ML-KEM-1024) | `crates/gasapp-protocol/src/sealed_sender.rs` |
| Message size | Hidden to padding buckets | Padding before encryption | `crates/gasapp-protocol/src/padding.rs` |

What the server stores for a conversation: an opaque envelope until it is
delivered (30 days at most), then nothing.

**Not covered.** Post-quantum protection applies to session setup only, not
to the ratchet. A key that only the server named is not trusted for
sending: it must be confirmed by a contact link/QR, a safety-number check,
or the key-transparency log.

## Channels

| Data | Who can read it | How | Code |
|---|---|---|---|
| Title, description, avatar, posts, files | Anyone holding the channel key | AES-256-GCM under a key derived from the channel secret; every record signed by the owner or an administrator (Ed25519) | `crates/gasapp-protocol/src/channel.rs` |
| Channel key of a **link** channel | Whoever has the link | The link carries the secret; it never reaches the server | same |
| Channel key of a **public** channel (`@name`) | Whoever has the link **and the server** | The owner hands the link to the server so the channel can be found by name | same |
| Channel key of a **closed** channel | Approved members only | Sealed to each member's one-time **hybrid** key (X25519 + ML-KEM-1024 → HKDF → AES-256-GCM): stored grants cannot be opened later by breaking one curve. A new key after every removal of a subscriber or administrator | `crates/gasapp-protocol/src/channel_join.rs` |
| A report about a channel | The operator | Sent over TLS; the channel key is attached **only if the reporter chooses to** | `crates/gasapp-core/src/client/channel_closed.rs` |

**Not covered.** A channel is not a private conversation: no forward
secrecy; everyone with the key reads everything published under it.
Subscriber counts, views and reactions are server statistics, not signed.

## On the device

| Data | Protection | Code |
|---|---|---|
| Messages, contacts, keys, channel keys | SQLCipher database; its key is wrapped by a hardware-backed key (Android Keystore) and unlocked by the PIN | `crates/gasapp-storage`, `crates/gasapp-keystore` |
| App lock | 6-digit PIN with Argon2id and attempt limits | `crates/gasapp-core/src/lock.rs` |
| Vault for files | Second factor, separate key | `crates/gasapp-core/src/vault.rs` |
| Screenshots, recent-apps preview | Blocked by default | `android/.../core/SecureWindow.kt` |
| System backups | Disabled (`allowBackup=false`, extraction rules exclude everything) | `AndroidManifest.xml` |
| Backup file you create | Zero-knowledge: Argon2id from a 256-bit recovery key, XChaCha20-Poly1305; without the key it is noise | `crates/gasapp-backup` |

## On the server

| Data | Stored as | Until |
|---|---|---|
| Username, account and device identifiers, public keys | Plain | Account deletion |
| E-mail address | **Not stored.** A keyed hash (HMAC-SHA-256) only | Account deletion |
| Undelivered envelopes and attachments | Ciphertext | Delivery, 30 days at most |
| Channel records and files | Ciphertext (readable by the server only for public channels) | Deletion by the author or with the channel |
| Who subscribes to which channel, read position, reactions | Plain | Unsubscribe or deletion |
| Join requests and key grants of closed channels | Public keys and ciphertext | Answer / removal |
| Reports | Reporter, reported account or channel, reason; for chats — a server-signed sender certificate, never the conversation | Operator decision |
| IP addresses | **Not logged** | — |

Details and retention periods: the data retention policy
(`docs/legal/data-retention-policy.md`).

## What is deliberately not encrypted end-to-end

* **Account names and the social graph of channels.** The server knows
  usernames, which account owns or administers a channel, and which
  accounts subscribe to it. This is what makes counts impossible to
  inflate.
* **Public channels.** By design the server can read them.
* **Timing and sizes.** The server sees when envelopes arrive and their
  padded size.
* **Bots.** A bot's keys live on its owner's machine, next to its
  database; the bot engine does not use Tor.

## Algorithms

Standard, published algorithms only — no proprietary cryptography:

X25519, Ed25519/XEdDSA, ML-KEM-1024 (FIPS 203), ML-DSA-65 (FIPS 204),
AES-256-GCM, XChaCha20-Poly1305, SHA-256, SHA-512, HMAC-SHA-256,
HKDF-SHA-256, Argon2id, TLS 1.3.

Protocol specification: `docs/protocol/GASAPP-PROTOCOL-v1.md`.
