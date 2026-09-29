<!-- SPDX-License-Identifier: Apache-2.0 -->

# AEGIS Privacy Policy

**Version:** 2026-09-30. This is a translation of
[`privacy-policy.md`](privacy-policy.md); if the two differ, the Russian
text is the reference and the difference is a bug — please report it.

> ⚠️ **AEGIS has not been released and has not had an independent audit.**
> This document describes how the app works today, not a promise about the
> future. Until there is an audit, everything below is worth exactly as much
> as your ability to check it against the source code — links to the code
> are given where a claim can be verified.

## In short

* We collect nothing about you that is not needed to deliver messages.
* We cannot read your messages.
* We do not know your phone number and do not ask for an email address.
* We do not log your IP address.
* There is no analytics, advertising or crash reporting in the app.
* We do not hand data to third parties, because we do not have it.

## What you need to use AEGIS

**A username.** You make it up yourself. It is not tied to a phone
number, an email address or your real name, and it is not verified.

🔐 Registration does **not** require a phone number. This is not a
convenience but a threat-model decision: a phone number ties the account
to an identity document and makes contact lists usable for matching.

**The camera — only when you scan a QR code.** The permission is requested
at the moment of scanning (to add a contact or to verify a safety number).
Frames are processed on the phone, are not stored and are not sent
anywhere. The app works without the camera: you can find a contact by
username.

**A PIN.** Six digits. We do not know it and cannot learn it: it is not
sent to the server and not stored on the device. The PIN derives the key
that encrypts the database on your phone; a wrong PIN gives a wrong key,
and the database does not open. There is no separate "is the PIN correct"
check — it would mean storing a hint for guessing somewhere.

## What the server sees

| Sees | Does not see |
|---|---|
| That account `alice` has a device | Who Alice is |
| That a device has an undelivered envelope | What is in it |
| The envelope size (to the nearest padding bucket) | Who it is from |
| The device's public keys | Private keys |
| That the device is online right now | Whom it talks to |
| In which month the account was active | On which day and at what time |

🔐 The server **does not know the sender** of any message. The right to
send is proven with the recipient's access key, not with the sender's
signature. For the first message to a new contact, before an access key
exists, a proof-of-work over that very envelope is solved instead.

Before 2026-09-24 the first message was signed by your device, and for a
first contact the server saw who wrote to whom. This policy said so.

🔐 **The key of a contact you found by username is supplied by the server,
and the server could supply its own.** So the app checks it against a
public key log: you can write once the same key has been in the log under
that username for at least a day (accounts older than a day — right away),
and the owner of every username checks their own entry. The server would
have to show a substitution to everyone, and it would be noticed. Queries
to the log are anonymous: the server does not learn whose name is checked.
The strongest check is to scan your contact's QR code in person: it
carries their key and does not pass through the server.

⚠️ **The last row is about presence — please read it carefully.** So that
messages arrive immediately rather than on refresh, the app keeps a
connection to the server while the chat list or a conversation is open.
The connection is per device, not per chat: the server does not learn
*which* conversation you opened.

But it does see that one is open: when the connection appeared, when it
dropped and how long it lasted. Such a trace reveals a daily routine — and
that two people tend to be online at the same time. Encrypting the content
does not protect against this: it is not content.

⚠️ There is no background connection in any build today (see "Push
notifications" below): the presence trace described above is the same for
everyone.

The full list of what is stored and for how long is in
[`data-retention-policy.md`](data-retention-policy.md).

## What we do not do

* **By default we do not even see IP addresses.** The app connects through
  Tor, built into the app itself, and the server sees the address of a Tor
  node, not yours. A direct connection is enabled only explicitly, with a
  warning that the server will see your address.
* **We do not learn who checks keys.** The key log (which the app uses to
  check a contact's key without meeting in person) is queried without the
  device signature and over a separate Tor circuit. The log holds a hash of
  the username and a public key, which the server stores anyway.
* **We do not log IP addresses.** The application does not see addresses at
  all: its rate limiters work on the username and device identifier. The
  load balancer in front of it does see the address — otherwise username
  enumeration could not be stopped — but keeps it only in the rate limiter's
  memory; access logging is off (`server/deploy/РАЗВЁРТЫВАНИЕ.md`). The
  address never reaches disk or the application servers.
* **No analytics.** The app contains no third-party analytics, advertising
  or crash-reporting SDK; CI checks this (`tools/check-no-telemetry.sh`).
* **We do not read metadata "to improve the service".** There will be no
  such line in this policy.
* **We do not request access to contacts, the gallery or the microphone
  "just in case".** Files are picked through the system dialog, which gives
  the app exactly the chosen file and nothing else.
* **We do not hand data to third parties.** There is nothing to hand over.

## Tor, bridges and Tor Project services

The built-in Tor connects to the Tor network — volunteer-run relays that
AEGIS does not operate. The entry relay (or bridge) sees your IP address,
but not where the connection goes; the connection then leads to the AEGIS
server's onion service, and no exit relay is involved at all when the
build knows that address.

**Where Tor is blocked**, the app connects through bridges on its own:

* **Bridges built into the app**, if any — run by the project.
* **Fresh bridges from Tor Project.** If the Tor network cannot be reached
  directly, the app asks moat — a Tor Project service that Tor Browser uses
  in the same way — for bridges, at most once every ten minutes. The
  request goes through a CDN, looking like a visit to a large website. Tor
  Project sees your IP address and that bridges were requested from it;
  **your country, username or anything else about you is not sent.** The
  answer — a list of bridge addresses — is kept on the device outside the
  encrypted database: it is needed to connect before the PIN is entered,
  and it reveals only what the installed app reveals anyway — that it uses
  Tor bridges.
* **Bridges you enter yourself.**

The AEGIS server takes no part in any of this and knows nothing about
bridges.

## Push notifications

⚠️ **There are no push notifications in any build today.** A new message
arrives while the chat list or a conversation is open; the rest arrive
the next time you open the app. Notifications for messages that arrive
while the app is closed are not shown.

This section used to describe delivery through Firebase in the build with
Google services and a persistent connection in the F-Droid build. Neither
existed in the app: both implementations were stubs, and the server does
not send push.

When push arrives, it will work as follows, and this section will be
updated with it:

* 🔐 a notification will carry **only a "something new" flag** — no text,
  no sender, no chat. Anything in the payload would be seen by Apple and
  Google;
* the F-Droid build will do without them, keeping its own connection, at
  the cost of battery.

## What stays on your device

Messages, contacts, keys and vault files are stored **only** on the device,
in a database encrypted with SQLCipher. The key is derived from your PIN
and from a secret that never leaves the phone's hardware-backed storage.

We have no access to this database and cannot restore it for you. A
backup is your choice, and it is encrypted with a recovery key that only
you know.

🔐 **Disappearing messages are not included in backups.** An uploaded
backup lives with whoever stores it, and nothing can erase a message from
it on a timer. So a restore never brings disappearing messages back — even
those whose time has not run out yet. ⚠️ Before 2026-09 they were included
together with their timer, and the timer only worked on the device.

⚠️ **A deleted message remains in backups made before the deletion.**
Restoring the whole backup chain removes it again (the backup carries a
deletion mark). But restoring from an old backup, or from a chain missing
its last links, brings it back: the app has no way to be sure the chain is
complete — files in someone else's storage carry no trustworthy "last
link" mark.

⚠️ **Losing the recovery key means losing your messages.** This follows
directly from our inability to read them. Promising otherwise would mean
promising access we must not have.

## Your rights and how to exercise them

| Right | How |
|---|---|
| Learn what is stored about you | Listed in the data retention policy; there is nothing beyond it |
| Delete your messages | In the app, locally; they are not on the server |
| Delete your account | Settings → Privacy → Delete account — see below |
| Take your data with you | Settings → Privacy → Export my data — see below |

### Data export

In the app: Settings → Privacy → Export my data. You get a JSON file with
your username, contacts, messages and settings. The format is open: a
person and another program can read it — a right to take your data in a
closed format is no right at all.

**⚠️ The file is not encrypted.** This is deliberate: an encrypted export
is not portable, and the point of an export is to take data where it can
be read. But whoever gets this file gets all your messages. The app warns
you about this before you choose where to save it.

**The export contains no keys** — neither the private identity key, nor the
ratchet state, nor the recovery key. So an account cannot be restored from
it: that is what the backup is for, and the backup is encrypted. These are
different tasks and must not be mixed — portability needs readability,
recovery needs secrecy.

### Usernames and inactive accounts

A username belongs to the account for as long as the account exists.
Reinstalling the app does not free it. You can bring the account back
with the same username on a new phone from a backup: "Restore my account
from a backup" on the registration screen. The backup holds the account
recovery key; the server stores only its public part and, after checking
the signature, re-binds the account to the new device. The safety key is
new, and contacts need to verify the safety number again: the private
identity key is never copied between devices.

An account nobody has signed in to for **12 months** is deleted by the
server entirely — just as when deleted by its owner — and the username is
freed. For this the server stores only the **month** of last activity,
without day or time: exact times would be a presence log.

### Deleting your account

In the app: Settings → Privacy → Delete account. There are two
confirmations, and they are not a formality: nobody, including the server
operator, can bring a deleted account back.

Removed from the server: the username, the identity key, all devices of
the account, signed and one-time prekeys, undelivered envelopes, push
tokens and sealed-sender access keys.

Removed from the device: the message database, the salt, the encrypted
hardware secret, the wrapping key in Android Keystore and the history of
PIN attempts.

The app shows numbers — how many devices, envelopes and attachments were
deleted. A "done" without numbers is indistinguishable from a "done" for
a request that did nothing, and after deletion there is nothing left to
check it with.

**⚠️ What deletion does not do.**

* **Messages that were already delivered stay with your contacts.** They
  are on their devices, and the server cannot reach them — that is what
  end-to-end encryption means.
* **Attachments stay on the server until they expire — both those sent to
  you and those you sent.** Uploads are anonymous: the server does not know
  who uploaded a file and has nothing to link it to an account with. They
  disappear after thirty days, together with all others; the server does
  not know whom they were meant for — that link is inside the ciphertext,
  and knowing it would mean keeping a graph of who sends files to whom.
* **The username is freed.** Anyone can take it. This does not let them
  impersonate you: the identity key will be different, and everyone who
  verified your safety number will get a key-change warning. Holding a
  username forever would mean keeping a record of the deleted account —
  that is, not deleting it.
* **Erasing on the device means deleting files, not wiping cells.** On
  flash memory, an overwrite does not land in the same cells, and promising
  unrecoverability would be untrue. The guarantee here is different: the
  database content is encrypted, and the wrapping key in Android Keystore
  is removed irreversibly — leftovers recovered from the disk cannot be
  opened.

If deletion on the server fails (no connection), **nothing is touched** on
the device, and you can try again. The opposite order would leave you
without your messages but with a live account on the server, and with no
way to retry: the request is signed with the device key.

## Children

The app is not intended for children under 13. We cannot check age without
collecting data we do not collect, so we do not check it, and we say so
plainly.

## Where the data is stored

On the server run by the operator of an instance. For the official
instance, the hosting location will be stated here before release 1.0.
AEGIS is distributed under AGPL-3.0, and anyone can run their own
instance — its operator's policy then replaces this one.

## Changes

Material changes are published in the repository with the version date.
The history of edits is visible in the `git log` of this file — a
notification mechanism you can trust without relying on us.

## Contact

`privacy@aegis.chat` — questions about data.
`security@aegis.chat` — vulnerabilities (`SECURITY.md`).
