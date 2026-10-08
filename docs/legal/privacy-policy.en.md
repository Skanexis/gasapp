<!-- SPDX-License-Identifier: Apache-2.0 -->

# GasApp Privacy Policy

**Version:** 2026-10-07. This is a translation of
[`privacy-policy.md`](privacy-policy.md); if the two differ, the Russian
text is the reference and the difference is a bug — please report it.

> ⚠️ **GasApp has not been released and has not had an independent audit.**
> This document describes how the app works today, not a promise about the
> future. Until there is an audit, everything below is worth exactly as much
> as your ability to check it against the source code — links to the code
> are given where a claim can be verified.

## In short

* We collect nothing about you that is not needed to deliver messages.
* We cannot read your messages.
* We do not know your phone number.
* Creating an account requires an email address: a code is sent to it.
  We do not store the address itself — only a hash of it. The email is
  sent by a mail service, and that service does see the address.
* We do not log your IP address.
* There is no analytics, advertising or crash reporting in the app.
* The only thing that goes to a third party is your email address and
  the confirmation code: to the mail service that delivers the email.

> **What changed on 2026-10-07.** Before this version, registration did
> not ask for an email address and this policy said "we do not ask for
> an email address". It does now. On the same date the product was
> renamed from AEGIS to GasApp, and channels were added.

## What you need to use GasApp

**A username.** You make it up yourself. It is not tied to a phone
number or your real name, and it is not verified.

**An email address.** Needed once — to create the account. The app asks
the server to send a six-digit code to it; the account is created only
with the correct code, and one address gives one account.

🔐 What happens to the address, step by step, without rounding:

* **The server sees the address** at the moment you request the code and
  when you enter it. At that moment it knows both the address and the
  username you chose.
* **The server stores only a hash of the address** (HMAC-SHA-256 under a
  key only the operator holds). A database dump without that key does
  not reveal the address. The hash exists so that a second account
  cannot be created for the same address.
* ⚠️ **An operator who holds the key can check whether an address they
  already know is registered**, and under which username: compute the
  same hash and compare. They cannot list the addresses of all users —
  only test a specific one.
* ⚠️ **The mail service sees the address, the time and the code itself**
  and keeps them in its logs under its own rules. It is not the GasApp
  server, and we cannot delete anything from it. Which service is used
  is the server operator's choice.
* **The code** lives for 15 minutes and survives five wrong entries; its
  hash is erased on registration or one hour after it expires.
* **On the phone** the address sits in the encrypted database only while
  registration is unfinished, and is erased once the account exists.
* **We send no email other than the code.** No newsletters, reminders or
  notifications.
* 🔐 **Email cannot be used to sign in or to recover the account.** The
  address does not replace the recovery key: if you lose the phone and
  the key, the account cannot be brought back by email — and nobody who
  takes over your mailbox gets your account.

If it matters to you that the account is not linked to your main email,
use a separate address for it: the link "address ↔ username" is seen by
the server at registration and by the mail service in the email.

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
| A hash of the email address the account was created with | The address itself (it is not stored after registration) |
| Whether the account has premium and which channels it created | What the channels say and who reads them |

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
* **We do not hand data to third parties — with one exception.** The
  email with the confirmation code is sent by a mail service, which
  receives your email address (see "An email address" above). There is
  nothing else to hand over.

## Channels

A channel is a feed of posts from one author: text, photos and files.
Anyone who has the channel link can read it; only the author can post,
edit and delete.

**What the server knows about a channel:** that it exists, which account
owns it, how many posts and files it has, their size (to the nearest
padding step), the hour each post was published, which posts were edited
and which were deleted.

**What the server does not know about a private channel:**

* 🔐 the title, the description, the avatar, the text of the posts and
  the contents of the files — it stores them as ciphertext. The read key
  is in the channel link, and the link never reaches the server;
* 🔐 who reads the channel. Posts are fetched without your device's
  signature, and the list of channels you read is kept only on your
  phone.

**The subscriber token.** So that a channel can show subscriber and view
counts, and so that you can react to a post, the app makes up a random
token when you add a channel — a separate one for each channel — and
tells the server. The server stores a hash of the token, the number of
the post you have read up to, and your reactions. The token is not tied
to your account or device: requests carrying it are not signed by the
device and, with the built-in Tor, travel on a separate circuit.

⚠️ A token is a pseudonym, not invisibility: the server sees that one
reader of the channel, unknown to it, read up to a certain post and
left a certain reaction. Tokens of the same person in different channels
cannot be linked from the database; on a direct connection without Tor
they can be matched by IP address and request timing. When you remove a
channel from the phone, the app asks the server to erase the token and
its reactions.

**The pass.** So that subscribers cannot be inflated in a loop, a
subscription costs a pass — a single-use right the server issues to your
account (at most forty a day). 🔐 It issues the pass blindly: it signs a
masked number and, when the pass is spent, cannot tell whom it was
issued to. The server knows how many passes an account took over the
last two days; it does not know which channels they went to.

⚠️ What this does not give: if the app had no passes in stock, you take
a pass and spend it at once, and the two events can be matched by time.
The app takes passes in advance and in batches so that this does not
happen.

**Administrators.** A channel owner can appoint administrators, who
publish, edit and delete posts. 🔐 An administrator is known to the
server, as the owner is: the server has to know which accounts to
accept posts from. A reader is still unknown to it. To become an
administrator you show the owner a request; it contains your device
identifier.

**Public channels.** An author can give a channel an `@name` so that it
can be found by search. To do that, the author's app hands the server
the channel link — and the link contains the read key. 🔐 **The server
can read a public channel**: title, posts and files. The app tells the
author so before the switch. If the channel is made private again, the
server stops handing out the link, but what it has already learned is
not forgotten. Even for a public channel the server cannot forge posts:
it does not have the author's signing key.

⚠️ **What channels do not promise.** A channel is not a private
conversation:

* the link is the access itself. Whoever gets it reads the whole
  channel, past and future posts; it cannot be revoked for one reader;
* the server can withhold posts (all or the latest), an edit or a
  deletion mark, but cannot forge a post, reorder posts, bring back the
  old text after an edit, or "delete" a post from readers on its own —
  the author signs all of these;
* subscriber, view and reaction counts are server statistics. Nobody
  signs them, and the server could show any numbers;
* deleting a post erases it from the server and, at their next
  synchronisation, from readers' apps. Copies made outside the app stay;
* the keys of the channels you read and run are part of the backup.
  Whoever obtains the backup file and the recovery key can read those
  channels and post to the ones you run;
* a removed administrator can no longer publish, but acting together
  with the server could rewrite posts published before the removal;
* an `@name` belongs to the server: it decides which channel the name
  leads to. If it matters that you reach a particular author's channel,
  compare the link with the author directly;
* 🔐 when you read a channel, the server sees a request for that channel
  and, on a direct connection without Tor, your IP address. With the
  built-in Tor (the default) it sees a Tor exit relay;
* the channel owner is known to the server: it is the account that
  created the channel.

**Premium.** Only premium accounts can create channels. Premium is a flag
on the account that the server operator sets by hand; there is no
payment in the app and we receive no payment data. The server stores the
flag itself and nothing about why it was granted.

## Tor, bridges and Tor Project services

The built-in Tor connects to the Tor network — volunteer-run relays that
GasApp does not operate. The entry relay (or bridge) sees your IP address,
but not where the connection goes; the connection then leads to the GasApp
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

The GasApp server takes no part in any of this and knows nothing about
bridges.

## Blocking and reporting

**Blocking** happens only on your phone. Messages from a blocked contact
are received and silently dropped; they are not told. The server does not
know about the block: if it did, it would learn that you knew each other.

**A report** goes to the server operator. 🔐 It reveals to the server
**who reported whom** — without that, reports could be neither verified
nor counted. The proof is the sender certificate from their envelope,
signed by the server itself: you can only report someone who actually
wrote to you. **Your conversation is not sent** — the server does not have
it. The reported person is not told.

In the admin center the operator sees the reported account's username and
the **number** of distinct reporters — not who they are. A report is kept
while both accounts exist, or until the operator decides. The decision
(deleting the account or dismissing the reports) is recorded in the
operator log **without the username**: what was done, why, and how many
people reported. The transparency report is built from this log.

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

## Security limitations

No messenger protects against everything. These are the limits of GasApp
today, so you can decide how to use it.

**A contact found by username.** When you look someone up by username,
their key comes from the server, and a dishonest server could hand you a
different one. GasApp checks it against a public key log: you can write
once the same key has stood in the log for at least a day, and every
account checks its own entry every hour, so a swapped key has to be shown
to everyone and gets noticed. Someone who has not opened the app for more
than a day notices only when they return. For full certainty, compare
safety numbers in person or add the person by their QR code or contact
link — then the key does not come from the server at all. Conversations
you already have are not affected: a contact's key is remembered, and a
change is always shown. Every message, the first included, is sealed: the
server does not see who wrote to whom.

**The other person.** Whoever received your message has seen it and can
photograph or remember it. "Delete for everyone" is a request to their
app, not a guarantee.

**Your network address.** With the built-in Tor (the default) the server
does not see it; with a direct connection it does — see
[Tor, bridges and Tor Project services](#tor-bridges-and-tor-project-services).

**Backups and the recovery key** — see
[What stays on your device](#what-stays-on-your-device).

**Notifications** — see [Push notifications](#push-notifications).

**Usernames and inactive accounts** — see
[Usernames and inactive accounts](#usernames-and-inactive-accounts).

**Calls.** There are no calls in this version.

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
tokens and sealed-sender access keys, as well as the hash of the email
address, the premium flag and every channel you created together with
its posts. The address is then free: a new account can be created with
it.

⚠️ Not removed: posts of your channels that readers have already
downloaded stay on their phones, and the mail service's log of the code
email is deleted under that service's rules, not ours.

Removed from the device: the message database (which also holds the
channels you read and the keys of your own channels), the salt, the encrypted
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
GasApp is distributed under AGPL-3.0, and anyone can run their own
instance — its operator's policy then replaces this one.

## Changes

Material changes are published in the repository with the version date.
The history of edits is visible in the `git log` of this file — a
notification mechanism you can trust without relying on us.

## Contact

`privacy@gasapp.chat` — questions about data.
`security@gasapp.chat` — vulnerabilities (`SECURITY.md`).
