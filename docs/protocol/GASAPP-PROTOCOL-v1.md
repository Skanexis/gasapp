# GasApp PROTOCOL VERSION 1.0

This document specifies the GasApp protocol version 1.0, which combines post-quantum cryptography with modern ratchet-based encryption to provide forward secrecy, post-compromise security, and resistance to quantum attacks.

> **Status: draft, reconciled with the implementation on 2026-08-14.**
>
> Every construction below corresponds to code in `crates/gasapp-protocol`
> that compiles and passes its tests. An earlier revision of this document
> described a design that did not: it specified the AEAD nonce as derived
> from the message counter and chain keys as derived through HKDF with a
> single shared label. Both are unsafe — the first repeats the (key, nonce)
> pair on the first message of every chain, the second links the message key
> to the next chain key — and both were corrected in the implementation
> before this document was updated to match.
>
> **The specification is not independently verified.** No reference vectors
> exist for PQXDH, the Double Ratchet or SPQR (§11), so agreement between
> this text and the code does not establish that either is correct. Read
> §11 before relying on this document for an audit.

## Table of Contents
1. [Introduction](#1-introduction)
2. [Protocol Overview](#2-protocol-overview)
3. [Cryptographic Primitives](#3-cryptographic-primitives)
4. [PQXDH Key Exchange](#4-pqxdh-key-exchange)
5. [Double Ratchet](#5-double-ratchet)
6. [SPQR Ratchet](#6-spqr-ratchet)
7. [Message Encryption Format](#7-message-encryption-format)
8. [Key Derivation Functions](#8-key-derivation-functions)
9. [Fingerprint Calculation](#9-fingerprint-calculation)
10. [Security Considerations](#10-security-considerations)
11. [Test Vectors](#11-test-vectors)
12. [Implementation Notes](#12-implementation-notes)

## 1. Introduction

GasApp is a secure messaging protocol designed to provide:
- Forward secrecy
- Post-compromise security
- Resistance to quantum computer attacks
- Deniability
- Insider security

The protocol combines:
- PQXDH (Post-Quantum Extended Diffie-Hellman) for initial key exchange
- Double Ratchet for synchronous communication
- SPQR (Sparse Post-Quantum Ratchet) for asynchronous/post-quantum security

## 2. Protocol Overview

The GasApp protocol operates in phases:

1. **Initial Key Exchange (PQXDH)**: Establishes a shared secret using a combination of classical X25519 Diffie-Hellman and ML-KEM-1024 key encapsulation mechanism.

2. **Ratchet Phase**: After the initial exchange, the protocol uses a combination of:
   - Double Ratchet (X25519 + HMAC-SHA-256) for synchronous messages
   - SPQR (ML-KEM-768 + X25519 + HMAC-SHA-256) for asynchronous messages

3. **Message Encryption**: Messages are encrypted using AES-256-GCM with keys derived from the ratchet state.

## 3. Cryptographic Primitives

GasApp v1.0 uses the following cryptographic primitives:

- **X25519**: Elliptic curve Diffie-Hellman over Curve25519
- **ML-KEM-1024**: Module-Lattice-Based Key-Encapsulation Mechanism (NIST FIPS 203)
- **ML-KEM-768**: Module-Lattice-Based Key-Encapsulation Mechanism (NIST FIPS 203) - used in SPQR
- **ML-DSA-65**: Module-Lattice-Based Digital Signature Algorithm (NIST FIPS 204) — the
  post-quantum half of the identity (§4.4); deterministic signing with a
  domain context string
- **HKDF-SHA-256**: HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869)
- **HMAC-SHA-256**: Hash-based Message Authentication Code (RFC 2104)
- **SHA-512**: Secure Hash Algorithm 512-bit (FIPS 180-4)
- **AES-256-GCM**: Advanced Encryption Standard in Galois/Counter Mode (NIST SP 800-38D)
- **XEdDSA**: signatures made **with an X25519 key**, by transporting the
  point between its Montgomery and Edwards representations. This is what
  lets a single key pair serve both Diffie-Hellman and signing. Note that
  plain Ed25519 cannot verify a signature under an X25519 public key: the
  encodings differ, and conflating them yields an implementation whose
  bundle verification can never succeed. The signing scalar is clamped
  exactly as X25519 clamps it (RFC 7748 §5), so the public key derived for
  signing equals the one used for DH; signatures are deterministic
  (nonce derived from key and message, never from an RNG)

## 4. PQXDH Key Exchange

The PQXDH key exchange combines classical and post-quantum key exchange to provide security against both classical and quantum adversaries.

### 4.1. Messages

The PQXDH protocol consists of a single message from the initiator to the responder:

```
Initiator -> Responder: X25519(IK_A) || X25519(EK_A) || ML-KEM-1024.Encapsulate(PQSPK_B)
```

Where:
- `IK_A`: Initiator's identity key (X25519)
- `EK_A`: Initiator's ephemeral key (X25519)
- `PQSPK_B`: Responder's signed post-quantum pre-key (ML-KEM-1024 public key)

### 4.2. Key Exchange Computation

Upon receiving the PQXDH message, both parties compute the shared secret as:

```
T  = SHA-256("GASAPP_PQXDH_v2_TRANSCRIPT" || IK_A || IK_B || EK_A || SPK_B
             || len(CT_pq) as u64 big-endian || CT_pq)

SK = HKDF-SHA-256(
    salt = T,
    IKM  = F || DH1 || DH2 || DH3 || [DH4] || SS_pq,
    info = "GASAPP_PQXDH_v2_X25519_MLKEM1024_TRANSCRIPT"
)
```

**Transcript binding (v2, 2026-09).** The salt is the hash of the public
transcript: both identity keys, the initiator's ephemeral key, the
responder's signed pre-key and the ML-KEM ciphertext. Version 1 used a
zero salt and no associated data, deviating from X3DH/PQXDH, which require
`AD = IK_A || IK_B`. This was not exploitable — both identities already
enter the secret through DH1 and DH2 — but the parties never confirmed
that they saw the same exchange, and PQXDH revision 3 recommends binding
the KEM ciphertext. Binding the transcript into the root is stronger than
AD on the first message alone: every later key derives from the root, so
any disagreement makes the very first message fail to decrypt. The KEM
public key needs no separate binding: the ML-KEM shared secret is derived
with `H(ek)`.

**Contributory DH.** Every X25519 computation rejects a non-contributory
result (a small-order peer key would otherwise yield an all-zero secret
known to anyone).

Where:
- `F`: 32 bytes of 0xFF for domain separation
- `DH1 = DH(IK_A, SPK_B)` — authenticates the initiator
- `DH2 = DH(EK_A, IK_B)` — authenticates the responder
- `DH3 = DH(EK_A, SPK_B)` — forward secrecy
- `DH4 = DH(EK_A, OPK_B)` — forward secrecy for the first message; present
  only while the one-time pool is not exhausted
- `SS_pq`: ML-KEM-1024 shared secret, encapsulated to PQOPK_B when
  available and to PQSPK_B otherwise

**DH1 and DH2 are not interchangeable.** Swapping them would make the
exchange symmetric, and an initiator's message indistinguishable from a
responder's.

**An absent DH4 is omitted, not zero-filled.** Substituting a zero block
would make an exhausted pool indistinguishable from an exchange whose DH4
computed to zero — and a zero X25519 output indicates a small-order point,
i.e. an attack.

### 4.3. PreKey Bundle

Each party publishes a PreKeyBundle containing:

| Field | Type | Rotation | Signed |
|---|---|---|---|
| Identity key (IK) | X25519, long-term | never | — |
| Signed pre-key (SPK) | X25519 | every 7 days | yes |
| One-time pre-key (OPK) | X25519, pool of 100 | on use | no |
| Signed PQ pre-key (PQSPK) | ML-KEM-1024 | every 7 days | yes |
| One-time PQ pre-key (PQOPK) | ML-KEM-1024, pool of 100 | on use | yes |

Signatures are **hybrid** (§4.4) — XEdDSA ‖ ML-DSA-65 — and MUST be verified
**with both halves of the bundle owner's identity** before any cryptographic
operation on the bundle. A failed
verification aborts session establishment; there is no degraded mode.

OPK carries no signature because substituting it gains an attacker nothing:
the shared secret still includes SPK, which is signed, so a substituted OPK
only causes the secrets to disagree. PQOPK is signed because the
post-quantum contribution is singular — substituting it would nullify
quantum resistance.

A bundle missing either one-time key is usable but **degraded**: forward
secrecy of the first message is weakened. Implementations MUST surface this
rather than fail, and SHOULD record it, since systematic pool exhaustion may
indicate an attacker draining a peer's pre-keys.

### 4.4. Hybrid Identity (ML-DSA-65)

Every account has a second, post-quantum half of its identity: an ML-DSA-65
key pair (FIPS 204) derived from its **own** 32-byte seed. The seed is never
derived from the X25519 identity key: a quantum adversary recovers that key
from its public half and would then recover the seed too.

```
PQ     = ML-DSA-65 public key                         -- 1952 bytes
bind   = hybrid_sign("GASAPP_PQID_BIND_v1",
                     "GASAPP_PQID_BIND_v1" || IK || PQ)
hybrid_sign(ctx, m) = XEdDSA_IK(m) || ML-DSA-65_PQ(m, ctx)   -- 64 + 3309 bytes
H(PQ)  = SHA-256("GASAPP_PQID_HASH_v1" || PQ)
```

A hybrid signature verifies only if **both** halves verify. ML-DSA signs with
a domain context, so one signed item cannot stand in for another:

| Item | Context |
|---|---|
| SPK | `"GASAPP_PQSIG_SPK_v1"` |
| PQSPK | `"GASAPP_PQSIG_KEM_v1"` |
| PQOPK | `"GASAPP_PQSIG_OTKEM_v1"` |
| Sealed-sender ML-KEM key | `"GASAPP_PQSIG_SEALED_KEM_v1"` |

The server stores and serves `PQ` and `bind` next to `IK`; it verifies
nothing. Clients MUST:

1. verify `bind` against `IK` and `PQ` before trusting any signature made
   with `PQ` — otherwise a server could pair a real `IK` with its own `PQ`;
2. remember `H(PQ)` at first contact (or take it from the peer's contact
   link) and refuse a different one as an identity change;
3. require that the bundle's `PQ` has the remembered hash.

`H(PQ)` enters the safety number (§9.2) and the contact link (§9.3), so an
in-person comparison covers both halves.

## 5. Double Ratchet

The Double Ratchet provides forward secrecy and post-compromise security for synchronous communication.

### 5.1. Ratchet Steps

The Double Ratchet consists of two ratchets:
1. **DH Ratchet**: advances when receiving a message with a new DH public key
2. **Symmetric Ratchet**: advances with each message sent or received

### 5.2. Key Derivation

See §8 for the normative definitions. In summary:
- New root key and chain key: `HKDF-SHA-256(salt=root_key, IKM=DH_output)`,
  64-byte output split in half
- Chain advancement: `HMAC-SHA-256(chain_key, 0x02)`
- Message key: `HMAC-SHA-256(chain_key, 0x01)`

### 5.3. Message Header

Each message includes a 40-byte header, transmitted in the clear and
authenticated as AEAD associated data:
- DH ratchet public key (32 bytes)
- Previous chain length (4 bytes, **big-endian**)
- Message number in the current chain (4 bytes, **big-endian**)

**The header MUST be authenticated.** It selects the decryption key at the
receiver, so an unauthenticated header would let an attacker alter the
message number and force the receiver to derive and store an arbitrary
number of skipped keys.

## 6. SPQR Ratchet

> ⚠️ **Implementation status (2026-09): specified and implemented in
> `gasapp-protocol::spqr`, not wired into sessions.** The session layer
> (`gasapp-core::session`) calls `RatchetState::encrypt` / `decrypt`, which
> pass no post-quantum component; every message key is `MK_classic` alone.
> The guarantee in §6.3 — "it is never left without one" — does not hold
> in the current client.
>
> What still holds: the Double Ratchet is seeded from the PQXDH secret,
> which includes ML-KEM-1024, so recorded traffic cannot be decrypted by
> breaking X25519 alone. What is missing: post-compromise recovery against
> a quantum adversary, which is what SPQR epochs provide.

The SPQR (Sparse Post-Quantum Ratchet) extends the Double Ratchet with post-quantum security by incorporating ML-KEM-768.

### 6.1. Ratchet Steps

SPQR adds a post-quantum ratchet step:
1. **DH Ratchet**: advances when receiving a message with a new DH public key
2. **PQ Ratchet**: advances periodically or based on message count using ML-KEM-768
3. **Symmetric Ratchet**: advances with each message sent or received

### 6.2. Key Derivation

The post-quantum ratchet maintains its own root, advanced on each completed
PQ step with the ML-KEM shared secret:
```
pq_root = HKDF-SHA-256(salt=pq_root, IKM=kem_shared_secret)["GASAPP_SPQR_v1_PQ_ROOT"]
```
The current `pq_root` is combined with the classical message key as
specified in §8.3. The two ratchets advance independently: the classical one
on every message, the post-quantum one only when a full KEM exchange
completes.

### 6.3. Post-Quantum Material

SPQR does not extend the message header. Post-quantum material travels as
chunks alongside messages (§6.4), because an ML-KEM-768 encapsulation key is
1184 bytes and a ciphertext 1088 bytes — attaching either to every message
would roughly triple traffic. This is what "sparse" denotes.

Until a PQ step completes, the session continues under the current
post-quantum secret; it is never left without one.

### 6.4. Chunking

ML-KEM material is split for transmission:
- Chunk payload: 128 bytes (encapsulation key spans 10 chunks, ciphertext 9)
- Each chunk carries: epoch (4 bytes), index (2), total (2), payload
- Maximum 32 chunks per epoch, bounding receiver memory

Reassembly tolerates loss, duplication and out-of-order arrival: chunks are
stored by index and released only when all are present. Chunks of a stale
epoch are discarded so that material from adjacent steps cannot mix.

## 7. Message Encryption Format

GasApp messages use AES-256-GCM:

```
Message = Header (40 bytes) || Ciphertext || AuthTag (16 bytes)
```

Where:
- **Header**: DH ratchet key, previous chain length, message number (§5.3).
  Sent in the clear and passed to AEAD as associated data
- **Ciphertext**: encrypted plaintext
- **AuthTag**: 16-byte GCM tag covering both ciphertext and header

The nonce is **not transmitted**: both parties derive it from the message
key (§7.1). Sending it would waste 12 bytes per message and offer an
attacker a field to manipulate.

### 7.1. Nonce Generation

The AEAD nonce is derived from the **message key**, not from a counter:
```
Nonce = first_12_bytes(HKDF-SHA-256(salt=none, IKM=message_key)["GASAPP_DR_v1_NONCE"])
```

> ⚠️ Corrected 2026-09. This section previously named `GASAPP_AEAD_v1_NONCE`.
> That label exists, but belongs to the outer sealed-sender AEAD layer
> (`aead::seal_with_key`); Double Ratchet messages use `GASAPP_DR_v1_NONCE`
> (`double_ratchet.rs`). The spec check (`tools/check-protocol-spec.py`)
> passed anyway, because it only verifies that a label occurs somewhere
> in the code — not that it is used where the spec says.

**Rationale.** A counter-derived nonce is unsafe here: the message counter
resets to zero on every DH ratchet step, so the (key, nonce) pair would
repeat on the first message of every new chain. In AES-GCM a repeated
(key, nonce) pair reveals the XOR of both plaintexts and permits tag
forgery. Message keys are unique by construction, so deriving the nonce
from the key makes nonce collision exactly as unlikely as key collision.

## 8. Key Derivation Functions

GasApp uses HKDF-SHA-256 (RFC 5869) for key derivation and HMAC-SHA-256 for
symmetric chain advancement, with domain separation by distinct labels.

### 8.1. Root Key Derivation

On each DH ratchet step the previous root key acts as the HKDF salt and the
Diffie-Hellman output as input key material:
```
(new_root_key, chain_key) = HKDF-SHA-256(salt=root_key, IKM=dh_output)["GASAPP_DR_v1_ROOT"]
```
The 64-byte output is split: first 32 bytes become the new root key, the
remaining 32 the chain key.

### 8.2. Chain Key Derivation

Chain advancement uses **HMAC with distinct constants**, not HKDF:
```
next_chain_key = HMAC-SHA-256(chain_key, 0x02)
message_key    = HMAC-SHA-256(chain_key, 0x01)
```

**Rationale.** The two outputs must be independent: knowledge of a message
key must not yield the next chain key, or forward secrecy fails. Distinct
constants under the same HMAC key provide that independence. Deriving both
through HKDF with a single shared label — as an earlier draft of this
document specified — makes them related and breaks the property.

### 8.3. Hybrid Message Key (Triple Ratchet)

> ⚠️ Implementation status (2026-09): **not in effect** — see §6. Sessions
> pass no post-quantum component, and the message key is `MK_classic`.

The final message key combines the classical and post-quantum halves:
```
message_key = HKDF-SHA-256(salt=none, IKM=MK_classic || MK_pq)["GASAPP_TripleRatchet_v1"]
```
Both inputs are mandatory. An adversary holding only one of them cannot
derive the message key (see §10.4).

## 9. Fingerprint Calculation

> ⚠️ Rewritten 2026-09 to match the code (`gasapp-protocol::fingerprint`,
> `gasapp-core::client::safety_number_of`). The previous text described
> a different iteration (`H_i = SHA-512(H_{i-1})`), no version bytes,
> an identifier "e.g. phone number or username", and no ordering rule —
> none of which is what the client computes.

### 9.1. Fingerprint of one party

```
h_0 = SHA-512(0x00 || 0x00 || IK || identifier)
h_i = SHA-512(h_{i-1} || IK)        for i = 1 .. 5200
fingerprint = first 30 bytes of h_5200
```

In short: `fingerprint = first_30_bytes(SHA-512^5200(...))` — 5200 chained
rounds, each mixing `IK`, over the version-prefixed input.

* `0x00 || 0x00` — fingerprint format version. A different version gives
  an entirely different fingerprint, so numbers of different versions
  cannot be mistaken for one another.
* `IK` is mixed into **every** round, not only the first.
* `identifier` = the 16-byte account identifier **derived from `IK`**
  (its first 16 bytes). It is derived rather than taken from the server,
  because both parties must use the same identifier for each participant,
  and a server-assigned account id is not known the same way to both
  (a contact added by name vs. learned from an incoming message).

**Hybrid fingerprint (format version 1).** The safety number is computed
over both halves of the identity (§4.4):

```
K   = IK || H(PQ)                                   -- 64 bytes
h_0 = SHA-512(0x00 || 0x01 || K || identifier)
h_i = SHA-512(h_{i-1} || K)        for i = 1 .. 5200
```

The version bytes differ from the classical fingerprint, so a hybrid number
cannot be mistaken for a classical one of the same key.

### 9.2. Safety number

```
(first, second) = sort_lexicographically(fingerprint_A, fingerprint_B)
safety_number   = digits(first) || digits(second)       -- 60 digits
digits(fp)      = for each 5-byte group g of fp:
                      five decimal digits of (big-endian u40(g) mod 100000)
```

Sorting makes both parties obtain the same 60 digits although "own" and
"peer" are swapped between them. Display: 12 groups of 5 digits (ADR-022).

### 9.3. Contact links

`gasapp://contact/<base32(IK)>.<base32(H(PQ))>[?name=...]`. The hash of the
post-quantum half is mandatory: a link without it would vouch for the
classical half only. A client adding a contact by link records `H(PQ)`
from the link and refuses a server-supplied `PQ` with a different hash.

### 9.4. Account recovery

A username belongs to its account; the private identity key never leaves a
device. To keep the account after a reinstall, the account holds a separate
**recovery key** (X25519/XEdDSA + ML-DSA-65). Its public halves are given to
the server at registration; its secret travels only inside the encrypted
backup. A new install creates a new identity and sends:

```
m   = "GASAPP_ACCOUNT_RECOVER_v1"
      || len32(username) || username
      || len32(IK') || IK' || len32(DIK') || DIK'
      || len32(PQ') || PQ' || len32(bind') || bind'
      || issued_at_ms (i64, big-endian)
sig = hybrid_sign("GASAPP_ACCOUNT_RECOVER_v1", m)   -- with the recovery key
```

The server verifies both halves, requires `issued_at` within five minutes
and newer than the previous recovery (replays fail), deletes the account's
devices and installs the new identity. Peers see an identity change and
must compare safety numbers again.

### 9.5. Usernames

A username is canonical: lowercase ASCII letters, digits and `_`, starting
with a letter, 3 to 32 characters. Clients lowercase ASCII input and strip a
leading `@`; anything else that does not fit is refused, never cleaned up.
The server and its database enforce the same rule. Without it, `alice`,
`Alice` and `аlice` (Cyrillic `а`) were distinct accounts that look alike.

### 9.6. Key confirmation before sending

A peer's identity key obtained from the server by username is **not trusted
for sending**. A client refuses to encrypt to it (`PeerUnconfirmed`) until the
key is confirmed out of band, either by comparing the safety number or by
adding the peer from their own contact link or QR code, which carries the
identity key itself. A key the server names in place of a known one is
refused as `IdentityChanged`, and only a safety-number comparison resolves
that. Receiving is not blocked.

Since §9.7 a key is also confirmed by the key log when it has stood there
unchanged for a day.

### 9.7. Key transparency

The server keeps a public log of `username → identity`. Every epoch
(`EPOCH = 1 h`, epoch number `e = floor(unix_ms / EPOCH)`) it builds a
compact sparse Merkle tree of depth 256:

```
index(u)    = SHA256("GASAPP_KT_INDEX_v1" || u32be(len(u)) || u)
value       = SHA256("GASAPP_KT_LEAF_v1" || index || IK || H(PQ) || u64be(version))
leaf node   = SHA256(0x00 || index || value)
inner node  = SHA256(0x01 || left || right)
empty       = 32 zero bytes
head(e)     = SHA256("GASAPP_KT_HEAD_v1" || u64be(e) || root(e) || head(previous))
```

A subtree holding one leaf is that leaf node; bits of `index` choose the
path, most significant bit first. `version` grows with every rebind of the
account to a new identity (§9.4).

Clients fetch heads and proofs **anonymously** (no device signature, a
separate Tor circuit per connection), so the server cannot tell who is
checking and must show everyone the same tree.

* **Chain.** A client stores verified heads and accepts a new head only if
  `head(e) = H(e, root(e), head(previous))` continues its stored chain.
  A mismatch is a security event (`kt_log_forked`). The chain must not lag
  the clock by more than two epochs.
* **Peer.** A key named by discovery is trusted for sending without an
  out-of-band check only if the same leaf (key, `H(PQ)`, version) proves
  present at the latest epoch **and** at an epoch at least 24 epochs older.
  A fresher key needs the safety-number comparison.
* **Self.** A client checks its own index at every epoch since its last
  check (at most 168 epochs back), starting at registration or recovery.
  A leaf with another key, or a lower version, is a security event
  (`kt_foreign_key_for_own_name`). If the chain syncs but proofs for the
  own index are withheld for more than 6 epochs, that too is a security
  event (`kt_self_check_blocked`): a server could otherwise serve peers
  and refuse only the owner, whose requests it can tell apart. Proof
  requests carry no per-index rate limit for the same reason.

* **Gossip.** At most once a day per peer, a client sends its latest
  `(epoch, head)` inside an ordinary end-to-end message (content kind 9,
  `KtHead`). The receiver compares it with its own head of that epoch
  (syncing first if the epoch is newer); a mismatch is a security event
  (`kt_peer_log_differs`) — the server shows one of the two a different
  branch.

The server keeps leaf history and epochs for 192 epochs.

### 9.8. Channels

A channel is a one-to-many feed: one author posts, anyone holding the
invitation link reads. It is a separate construction from the pairwise
session (§4–§8) and gives **weaker** guarantees, listed at the end of
this section. Implementation: `crates/gasapp-protocol/src/channel.rs`.

**Keys.** The author generates, on the device:

* `channel_id` — 16 random bytes (the server sees it as a UUID);
* `secret` — 32 random bytes;
* an Ed25519 signing key pair `(sk, vk)`.

The read key is derived, not stored:

```
K_read = HKDF-SHA-256(salt = channel_id, ikm = secret,
                      info = "GASAPP_CHANNEL_v1_KEY", L = 32)
```

**Invitation link.** `gasapp://channel/<hex(channel_id)>.<base32(secret)>.<base32(vk)>`
(RFC 4648 base32 without padding, as in contact links, §9.3). The link is
the whole reader capability. For a private channel it never reaches the
server: the author shows it as a QR code or copies it, and the reader
pastes or scans it. A public channel is the exception (below).

**Record format.** Three kinds of record — the channel description
(`kind = 1`), a post (`kind = 2`) and a deletion mark (`kind = 3`) — are
sealed the same way:

```
nonce      = 12 random bytes
padded     = pad(content)                         (buckets of §7, min 512 bytes)
ciphertext = AES-256-GCM(K_read, nonce, padded,
                         aad = "GASAPP_CHANNEL_v1_AAD" ‖ kind ‖ channel_id)
signature  = Ed25519.Sign(sk_signer, "GASAPP_CHANNEL_v1_SIG" ‖ kind ‖ channel_id
                                     ‖ vk_signer ‖ nonce ‖ ciphertext)
wire       = 0x02 ‖ kind ‖ vk_signer ‖ nonce ‖ signature ‖ ciphertext
```

`vk_signer` is the public key of whoever signed the record: the owner
(`vk` from the link) or an administrator (below).

The leading byte is the wire version. Version 1 (text-only posts, no
revisions) was never deployed and is not read.

All integers are big-endian. `block16(x)` is `len(x) (u16) ‖ x`.

* **Post:** `number (u64) ‖ revision (u32) ‖ created_at_millis (i64) ‖
  edited_at_millis (i64) ‖ text_len (u32) ‖ text (UTF-8) ‖ count (u8) ‖
  count × block16(attachment)`. Text is at most 16 000 bytes, there are
  at most 10 attachments, each at most 1 024 bytes. A post has text, an
  attachment, or both. `revision` is 0 when published and grows by one
  with each edit; `edited_at_millis` is 0 until the first edit.
* **Deletion mark:** `number (u64) ‖ revision (u32) ‖ deleted_at_millis (i64)`.
* **Description:** `updated_at_millis (i64) ‖ block16(title) ‖
  block16(description) ‖ pinned (u64) ‖ block16(avatar) ‖ count (u8) ‖
  count × admin`. Title at most 64 characters, description at most 500.
  `pinned` is the number of the pinned post, 0 for none. `avatar` is an
  attachment descriptor, empty for none. `admin` is
  `vk (32) ‖ active (u8: 1 or 0) ‖ until (u64)`; at most 16 entries.

Trailing bytes after the last field are an error.

**Media.** An attachment is the same descriptor message attachments use: the
blob's address, a fresh random key and the plaintext size. The file is
stripped of metadata, padded and encrypted in chunks exactly as a
message attachment is; only the storage differs. The blob is uploaded
to the channel (`/v1/channels/own/…/media`, signed by the owner's
device, at most 32 MiB) and fetched without authentication
(`/v1/channels/feed/…/media/…`). The server holds ciphertext and its
padded length; the key travels inside the encrypted post.

**Administrators.** The owner may let others write to the channel. A
would-be administrator generates their own Ed25519 key pair on their
device and shows the owner a request
`gasapp://channel-admin/<hex(channel_id)>.<base32(vk_admin)>.<hex(device_id)>`
(no secrets in it). The owner then

1. tells the server to accept posts from the account of `device_id`, and
2. adds `vk_admin` to the admin list in the description — which only
   the owner signs.

An administrator can publish, edit and delete posts and upload media.
The description (title, pin, avatar, admin list), the public handle and
the channel's deletion stay with the owner.

To remove an administrator the owner first tells the server to stop
accepting their posts, then reads the channel's last sequence number `n`
and marks the entry `active = 0, until = n`. The entry is kept: without
it the posts that administrator already wrote would stop verifying.

**Reading.** A reader takes the admin list from the newest accepted
description. A description is accepted only if signed by `vk` **from the
link**; a post or deletion mark is accepted only if `vk_signer` is `vk`
or an admin entry that covers the record's number (active, or
`number ≤ until`). Verification is strict Ed25519 and precedes
decryption. A reader rejects:

* a channel whose server-side `verify_key` differs from `vk` in the link;
* a description signed by anyone but the owner — an administrator cannot
  add administrators;
* a record signed by a key that is not the owner's and not in the admin
  list, or by a removed administrator for a number above their `until` —
  the server cannot appoint administrators or bring a removed one back;
* a post or deletion mark whose inner `number` differs from the sequence
  number the server served it under — the server cannot reorder posts,
  replay one in another position, or delete one post with another's mark;
* a post whose `revision` is not greater than the one already stored —
  the server cannot roll an edit back;
* any post for a number that already carries an accepted deletion mark —
  a deleted post does not come back from its old ciphertext;
* a deletion claimed by the server without a valid deletion mark — the
  server cannot remove a post from readers on its own;
* a description whose `updated_at_millis` is not newer than the one
  already accepted — the server cannot roll back a title, a pin or an
  avatar.

A rejected record is skipped, not retried. A reader keeps a deleted post
as an empty row carrying the mark's revision, so that the rejection above
survives restarts.

**Synchronisation.** The server numbers every change to a channel — a
new post, an edit, a deletion — with a growing revision counter (distinct
from the per-post `revision` above). A reader remembers the last counter
value it has seen and asks for changes after it. The first
synchronisation takes the newest page of posts instead of the whole
history; older pages are fetched on demand.

**Subscribers, views and reactions.** A subscriber is an account. When a
reader adds a channel, the app subscribes the account
(`/v1/channels/reader/{device}/{channel}/subscribe`); "read up to post
N" and reactions go the same way. All of these are signed by the device
(§12.6): one account is one subscriber, however many times it asks, so
the counts cannot be inflated without creating accounts. A reaction is
one of eight fixed emoji; free text is refused, otherwise readers could
write into someone else's channel.

Reading is separate from subscribing: the channel, its posts and its
media are fetched without a signature, so a channel can be read by link
without the server learning who reads it.

Counts of subscribers, views and reactions are server statistics. They
are not signed by anyone, and clients present them as such.

**Public channels.** An author may give a channel a public handle
(`^[a-z][a-z0-9_]{2,31}$`). To make the channel resolvable by that
handle, the author hands the server the invitation link. The server
accepts only a link to that very channel and serves it to anyone who
asks for the handle. A client that resolves a handle checks that the
link's `channel_id` and `vk` match the channel the server returned and
that the description opens and verifies under the link's keys.

**What the server does.** It checks that the publishing device signed
the request (§12.6) and that its account owns the channel or is one of
its administrators; creating a channel additionally requires the
account's `premium` flag, which the operator sets by hand. A publish
request names the sequence number the author sealed inside the post; if
the channel has moved on (two authors raced), the server answers `409`
and stores nothing, and the author seals again under the next number.
The server does not verify record signatures. Reads of an open
channel (`/v1/channels/feed/…`) are unauthenticated; a closed channel
(§9.9) is served only to its members.

**What this does not provide.**

* **No forward secrecy and no post-compromise security.** `K_read` is
  static. Whoever obtains the link reads every past and future post; a
  single reader cannot be revoked.
* **A public channel is readable by the server.** The link the author
  hands over contains `secret`. Making the channel private again does
  not take that knowledge back. The server still cannot forge records:
  it never has `sk`.
* **A handle is the server's namespace.** Nothing binds a handle to a
  channel except the server's word; it could answer a handle with a
  different (internally consistent) channel tomorrow. Readers who need
  certainty compare the link out of band.
* **The server knows who subscribes.** It stores which accounts follow
  which channels, how far each has read and how each reacted. This is
  the price of counts that cannot be inflated: an anonymous subscription
  cannot be rationed. Reading by link without subscribing stays
  anonymous.
* **Withholding.** The server can omit the newest posts, an edit or a
  deletion mark, or stop serving a channel. It cannot forge, alter or
  reorder records.
* **Deletion is not erasure.** Readers who already fetched a post keep
  it until they synchronise, and copies made outside the app stay.
* **No post-quantum authenticity.** The author signature is Ed25519
  only; a quantum adversary could forge posts. Confidentiality rests on
  AES-256-GCM under a symmetric key and is not affected.
* **Random nonces under a long-lived key.** Safe while a channel holds
  far fewer than 2³² records; the server caps a channel at 100 000 posts.
* **A removed administrator plus the server.** A removed administrator's
  key stays valid for numbers up to `until`. Colluding with the server,
  they could replace posts published before their removal with their own
  (as a higher revision). They cannot publish under later numbers. The
  owner's key cannot be revoked at all.
* **Administrators are known to the server.** A reader is anonymous to
  it; an administrator's account is listed, as the owner's is.
* **Channel keys are in the backup.** `secret` and the signing key of
  an owner or administrator are part of the zero-knowledge backup
  (bundle version 3): whoever holds the recovery key and a backup file
  can read and post to those channels. Posts are not backed up — they
  are fetched again and verified.

### 9.9. Closed channels

A channel can be **closed**: it is then joined by an approved request,
and the server serves its records only to members (the owner, the
administrators and approved subscribers), on device-signed requests
(`/v1/channels/reader/<device>/<channel>/{info,posts,media/…}`). A closed
channel cannot have a public handle. Implementation:
`crates/gasapp-protocol/src/channel_join.rs`.

**Join link.** `gasapp://channel-join/<hex(channel_id)>.<base32(vk)>.<hex(invite)>`,
where `invite` is 16 random bytes. The link carries **no** `secret`. The
server stores `SHA-256(invite)` and accepts a request only with a tag
whose hash it holds and that has not been revoked.

**Request.** The applicant draws a 32-byte one-time seed and derives a
**hybrid** key pair from it — X25519 `(e, E)` and ML-KEM-1024 `(dk, EK)` —
and signs both public halves with the account identity key (XEdDSA, §3):

```
e  = HKDF-SHA-256(ikm = seed, info = "GASAPP_CHANNEL_v2_SEED_X25519", L = 32)
dk = ML-KEM-1024.KeyGen(HKDF-SHA-256(ikm = seed, info = "GASAPP_CHANNEL_v2_SEED_MLKEM", L = 64))

request = 0x02 ‖ E (32) ‖ EK (1568) ‖ IK (32) ‖ Sig (64)
Sig     = XEdDSA.Sign(ik, "GASAPP_CHANNEL_v2_JOIN" ‖ channel_id ‖ E ‖ EK)
```

**Grant.** Whoever runs the channel verifies `Sig`, generates a one-time
X25519 pair `(a, A)`, encapsulates to `EK` and wraps the channel `secret`
under both shared secrets:

```
(ss, ct) = ML-KEM-1024.Encaps(EK)
K     = HKDF-SHA-256(salt = channel_id, ikm = X25519(a, E) ‖ ss,
                     info = "GASAPP_CHANNEL_v2_GRANT" ‖ E ‖ A ‖ SHA-256(EK) ‖ SHA-256(ct), L = 32)
grant = 0x02 ‖ A (32) ‖ ct (1568) ‖ nonce (12) ‖
        AES-256-GCM(K, nonce, epoch (4) ‖ secret,
                    aad = "GASAPP_CHANNEL_v2_GRANT_AAD" ‖ channel_id ‖ vk)
```

Breaking the grant requires breaking **both** X25519 and ML-KEM-1024: an
adversary who stores grants today cannot open them with a quantum computer
later. Version `0x01` (X25519 only) is not accepted.

The server stores `request` and `grant` as opaque bytes. The applicant
opens the grant with `e` and accepts the recovered `secret` **only if**
the channel metadata decrypts under it and verifies against `vk` from
the link — a grant fabricated by the server fails that check.

**Removal and key change.** Whoever runs the channel can remove a
subscriber: the server deletes the subscription, the grant, the request
and the delivery key, and refuses new requests from that account until
the ban is lifted. The remover's device then starts a new key **epoch**:

```
S_n      = 32 fresh random bytes                      (n = previous epoch + 1)
record_n = 0x01 ‖ n (4) ‖ signer_vk (32) ‖ nonce (12) ‖ Sig (64) ‖
           AES-256-GCM(HKDF(salt = channel_id, ikm = S_n, info = "GASAPP_CHANNEL_v1_EPOCH"),
                       nonce, S_{n-1}, aad = "GASAPP_CHANNEL_v1_EPOCH" ‖ channel_id ‖ n)
Sig      = Ed25519.Sign(sk_signer, "GASAPP_CHANNEL_v1_EPOCH_SIG" ‖ channel_id ‖ n ‖
                        signer_vk ‖ nonce ‖ ciphertext)
```

`record_n` is a chain link: a member holding `S_n` recovers `S_{n-1}`
and so reads the history; nothing leads forward from an old secret. The
signer must be the owner or an administrator named in the channel
metadata — and the link that starts the **current** epoch must be signed
by the owner or an administrator who is still active. Removing an
administrator of a closed channel therefore changes the key at once. `S_n` is handed to every remaining member as a grant (the same
construction as above, with the plaintext `n (4) ‖ S_n`) sealed to that
member's **delivery key** — the one-time key of their join request, or,
for members who never sent one, a key they register on their next
synchronisation (`E ‖ IK ‖ Sig`, same format as a request). A device that
runs the channel derives its delivery key from its channel signing key
(`HKDF(salt = channel_id, ikm = sk, info = "GASAPP_CHANNEL_v1_DELIVERY")`),
so an owner restored from a backup can open their own grant.

A record sealed under epoch `n > 0` is prefixed `0x03 ‖ n (4)`; the server
reads only this prefix and refuses (`409`) a record whose epoch is not
the channel's current one. The prefix is not authenticated — it only
selects the key. A channel whose key was changed cannot be reopened.

**What this does not provide.**

* **Removal is not retroactive.** Changing the key (below) protects
  records published after the removal. Everything published before it,
  and the channel title, description and avatar (which stay under the
  epoch-0 key), remain readable to the removed subscriber if they obtain
  the ciphertext.
* **The server can substitute a request.** `Sig` binds the one-time
  keys to an identity key, but the approver learns *whose* key that is
  from the server — unless the applicant is a **confirmed** contact
  (verified, or added by link/QR), or the key has stood under that name in
  the key-transparency log (§9.7) for more than a day. The app marks both
  cases; everything else is the server's word. A server that swaps in its own
  `(E, IK)` under an applicant's name receives `secret` when the request
  is approved.
* **The old open link still contains the epoch-0 `secret`.** Closing a
  channel stops the server from serving it to non-members; a link issued
  while the channel was open still decrypts what was published before
  the first key change.
* **A delivery key substituted at first sight.** A device that runs the
  channel remembers the identity key of every member it approved or first
  handed a key to, and refuses a delivery key signed by any other identity
  under that account. A server can still plant its own key for a member
  the device has never seen — once, before the first hand-out. A member
  whose identity key changes (account restored on a new phone) gets no
  further keys until re-approved.
* **An administrator removed while the owner is offline.** A removed
  administrator cannot start the current epoch (see above), but until the
  owner's device publishes the new metadata and the key change, they are
  still an administrator.
* **A member who is offline during a key change** reads new records only
  after a device that runs the channel hands them the key.
* **Membership is known to the server**, as subscription already was
  (§9.8); it additionally tells whoever runs the channel the account
  names of applicants and subscribers.
* Join links are kept only on the device that created them and are not
  in the backup; the server holds their hashes.

### 9.10. Bots

A bot is an ordinary account — its own identity key, prekeys and
sessions — that is run by a program instead of a person. It differs in
two ways: it is created by another account (the owner, which must have
`premium`), and it has no e-mail address. Its username ends in `bot`;
the server refuses that suffix to ordinary registrations.

The owner asks the server for a one-time token bound to a bot username
(valid for one hour, stored as `SHA-256(token)`). The bot program
registers with that token (`POST /v1/bots/register`), generating all key
material itself and solving the same proof of work as a normal
registration. Neither the server nor the owner's app ever holds the
bot's private keys. Deleting the owner deletes its bots.

The server does nothing on a bot's behalf. Everything a bot does — reply
to messages, post to a channel it administers, approve join requests,
remove subscribers — is done by its program through the same signed
requests the app uses (`crates/gasapp-bot`).

**What this does not provide.**

* The `bot` suffix says only that the account was created as a bot. It
  says nothing about what its program does or who wrote it.
* A bot that administers a closed channel holds that channel's `secret`,
  like any administrator: the machine it runs on becomes part of what
  the channel trusts.
* The reference bot engine connects directly over TLS, without Tor; the
  server sees the bot machine's address.

**Buttons.** Two message content kinds (§7) carry inline buttons inside
the pairwise session, so the server sees neither labels nor presses:

* kind `10`, *keyboard*: `target (16) ‖ len (4) ‖ keyboard` — rows of
  buttons attached to a message the sender wrote earlier (`target` is
  its identifier). A button is a label (≤ 40 characters, no control,
  bidirectional-override or zero-width characters) and either callback
  data (≤ 64 bytes) or an `https://` URL (≤ 512 bytes, printable ASCII
  only, no credentials before the host — an internationalised name must be
  written as `xn--…`); at most 8 rows of 4. An empty keyboard removes the buttons. The receiver
  accepts it only for a message of that peer in that chat.
* kind `11`, *callback*: `target (16) ‖ len (4) ‖ data` — a press. The
  receiver accepts it only if it itself attached, to that message in
  that chat, a button carrying exactly this data.

A URL button sends nothing to the author: the app shows the full link
and opens it only on the user's confirmation.

## 10. Security Considerations

### 10.1. Forward Secrecy
Past messages remain secret after a state compromise. The property comes
from the **symmetric ratchet**: each message key is consumed and destroyed
immediately, and HMAC is one-way, so a captured chain key yields no earlier
key.

### 10.2. Post-Compromise Security
Secrecy is restored after a state compromise, but **not immediately**. The
property comes from the **DH ratchet**, and healing completes only once both
parties have introduced a fresh ratchet key — that is, after a full exchange
in both directions. Messages sent inside that window remain readable to an
adversary holding the captured state. Implementations MUST NOT describe PCS
as instantaneous.

### 10.3. Quantum Resistance

> ⚠️ Implementation status (2026-09): SPQR is not wired into sessions (§6).
> What holds today: the Double Ratchet is seeded from the PQXDH secret, so
> recorded traffic is not decrypted by breaking X25519 alone. What does not
> hold: post-compromise recovery against a quantum adversary.

PQXDH protects the initial exchange, SPQR the remainder of the session.
Because the message key derives from both halves (§8.3), an adversary must
break **both** X25519 and ML-KEM. If ML-KEM were broken classically — as
happened to the SIKE and Rainbow candidates — security degrades to the
Double Ratchet level rather than collapsing; symmetrically, ML-KEM covers
the arrival of a quantum computer.

Protocol version 2 mandates the post-quantum ratchet. It is carried as the
first byte of every envelope. Version 0 is rejected outright; version 1
(zero-salt PQXDH, X25519-only sealed sender) is rejected too. No version
negotiation exists — negotiation is itself the channel through which
downgrade attacks are mounted.

### 10.4. Sealed Sender Outer Layer

Every envelope travels sealed: the server learns the recipient device, never
the sender. The outer layer is a hybrid KEM:

```
header = 0xA2 || EK (X25519, ephemeral) || CT_kem (ML-KEM-1024 to PK_kem_B)
salt   = SHA-256("GASAPP_SEALED_SENDER_v2_SALT" || EK || IK_B || SHA-256(PK_kem_B) || CT_kem)
key    = HKDF-SHA-256(salt, DH(EK, IK_B) || SS_kem, "GASAPP_SEALED_SENDER_v2_X25519_MLKEM1024")
body   = AES-256-GCM(key, nonce = EK[..12], plaintext = cert || envelope, AAD = header)
```

`PK_kem_B` is a per-device ML-KEM-1024 key, signed by the recipient's
identity key over `"GASAPP_SEALED_KEM_v1" || PK_kem_B` and served by
discovery. It is replaced 7 days after publication; retired keys are kept
for 30 days (the envelope lifetime on the server, at most 8 keys) and then
erased, and an envelope is opened with the current key first, then with the
retired ones. The sender verifies the signature; a missing key aborts the
send rather than falling back to X25519 alone. The classical-only format
`0xA1` is rejected.

Why hybrid: the message content was already protected by the post-quantum
ratchet, but the sender's identity rested on X25519 alone. An adversary
recording envelopes today could, with a quantum computer later, recover who
wrote to whom. Now both X25519 and ML-KEM must be broken.

The first envelope to a new contact carries no access key; the right to send
anonymously is proven by proof-of-work over the recipient device and the
envelope hash (18 bits, `GASAPP_POW_FIRST_v1`) instead of the sender's
signature.

Attachments are uploaded and downloaded without any signature. The right to
store a blob is proven by proof-of-work over the blob itself
(`GASAPP_POW_UPLOAD_v1`, 16 bits plus one bit per doubling of the size in MiB),
so the server does not learn who uploaded a file or who fetched it.

### 10.5. Deniability
Messages do not contain signatures that bind them to a specific sender.

### 10.6. Insider Security
Server compromise does not reveal message contents due to end-to-end encryption.

### 10.7. Side-Channel Resistance
All implementations should use constant-time algorithms for security-critical operations.

## 11. Test Vectors

Test vectors live in `docs/protocol/test-vectors/`. Their README distinguishes
two kinds, and the distinction matters:

**Reference vectors** — from an independent source. Agreement demonstrates
*interoperability*.

| Primitive | Source | Status |
|---|---|---|
| X25519 | RFC 7748 §6.1 | present |
| Ed25519 | RFC 8032 §7.1 | present |
| ML-KEM-768/1024 | FIPS 203 | present |
| HKDF-SHA-256 | RFC 5869 Appendix A | present |
| SHA-512 | FIPS 180-4 | present |

**Regression vectors** — produced by this implementation and pinned to
detect unintended change. They do *not* demonstrate interoperability: an
error present from the outset would be pinned rather than exposed.

| Component | Status |
|---|---|
| Fingerprint | present (regression only) |

**Absent: reference vectors for the protocol itself** — PQXDH, Double
Ratchet, SPQR. Their only source is the libsignal reference implementation,
which is AGPL-3.0 and can be neither linked nor copied here (ADR-005). The
sanctioned route is to run it in an isolated container and commit the
resulting **vectors** — data, not code.

Until that exists, the protocol layers are verified only against
themselves. An error made symmetrically in both the sending and receiving
paths would pass every current test while breaking interoperability with
any other implementation. This is the largest open verification gap in
GasApp v1.0 and is stated here so that no reader mistakes the present test
suite for proof of correctness.

## 12. Implementation Notes

### 12.1. Error Handling
All cryptographic functions should return explicit errors rather than panicking.

### 12.2. Zeroization
All secret materials should be zeroized immediately after use.

### 12.3. Constant-Time Operations
Comparisons of secret values should be performed in constant time.

### 12.4. Random Number Generation
All nonces and ephemeral keys should be generated using cryptographically secure random number generators.

### 12.5. Key Validation
All received public keys should be validated for correct format and membership in the appropriate group.

> ⚠️ Implementation note (2026-09): X25519 public keys are checked for
> length only. Subgroup membership is **deliberately not** checked
> (`x25519.rs`), and non-contributory (e.g. all-zero) shared secrets are
> **not** rejected either. In PQXDH a low-order key substituted for the
> unsigned one-time prekey zeroes only that DH term; the other DH terms
> and the ML-KEM secret still bind the key. Rejecting non-contributory
> results is defence in depth that the implementation does not have.

### 12.6. Replay Protection
Implementations should include replay protection mechanisms, such as message counters or timestamps.

> Implementation note (2026-09). Messages inside a session are protected
> by the Double Ratchet: a message key is deleted once used. Initial
> (PQXDH) envelopes were protected only by one-time prekeys — and the
> server may withhold those (an exhausted pool looks the same). A replayed
> initial envelope without them was accepted as a new session and replaced
> the live one. The recipient now records the sender's base key of every
> accepted initial envelope and drops a repeat without touching the
> session, logging `initial_envelope_replayed`. A record is kept for as
> long as the signed prekey that accepted the envelope exists (current or
> retired): without that key a replay does not decrypt anyway.

### 12.7. Message Size Limits
Implementations should enforce reasonable limits on message sizes to prevent resource exhaustion attacks.

## References

[1] NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
[2] RFC 7748: Elliptic Curves for Security
[3] RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
[4] RFC 2104: HMAC: Keyed-Hashing for Message Authentication
[5] FIPS 180-4: Secure Hash Standard
[6] NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
[7] Bernstein et al.: High-speed high-security signatures
[8] Marlinspike & Perrin: The Double Ratchet Algorithm