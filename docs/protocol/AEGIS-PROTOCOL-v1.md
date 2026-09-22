# AEGIS PROTOCOL VERSION 1.0

This document specifies the AEGIS protocol version 1.0, which combines post-quantum cryptography with modern ratchet-based encryption to provide forward secrecy, post-compromise security, and resistance to quantum attacks.

> **Status: draft, reconciled with the implementation on 2026-08-14.**
>
> Every construction below corresponds to code in `crates/aegis-protocol`
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

AEGIS is a secure messaging protocol designed to provide:
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

The AEGIS protocol operates in phases:

1. **Initial Key Exchange (PQXDH)**: Establishes a shared secret using a combination of classical X25519 Diffie-Hellman and ML-KEM-1024 key encapsulation mechanism.

2. **Ratchet Phase**: After the initial exchange, the protocol uses a combination of:
   - Double Ratchet (X25519 + HMAC-SHA-256) for synchronous messages
   - SPQR (ML-KEM-768 + X25519 + HMAC-SHA-256) for asynchronous messages

3. **Message Encryption**: Messages are encrypted using AES-256-GCM with keys derived from the ratchet state.

## 3. Cryptographic Primitives

AEGIS v1.0 uses the following cryptographic primitives:

- **X25519**: Elliptic curve Diffie-Hellman over Curve25519
- **ML-KEM-1024**: Module-Lattice-Based Key-Encapsulation Mechanism (NIST FIPS 203)
- **ML-KEM-768**: Module-Lattice-Based Key-Encapsulation Mechanism (NIST FIPS 203) - used in SPQR
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
SK = HKDF-SHA-256(
    salt = 32 zero bytes,
    IKM  = F || DH1 || DH2 || DH3 || [DH4] || SS_pq,
    info = "AEGIS_PQXDH_v1_X25519_MLKEM1024"
)
```

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

Signatures use XEdDSA and MUST be verified **with the bundle owner's
identity key** before any cryptographic operation on the bundle. A failed
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
> `aegis-protocol::spqr`, not wired into sessions.** The session layer
> (`aegis-core::session`) calls `RatchetState::encrypt` / `decrypt`, which
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
pq_root = HKDF-SHA-256(salt=pq_root, IKM=kem_shared_secret)["AEGIS_SPQR_v1_PQ_ROOT"]
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

AEGIS messages use AES-256-GCM:

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
Nonce = first_12_bytes(HKDF-SHA-256(salt=none, IKM=message_key)["AEGIS_DR_v1_NONCE"])
```

> ⚠️ Corrected 2026-09. This section previously named `AEGIS_AEAD_v1_NONCE`.
> That label exists, but belongs to the outer sealed-sender AEAD layer
> (`aead::seal_with_key`); Double Ratchet messages use `AEGIS_DR_v1_NONCE`
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

AEGIS uses HKDF-SHA-256 (RFC 5869) for key derivation and HMAC-SHA-256 for
symmetric chain advancement, with domain separation by distinct labels.

### 8.1. Root Key Derivation

On each DH ratchet step the previous root key acts as the HKDF salt and the
Diffie-Hellman output as input key material:
```
(new_root_key, chain_key) = HKDF-SHA-256(salt=root_key, IKM=dh_output)["AEGIS_DR_v1_ROOT"]
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
message_key = HKDF-SHA-256(salt=none, IKM=MK_classic || MK_pq)["AEGIS_TripleRatchet_v1"]
```
Both inputs are mandatory. An adversary holding only one of them cannot
derive the message key (see §10.4).

## 9. Fingerprint Calculation

> ⚠️ Rewritten 2026-09 to match the code (`aegis-protocol::fingerprint`,
> `aegis-core::client::safety_number_of`). The previous text described
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

### 9.2. Safety number

```
(first, second) = sort_lexicographically(fingerprint_A, fingerprint_B)
safety_number   = digits(first) || digits(second)       -- 60 digits
digits(fp)      = for each 5-byte group g of fp:
                      five decimal digits of (big-endian u40(g) mod 100000)
```

Sorting makes both parties obtain the same 60 digits although "own" and
"peer" are swapped between them. Display: 12 groups of 5 digits (ADR-022).

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

Protocol version 1 mandates the post-quantum ratchet. Version 0 is rejected
outright, and no version negotiation exists — negotiation is itself the
channel through which downgrade attacks are mounted.

### 10.4. Deniability
Messages do not contain signatures that bind them to a specific sender.

### 10.5. Insider Security
Server compromise does not reveal message contents due to end-to-end encryption.

### 10.6. Side-Channel Resistance
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
AEGIS v1.0 and is stated here so that no reader mistakes the present test
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