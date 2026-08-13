# AEGIS PROTOCOL VERSION 1.0

This document specifies the AEGIS protocol version 1.0, which combines post-quantum cryptography with modern ratchet-based encryption to provide forward secrecy, post-compromise security, and resistance to quantum attacks.

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
- **XEdDSA**: Extended Edwards-curve Digital Signature Algorithm (based on Ed25519)

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
    0xFF || 
    DH1 || 
    DH2 || 
    DH3 || 
    DH4 || 
    SS_pq,
    "AEGIS_PQXDH_v1_25519_MLKEM1024"
)
```

Where:
- `0xFF`: 32 bytes of 0xFF for domain separation
- `DH1 = IK_A || SPK_B` (Diffie-Hellman between initiator identity and responder signed pre-key)
- `DH2 = EK_A || IK_B` (Diffie-Hellman between initiator ephemeral and responder identity)
- `DH3 = EK_A || SPK_B` (Diffie-Hellman between initiator ephemeral and responder signed pre-key)
- `DH4 = EK_A || OPK_B` (Diffie-Hellman between initiator ephemeral and responder one-time pre-key, if available)
- `SS_pq`: ML-KEM-1024 shared secret derived from encapsulating to responder's PQSPK

### 4.3. PreKey Bundle

Each party publishes a PreKeyBundle containing:
- Identity key (IK)
- Signed pre-key (SPK) with signature
- One-time pre-key (OPK) (optional)
- Signed post-quantum pre-key (PQSPK)
- One-time post-quantum pre-key (PQOPK) (optional)

All keys are signed with XEdDSA to prevent substitution attacks.

## 5. Double Ratchet

The Double Ratchet provides forward secrecy and post-compromise security for synchronous communication.

### 5.1. Ratchet Steps

The Double Ratchet consists of two ratchets:
1. **DH Ratchet**: advances when receiving a message with a new DH public key
2. **Symmetric Ratchet**: advances with each message sent or received

### 5.2. Key Derivation

Root keys and chain keys are derived using HKDF-SHA-256:
- New root key: `HKDF-SHA-256(current_root_key, DH_output)`
- Chain key: `HKDF-SHA-256(current_chain_key, 0x01)` for sending
- Chain key: `HKDF-SHA-256(current_chain_key, 0x02)` for receiving
- Message key: `HKDF-SHA-256(chain_key, 0x03)` or `HKDF-SHA-256(chain_key, 0x04)`

### 5.3. Message Header

Each message includes a header containing:
- DH public key (32 bytes)
- Previous chain length (4 bytes, little-endian)
- Current chain length (4 bytes, little-endian)

## 6. SPQR Ratchet

The SPQR (Sparse Post-Quantum Ratchet) extends the Double Ratchet with post-quantum security by incorporating ML-KEM-768.

### 6.1. Ratchet Steps

SPQR adds a post-quantum ratchet step:
1. **DH Ratchet**: advances when receiving a message with a new DH public key
2. **PQ Ratchet**: advances periodically or based on message count using ML-KEM-768
3. **Symmetric Ratchet**: advances with each message sent or received

### 6.2. Key Derivation

Root keys are derived from both classical and post-quantum components:
- New root key: `HKDF-SHA-256(current_root_key, DH_output || PQ_output)`
- Chain keys and message keys derived as in Double Ratchet

### 6.3. Message Header

Each SPQR message includes a header containing:
- DH public key (32 bytes)
- PQ public key (ML-KEM-768 ciphertext, 1568 bytes)
- Previous chain length (4 bytes, little-endian)
- Current chain length (4 bytes, little-endian)

### 6.4. Chunking

ML-KEM-768 ciphertexts are chunked for transmission:
- Each chunk is ~1088 bytes
- Chunks are numbered and include the total count
- Receiver reassembles chunks before processing

## 7. Message Encryption Format

AEGIS messages use AES-256-GCM for encryption:

```
Ciphertext = Header || Nonce || Ciphertext || AuthTag
```

Where:
- **Header**: Contains ratchet information (DH key, PQ key for SPQR, chain lengths)
- **Nonce**: 12 bytes, derived from chain length to ensure uniqueness
- **Ciphertext**: Encrypted plaintext
- **AuthTag**: 16-byte authentication tag

### 7.1. Nonce Generation

Nonces are generated as:
```
Nonce = first_12_bytes(SHA-256(chain_length || fixed_string))
```
Where `fixed_string` is "AEGIS_MESSAGE_NONCE_V1".

## 8. Key Derivation Functions

AEGIS uses HKDF-SHA-256 for all key derivation with appropriate domain separation:

### 8.1. Root Key Derivation
```
HKDF-SHA-256(salt, IKM)[info]
```
Where salt is optionally provided, IKM is input key material, and info specifies the purpose.

### 8.2. Chain Key Derivation
```
HKDF-SHA-256(current_chain_key, 0x01)  # sending chain
HKDF-SHA-256(current_chain_key, 0x02)  # receiving chain
```

### 8.3. Message Key Derivation
```
HKDF-SHA-256(chain_key, 0x03)  # message key for encryption
HKDF-SHA-256(chain_key, 0x04)  # message key for authentication
```

## 9. Fingerprint Calculation

### 9.1. Safety Number Calculation

Safety numbers are 60-digit decimal numbers derived from the identity keys of two users:

```
Fingerprint = first_30_bytes(SHA-512^5200(IK_A || identifier))
SafetyNumber = decimal_display(Fingerprint_A || Fingerprint_B)
```

Where:
- `IK_A`: Identity key of user A
- `identifier`: User identifier (e.g., phone number or username)
- `SHA-512^5200`: 5200-fold iteration of SHA-512
- `first_30_bytes`: First 30 bytes of the final hash
- `decimal_display`: Conversion to 60-digit decimal string (2*30 bytes * 2 hex digits/byte * ~0.415 decimal digits/hex digit)

### 9.2. Iterative SHA-512

The iterative SHA-512 computation is defined as:
```
H_0 = SHA-512(input)
H_i = SHA-512(H_{i-1}) for i = 1 to 5199
Result = H_5199
```

## 10. Security Considerations

### 10.1. Forward Secrecy
Compromise of long-term keys does not compromise past session keys due to the DH ratchet.

### 10.2. Post-Compromise Security
Compromise of current state does not compromise future messages due to the symmetric ratchet.

### 10.3. Quantum Resistance
The ML-KEM components provide security against quantum computers.

### 10.4. Deniability
Messages do not contain signatures that bind them to a specific sender.

### 10.5. Insider Security
Server compromise does not reveal message contents due to end-to-end encryption.

### 10.6. Side-Channel Resistance
All implementations should use constant-time algorithms for security-critical operations.

## 11. Test Vectors

Test vectors for AEGIS v1.0 are located in `docs/protocol/test-vectors/` and include:
- PQXDH key exchange vectors
- Double Ratchet encryption/decryption vectors
- SPQR encryption/decryption vectors
- Fingerprint calculation vectors
- Key derivation function vectors

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