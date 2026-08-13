# AEGIS Protocol Test Vectors

This directory contains test vectors for verifying the correctness of the AEGIS protocol implementation.

## Directory Structure

- `pqxdh/` - Test vectors for PQXDH key exchange
- `double_ratchet/` - Test vectors for Double Ratchet
- `spqr/` - Test vectors for SPQR ratchet
- `fingerprint/` - Test vectors for fingerprint calculation
- `kdf/` - Test vectors for key derivation functions

## Format

Each test vector file follows the format:
```
# Description of the test
Input: <hex-encoded input>
ExpectedOutput: <hex-encoded output>
```

## Generating Test Vectors

Test vectors can be generated using the reference implementation or by using established test vectors from:
- NIST for ML-KEM (FIPS 203)
- RFC 7748 for X25519
- RFC 5869 for HKDF
- The Signal Protocol test vectors for Double Ratchet (adapted for AEGIS)

## Usage

To run tests against these vectors, use the provided test scripts or implement your own verification suite.