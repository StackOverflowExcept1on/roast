# ROAST (Robust Asynchronous Schnorr Threshold Signatures)

[![Build Status](https://github.com/StackOverflowExcept1on/roast/workflows/CI/badge.svg)](https://github.com/StackOverflowExcept1on/roast/actions)

| Crate                                      | Description                  |
|--------------------------------------------|------------------------------|
| [`roast-core`](roast-core)                 | Generic ROAST implementation |
| [`roast-ed25519`](roast-ed25519)           | Ed25519 ciphersuite          |
| [`roast-ed448`](roast-ed448)               | Ed448 ciphersuite            |
| [`roast-p256`](roast-ed448)                | P-256 ciphersuite            |
| [`roast-ristretto255`](roast-ristretto255) | Ristretto255 ciphersuite     |
| [`roast-secp256k1`](roast-secp256k1)       | secp256k1 ciphersuite        |

Rust implementation of [ROAST (Robust Asynchronous Schnorr Threshold Signatures)](https://eprint.iacr.org/2022/550)
with [cryptography by Zcash Foundation](https://github.com/ZcashFoundation/frost).

## Getting Started

Refer to the [ZF FROST book](https://frost.zfnd.org), [ROAST white paper](https://eprint.iacr.org/2022/550)
and [cybersecurity seminar about ROAST](https://youtu.be/FVW6Hgt_meg?feature=shared).

## Status

The ROAST implementation is not yet finalized. Thus, significant changes may occur and SemVer is not guaranteed. ZF
FROST code base has been partially audited by NCC, see below for details.

### NCC Audit of ZF FROST

NCC performed [an audit](https://github.com/ZcashFoundation/frost/blob/main/README.md#ncc-audit) of ZF FROST. So the
cryptography was audited, but this ROAST implementation was not audited.

## Usage

`roast-core` implements the base traits and types in a generic manner, to enable top-level implementations for different
ciphersuites / curves without having to implement all of ROAST from scratch. End-users should not use `roast-core` if
they want to sign and verify signatures, they should use the crate specific to their ciphersuite/curve parameters that
uses `roast-core` as a dependency.
