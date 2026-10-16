# Security Policy

## Status

The auth and crypto core is implemented and tested — SRP-6a cross-verified
against golden vectors, 2SKD/Argon2id key derivation, XChaCha20-Poly1305 item
encryption, per-vault keys, and atomic key rotation on member removal (ADR-008).

It has **not** been through an external security audit. Treat this as pre-1.0
software: **do not store real secrets in a Kleidion deployment yet.**

## Zero-knowledge invariant

By design, the server must never see plaintext vault data. If you find any path where the server,
its logs, or its database can obtain unencrypted item content, master passwords, Secret Keys, or
derived keys — that is a critical vulnerability.

## Reporting a vulnerability

Please report privately:

- Email: security@kleidion.com *(pending domain registration — until then, use the GitHub private
  vulnerability reporting feature on the repository)*

We aim to acknowledge reports within 48 hours and provide fixes for critical issues within 7 days.

## Scope (once live)

In scope: client crypto (`packages/crypto`), SRP implementation, server auth, sync protocol,
extension content scripts, mobile autofill providers, key storage on devices.

## Disclosure policy

We follow coordinated disclosure; reporters get credit (or anonymity, their choice) and we publish
advisories for confirmed issues.
