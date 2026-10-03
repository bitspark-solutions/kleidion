# Security Policy

## Status

Kleidion is in **Phase 1 (infrastructure)**. The auth/crypto core (Phase 2) has NOT been
implemented yet, and the project has NOT been audited. **Do not store real secrets in a
Kleidion deployment yet.**

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
