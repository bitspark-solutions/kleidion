# ADR-001: Monorepo with npm workspaces + Go module

Date: 2026-10-03 · Status: accepted

## Decision
Single repository `kleidion` containing all clients (`apps/*`) and shared TS packages
(`packages/*`) via npm workspaces; the Go server is its own module (`github.com/kleidion/server`)
inside the same repo.

## Rationale
- The security-critical client crypto (`packages/crypto`) must have ONE implementation shared by
  web, extension, desktop and mobile. Separate repos would fork it and drift.
- Compose/Tilt orchestration at root manages the whole stack from one command.
- Go lives in-tree but as its own module; `go.work` optional for local dev.

## Alternatives rejected
- Polyrepo per app: cross-cutting crypto/schema changes would need N coordinated PRs.
- Full Go monorepo tooling (Bazel): overkill at this stage.
