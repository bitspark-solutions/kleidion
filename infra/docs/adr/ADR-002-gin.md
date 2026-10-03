# ADR-002: Gin as the Go HTTP framework

Date: 2026-10-03 · Status: accepted

## Decision
Use Gin v1 (github.com/gin-gonic/gin) for the server's HTTP layer.

## Rationale
- Most widely used Go web framework (≈48% adoption, JetBrains Go Ecosystem 2025).
- Frozen v1 API ("new releases will not break your code"), battle-tested, complete middleware
  suite (recovery, CORS, rate-limit), radix-tree router with predictable performance.
- Team familiarity and huge community = reliable long-term maintenance.

## Alternatives rejected
- chi: leaner, 100% stdlib-compatible — acceptable fallback; less ecosystem.
- Echo: comparable, slightly smaller community.
- Fiber (fasthttp): fastest, but non-stdlib HTTP engine conflicts with net/http middleware and
  some security tooling; rejected for a security product.
