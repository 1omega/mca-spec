# Machine Commerce Attestation (MCA)

**An open standard for tamper-evident attestation of machine commerce — who paid, under whose authority, what was delivered, and proof the record was never rewritten.**

As AI agents become paying participants of the internet (x402-class rails, AP2, card-network agent protocols), the payment rails define how machines *pay*. MCA defines how anyone *proves it* afterward — a rail-agnostic attestation record format, append-only hash-chained logs, and RFC-6962-style Merkle checkpoints with independent witnessing. **Certificate Transparency for machine commerce.**

- **[Read the specification →](./SPEC.md)** (Draft v0.1, open for community review)
- **Reference verifier:** [`mca-verify`](https://github.com/1omega/mca-verify) — dependency-free, Apache-2.0, with conformance vectors
- **Reference log:** operated by [IONDRA](https://iondra.com) (public Ed25519 mode rollout in progress)
- **Governance:** [GOVERNANCE.md](./GOVERNANCE.md) — public PRs, 14-day comment windows, stated path to neutral stewardship

## Why

Every participant in the agent economy profits from more spending — the rails from volume, the sellers from consumption — except the organization whose agents do the buying. And a payment network attesting to its own transactions is a company auditing itself. The evidence layer must be neutral, open, and verifiable by anyone. That is MCA.

## What MCA specifies

- **Attestation Records** — one immutable statement per event, JCS-canonicalized, SHA-256 hash-chained
- **Checkpoints** — Ed25519-signed Merkle commitments (RFC 6962) with independent witnessing
- **The Commerce Triple** — request hash + payment receipt + delivered-content hash: proof that value moved, not just money
- **Privacy by construction** — hashes and bounded metadata only; payload bodies are never logged
- **Verification** — four procedures any party can run without trusting the log operator

## Status

v0.1 public draft. Feedback via issues. v0.2 targets: normative mandate profile, witness gossip, multi-log cross-anchoring.

---
*Specification text CC-BY-4.0 · Reference code Apache-2.0 · Initiated by [IONDRA](https://iondra.com)*
