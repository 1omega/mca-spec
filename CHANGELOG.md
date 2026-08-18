# Changelog

## v0.1-draft.1

Initial public draft:

- Attestation Record (AR) data model with subject model (machine / human / system)
- RFC 8785 (JCS) canonicalization and SHA-256 hash-chained append-only log
- RFC 6962 Section 2.1 Merkle-tree checkpoints
- Ed25519 public-log signatures with HMAC-SHA256 private deployment mode
- Witnessing and split-view detection via prev_checkpoint_hash gossip
- The Commerce Triple (request / payment receipt / delivered content hashes)
- Privacy requirements (hashes and bounded metadata only; never payload bodies)
- Verification procedures and result vocabulary (VALID / INVALID with UNWITNESSED, UNANCHORED, SEALED_HISTORY_PRESENT caveats)
- Conformance profiles (Producer, Log, Verifier, Witness) and vector suite
