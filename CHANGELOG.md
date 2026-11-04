# Changelog

## v0.1.1 (addendum, 2026-11-04)

Documents the wire format the reference Log has run in production since 31 Aug 2026 (first attested machine payment, https://www.iondra.com/proof/0). No change to hashing, canonicalization, or signature semantics; 0.1 records and checkpoints verify unchanged.

- §3: served ARs MAY carry `record_hash`; verifiers exclude it and never trust it
- §6.1: Log Descriptor at `/.well-known/mca/log.json` (operator key, cadence/exposure window, leaf input, record profile, log generations, recognised witnesses, endpoint links)
- §6.2: served endpoints profile, including `records-lookup?payment_hash=` and the witness submission endpoint; `latest` is 404 until the first append
- §7: normative `key_id` derivation for Ed25519 (`"ed25519:" + first 16 hex of sha256(SPKI DER)`)
- §8: witness entry fields (`witness_id`, `key_id`, `alg`, `timestamp`, `sig`), Witness Descriptor at `/.well-known/mca/witness.json`, independence rule, split-view halt
- §9.1: hash-only profile (`amount` and `counterparty` MAY be omitted on a public Log); receipt-descriptor privacy rule
- §13: `WITNESSED:<id>` / `WITNESS_UNVERIFIED:<id>` vocabulary; inclusion proof served (object) form
- Appendix B: witness vectors and static production vectors

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
