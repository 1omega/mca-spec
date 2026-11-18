# Changelog

## v0.2-draft.1 (proposed, not published): the checkpoint chain link

Closes issue #2. In v0.1, `prev_checkpoint_hash` covered the whole previous Checkpoint, including its `witnesses`, which change after the Checkpoint is emitted. Observed on the reference Log on 2026-11-05 (`rh1-cp-10`, `rh1-cp-11`).

- §6.3 (new): Checkpoint body, body bytes and `checkpoint_hash`, defined once and used for the operator signature, witness cosignatures and the chain link
- §6, §6.3: a Checkpoint with `mca_version` `"0.2"` links by the previous Checkpoint's `checkpoint_hash`; the linking Checkpoint's version selects the form and a verifier accepts no other
- §6.3: an existing Log switches in place, one way, without a new `log_id`; earlier links and signatures are untouched
- §6.3: rules for legacy `"0.1"` links: witness entries are frozen once a `"0.1"` Checkpoint links to them; verifiers tolerate entries merged later and report `PREV_WITNESS_ADDED_AFTER_LINK:<witness_id>`
- §6.1: `checkpoint_link` in the Log Descriptor; §6.2: the witness endpoint refuses a merge that would break a `"0.1"` link
- §8: a Witness records and compares `checkpoint_hash`; a copy that differs only in `witnesses` is not a split view
- §11, §13: a verifier refuses a Checkpoint version it does not implement; new reporting vocabulary
- Appendix B: `v02/` vectors and production Checkpoints `rh1-cp-9..15`

Every v0.1 Checkpoint and AR verifies unchanged.

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
