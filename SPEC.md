# Machine Commerce Attestation (MCA)
## Specification - Draft v0.1
**Status:** Public Draft for Community Review | **Editor:** Silver Nsaka (IONDRA) | **License:** Text CC-BY-4.0; reference code Apache-2.0
**Reference implementation & public verification API:** iondra.com | **Reference verifier:** github.com/1omega/mca-verify

---

## Abstract

Autonomous agents are becoming paying participants in the internet economy. Payment rails such as x402-class HTTP-402 protocols, AP2-style payment mandates, and card-network agent programs define how machines *pay*. No open format defines how anyone *proves*, after the fact, that a machine transaction was authorized, what was delivered in exchange, and that the record of it has not been rewritten. This document specifies **Machine Commerce Attestation (MCA)**: a rail-agnostic format for tamper-evident attestation records, an append-only hash-chained log structure with Merkle-anchored checkpoints, and the procedures by which any party can verify a record integrity, inclusion, and authority chain. MCA is to machine commerce what Certificate Transparency is to TLS issuance: not a payment system, but the public evidence layer that makes payment systems accountable.

## 1. Motivation & Design Goals

1. **Neutrality.** Parties that move money or sell resources cannot credibly attest to their own conduct. MCA records MUST be verifiable without trusting the log operator, via signed checkpoints and (optionally) external witnesses.
2. **Rail-agnosticism.** MCA binds evidence to commerce events regardless of settlement mechanism (HTTP-402 stablecoin rails, card networks, ACH, invoicing).
3. **Privacy by construction.** MCA records carry hashes and bounded metadata - never payload bodies, never raw personal data (Section 10).
4. **Minimality.** Anything not required for verification is out of scope. Governance policy, risk scoring, and dispute adjudication are applications *above* MCA, not part of it.
5. **Implementability.** A conforming verifier MUST be buildable from this document and the published test vectors alone.

Requirement keywords **MUST**, **SHOULD**, **MAY** are used per RFC 2119.

## 2. Terminology

- **Attestation Record (AR):** one immutable statement that an event occurred, with evidence hash and subject identity.
- **Subject:** the actor an AR describes - `machine`, `human`, or `system`.
- **Log:** an append-only sequence of ARs maintained by a **Log Operator**.
- **Checkpoint:** a signed commitment to the state of a Log at a point in time, containing a Merkle root over ARs since the previous Checkpoint.
- **Witness:** a party independent of the Log Operator that countersigns Checkpoints.
- **Mandate:** a signed grant of commerce authority to a machine Subject (scope, limits, expiry, signer). MCA references mandates by hash; mandate *semantics* are profiled in Section 9.2.
- **Commerce Triple:** the three bound hashes of a purchase - request, payment receipt, delivered content (Section 9.1).

## 3. Data Model - the Attestation Record

An AR is a JSON object with the following fields. Unknown fields MUST be preserved by logs and ignored by verifiers (Section 11).

| Field | Type | Req | Description |
|---|---|---|---|
| `mca_version` | string | MUST | `"0.1"` |
| `record_id` | string | MUST | Globally unique, <=128 chars; UUIDv7 RECOMMENDED |
| `log_id` | string | MUST | Identifier of the Log (domain-prefixed, e.g. `log.iondra.com/main`) |
| `seq` | integer | MUST | Zero-based position in the Log; strictly increasing by 1 |
| `timestamp` | string | MUST | RFC 3339 UTC, millisecond precision |
| `subject_type` | string | MUST | `machine` / `human` / `system` |
| `subject_id` | string | MUST | Opaque identifier of the Subject (SPIFFE ID, DID, or operator-scoped id) |
| `action` | string | MUST | Registered action name (Section 12), e.g. `commerce.payment.executed` |
| `evidence_hash` | string | MUST | Lowercase hex SHA-256 of the canonicalized Evidence Bundle (Section 4) |
| `prev_hash` | string | MUST | `record_hash` of the AR at `seq-1`; for `seq=0`, 64 zeros |
| `mandate_ref` | string | SHOULD (commerce) | SHA-256 of the governing Mandate document |
| `commerce` | object | MAY | Commerce Triple binding (Section 9.1) |
| `ext` | object | MAY | Namespaced extensions (Section 11) |

**`record_hash`** (not stored in the AR itself) = SHA-256 over the canonical form (Section 4) of the AR **excluding** any field named `record_hash`. The chain property: `AR[n].prev_hash == record_hash(AR[n-1])`.

## 4. Canonicalization & Hashing

All hashing operates on **RFC 8785 JSON Canonicalization Scheme (JCS)** output encoded as UTF-8. Hash algorithm for v0.1 is **SHA-256** exclusively; the `hash_alg` field of Checkpoints exists for future agility. Implementations MUST reject records whose canonical re-serialization does not reproduce the claimed hashes. Evidence Bundles (the raw material behind `evidence_hash`) are **never** transmitted to or stored by the Log; producers retain or discard them per their own policy - the Log holds only the hash.

## 5. Append-Only Semantics

A conforming Log MUST NOT expose any operation that mutates or deletes an AR. Corrections are new ARs (`action: mca.correction.appended`, `ext` pointing at the corrected `record_id`). A Log that has suffered damage MUST seal the damaged region behind a Checkpoint whose `notes` field declares the seal (`sealed_history: true`) rather than rewriting history; verifiers surface such seals in output.

## 6. Checkpoints

A Checkpoint is a JSON object:

| Field | Type | Req | Description |
|---|---|---|---|
| `mca_version` | string | MUST | `"0.1"` |
| `log_id` | string | MUST | As in Section 3 |
| `checkpoint_id` | string | MUST | Unique per Log |
| `range` | object | MUST | `{ "from_seq": n, "to_seq": m }`, inclusive; `from_seq` = previous checkpoint to_seq + 1 |
| `merkle_root` | string | MUST | Root over `record_hash` of ARs in `range`, RFC 6962 Section 2.1 tree construction |
| `prev_checkpoint_hash` | string | MUST | SHA-256 of previous Checkpoint canonical form; genesis = 64 zeros |
| `hash_alg` | string | MUST | `"sha-256"` |
| `timestamp` | string | MUST | RFC 3339 UTC |
| `signature` | object | MUST | Section 7 |
| `witnesses` | array | SHOULD | Witness countersignatures (Section 8) |
| `notes` | object | MAY | e.g. `{"sealed_history": true}` |

Checkpoint cadence is operator policy; **hourly or better is RECOMMENDED** for commerce logs. The interval between an AR append and its first covering Checkpoint is the log **exposure window** and MUST be published in the Log policy document.

## 7. Signatures

`signature` = `{ "alg": "ed25519", "key_id": "<log key identifier>", "sig": "<base64url>" }` over the canonical Checkpoint excluding `signature` and `witnesses`.

- **Ed25519 is MANDATORY to implement** for public logs. ECDSA P-256 (`"es256"`) is OPTIONAL.
- **HMAC-SHA256 (`"hs256"`) is permitted only in Private Deployment Mode** (single-organization logs where verifier and operator share trust); such Checkpoints are non-verifiable by third parties and MUST NOT be presented as public attestations. *(Note: the IONDRA reference log launched in HMAC private mode and migrates to Ed25519 public mode at MCA launch; both modes are conformant in their respective scopes.)*
- Log signing keys SHOULD be custodied in an HSM or equivalent; key rotation is announced via a `mca.log.key_rotated` AR and a policy-document update.

## 8. Witnessing

A Witness fetches a Checkpoint, verifies its internal consistency (Section 13.3), and returns `{ "witness_id", "timestamp", "sig" }` over the same canonical bytes the operator signed. A Checkpoint with >=1 independent witness is **witnessed**; verifiers MUST report witnessed status. Split-view attacks (showing different histories to different parties) are detected when any two observers compare `prev_checkpoint_hash` chains - gossip between verifiers and witnesses is RECOMMENDED and will be profiled in v0.2.

## 9. Commerce Bindings

### 9.1 The Commerce Triple
For purchase events, the `commerce` object binds payment to value:

```json
"commerce": {
  "rail": "x402 | ap2 | card | ach | other",
  "request_hash":  "<sha256 of canonicalized request descriptor>",
  "payment_hash":  "<sha256 of canonicalized rail receipt>",
  "delivery_hash": "<sha256 of delivered content or delivery descriptor>",
  "amount": { "value": "1.25", "currency": "USD" },
  "counterparty": "<domain or endpoint identifier>"
}
```

`delivery_hash` MAY be absent at payment time and supplied via a follow-up AR (`commerce.delivery.attested`) referencing the original `record_id`. A triple with all three hashes present and chain-verified constitutes **proof of value transfer**, the evidentiary unit disputes settle on.

### 9.2 Mandate Profile (informative in v0.1, normative in v0.2)
A Mandate is a signed JSON grant: `{ subject_id, scope: {domains|categories}, limits: {per_txn, daily, velocity}, expiry, delegation: {depth, narrowing}, signer, signature }`. ARs reference it by `mandate_ref`. Verifying that a payment *complied* with its mandate is an application-layer check; MCA guarantees only that the mandate referenced is the mandate that governed.

## 10. Privacy Requirements

Logs MUST NOT accept: payload bodies, raw request/response content, natural-person names, precise geolocation, or unhashed account/card identifiers. `subject_id` for human subjects MUST be a role or pseudonymous identifier. Amount and counterparty fields MAY be present (they are the point of commerce evidence) but producers MAY hash `counterparty` where confidentiality demands. Conformance testing includes negative vectors that a compliant Log MUST reject.

## 11. Versioning & Extensions

`mca_version` follows semver-minor within a major line; verifiers accept any `0.x` record whose MUST fields validate. Extensions live under `ext` with reverse-domain namespaces (`"ext": {"com.iondra.sentinel": {...}}`) and MUST NOT alter verification semantics.

## 12. Registries (initial)

**Actions:** `commerce.payment.executed`, `commerce.payment.blocked`, `commerce.delivery.attested`, `commerce.dispute.opened`, `mandate.issued`, `mandate.revoked`, `mca.correction.appended`, `mca.log.key_rotated`, plus the `x.` prefix for unregistered experimental actions. **Rails:** `x402`, `ap2`, `card`, `ach`, `other`. Registry changes occur via pull request under GOVERNANCE.md. See `registries/`.

## 13. Verification Procedures

A conforming verifier implements four checks and reports each independently:

1. **Record integrity:** canonicalize AR -> `record_hash`; recompute `evidence_hash` if the Evidence Bundle is supplied.
2. **Chain integrity:** for a sequence of ARs, `prev_hash` linkage holds and `seq` is gapless.
3. **Checkpoint verification:** Merkle root over the range record_hash values matches; operator signature valid; `prev_checkpoint_hash` chain intact back to a trusted anchor (a pinned Checkpoint or genesis).
4. **Inclusion proof:** given an AR and an RFC 6962 audit path, the AR is included under a signed Checkpoint root.

Output vocabulary: `VALID`, `INVALID(<reason>)`, `UNWITNESSED`, `UNANCHORED`, `SEALED_HISTORY_PRESENT`. A verifier MUST NOT report overall validity while suppressing anchor or seal caveats.

## 14. Security Considerations

The exposure window (Section 6) bounds silent-rewrite risk before first checkpointing; operators minimize it and MUST disclose it. Log-operator key compromise permits forged checkpoints going forward but cannot silently rewrite witnessed history - witnessing is the primary defense and multi-witness policies are RECOMMENDED for logs anchoring financial disputes. HMAC private mode provides no third-party verifiability by design. MCA proves what was *recorded*, not that recorded events were *wise*: garbage-in remains garbage, immutably. Producers are the trust boundary for evidence honesty; applications above MCA (governance, oracles) exist precisely to price that residual risk.

## Appendix A - Relationship to Prior Art
RFC 6962 (Certificate Transparency) supplies the log/checkpoint/inclusion architecture; MCA generalizes the leaf from certificate to commerce attestation and adds the Commerce Triple and subject/mandate model. RFC 8785 supplies canonicalization. x402/AP2/card agent protocols are *complementary*: they move value; MCA proves it moved and under whose authority.

## Appendix B - Conformance
An implementation claims conformance as **Producer**, **Log**, **Verifier**, or **Witness**, and MUST pass the corresponding vectors in `mca-verify/test/vectors` (positive chains, tampered-record, gap, forged-checkpoint, wrong-canonicalization, privacy-rejection, sealed-history cases). Test vectors ship with the reference verifier and regenerate deterministically via `npm test`.

*Feedback: open an issue on this repository. v0.2 targets: delegation-chain normativity, witness gossip profile, multi-log cross-anchoring.*
