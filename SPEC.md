# Machine Commerce Attestation (MCA)
## Specification - Draft v0.1, with the v0.2 draft change to the checkpoint chain link (Section 6.3)
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

**`record_hash`** (not part of the hashed content) = SHA-256 over the canonical form (Section 4) of the AR **excluding** any field named `record_hash`. The chain property: `AR[n].prev_hash == record_hash(AR[n-1])`.

*Served form (0.1.1).* A Log MAY include `record_hash` in the AR it serves, as a convenience to readers. Verifiers MUST exclude it before hashing and MUST NOT trust it: the served value is checked, never used.

## 4. Canonicalization & Hashing

All hashing operates on **RFC 8785 JSON Canonicalization Scheme (JCS)** output encoded as UTF-8. Hash algorithm for v0.1 is **SHA-256** exclusively; the `hash_alg` field of Checkpoints exists for future agility. Implementations MUST reject records whose canonical re-serialization does not reproduce the claimed hashes. Evidence Bundles (the raw material behind `evidence_hash`) are **never** transmitted to or stored by the Log; producers retain or discard them per their own policy - the Log holds only the hash.

## 5. Append-Only Semantics

A conforming Log MUST NOT expose any operation that mutates or deletes an AR. Corrections are new ARs (`action: mca.correction.appended`, `ext` pointing at the corrected `record_id`). A Log that has suffered damage MUST seal the damaged region behind a Checkpoint whose `notes` field declares the seal (`sealed_history: true`) rather than rewriting history; verifiers surface such seals in output.

## 6. Checkpoints

A Checkpoint is a JSON object:

| Field | Type | Req | Description |
|---|---|---|---|
| `mca_version` | string | MUST | `"0.1"`, or `"0.2"` for a Checkpoint that links by `checkpoint_hash` (Section 6.3) |
| `log_id` | string | MUST | As in Section 3 |
| `checkpoint_id` | string | MUST | Unique per Log |
| `range` | object | MUST | `{ "from_seq": n, "to_seq": m }`, inclusive; `from_seq` = previous checkpoint to_seq + 1 |
| `merkle_root` | string | MUST | Root over `record_hash` of ARs in `range`, RFC 6962 Section 2.1 tree construction |
| `prev_checkpoint_hash` | string | MUST | In a `"0.2"` Checkpoint: the `checkpoint_hash` of the previous Checkpoint (Section 6.3). In a `"0.1"` Checkpoint: SHA-256 of the previous Checkpoint's canonical form, `signature` and `witnesses` included. Genesis = 64 zeros in both |
| `hash_alg` | string | MUST | `"sha-256"` |
| `timestamp` | string | MUST | RFC 3339 UTC |
| `signature` | object | MUST | Section 7 |
| `witnesses` | array | SHOULD | Witness countersignatures (Section 8). Not covered by `checkpoint_hash` or by any signature; entries MAY be added after the Checkpoint is emitted (Section 6.3) |
| `notes` | object | MAY | e.g. `{"sealed_history": true}` |

Checkpoint cadence is operator policy; **hourly or better is RECOMMENDED** for commerce logs. The interval between an AR append and its first covering Checkpoint is the log **exposure window** and MUST be published in the Log policy document.

### 6.1 Log Descriptor (0.1.1)

A public Log publishes its policy document at `https://<log host>/.well-known/mca/log.json`. It is the anchor a verifier fetches first and the only place the operator's public key needs to be trusted from (pinning it is RECOMMENDED).

| Field | Req | Description |
|---|---|---|
| `log_id` | MUST | As in Section 3 |
| `mca_version` | MUST | `"0.1"` |
| `hash_alg` | MUST | `"sha-256"` |
| `signature_alg` | MUST | `"ed25519"` for a public Log |
| `key_id` | MUST | Section 7 derivation of `public_key_pem` |
| `public_key_pem` | MUST | Operator verification key, SPKI PEM |
| `checkpoint_cadence` | MUST | `{ "first_append": true, "max_records": n, "max_seconds": s }` — a Checkpoint is emitted on the first append after a Checkpoint and thereafter when either bound is reached. This states the exposure window. |
| `empty_windows` | SHOULD | Statement that windows with no appends emit no Checkpoint (there is no canonical empty range) |
| `leaf_input` | MUST | What the Merkle leaf is computed over; `"record_hash"` for this version |
| `record_profile` | SHOULD | `"hash-only"` when the Log omits optional plaintext fields (Section 9.1) |
| `checkpoint_link` | SHOULD (0.2) | `{ "form": "checkpoint-hash", "first_checkpoint_id": "<id>" }` once the Log emits `"0.2"` Checkpoints: the first Checkpoint that links by `checkpoint_hash` (Section 6.3). Informative: a verifier goes by each Checkpoint's own `mca_version`. The descriptor's `mca_version` is then `"0.2"` |
| `log_generations` | SHOULD | Array of `{ log_id, status: "active" \| "legacy-frozen", leaf_input, checkpoint_format }`; a frozen generation is never appended to and its Checkpoints are served with their own `log_id` |
| `witnesses` | SHOULD | Array of Witness Descriptor URLs (Section 8) the Log operator recognises; verifiers MAY witness with others |
| `links` | SHOULD | Templates for the served endpoints (Section 6.2), the spec and the verifier commit the operator tested against |

### 6.2 Served endpoints (informative profile)

The reference Log serves, without authentication and with public rate limits:

- `GET /api/mca/checkpoints/latest` — newest Checkpoint of the active generation; **404 until the first append** (an empty log is never presented as a healthy one)
- `GET /api/mca/checkpoints/{id}` — a Checkpoint by its serving id
- `GET /api/mca/checkpoints/{id}/records` — the ARs in its `range`, one JSON object per line (`application/x-ndjson`), in `seq` order
- `GET /api/mca/checkpoints/{id}/inclusion?record_hash=…` — the inclusion proof object of Section 13.4
- `GET /api/mca/records/{record_hash}` — one AR by hash
- `GET /api/mca/records-lookup?payment_hash=…` — ARs whose `commerce.payment_hash` matches (the consumer question: "is this receipt attested?")
- `POST /api/mca/checkpoints/{id}/witness` — accepts a Witness entry (Section 8) for merging into the Checkpoint's `witnesses`; authentication is operator policy. The Log MUST refuse the merge when a `"0.1"` Checkpoint already links to that Checkpoint (Section 6.3)

Tenant records are never listed; readers reach an AR only through a Checkpoint range, a hash, or a payment hash.

### 6.3 Checkpoint body, `checkpoint_hash` and the chain link (0.2)

In v0.1, `prev_checkpoint_hash` covered the whole previous Checkpoint, including `witnesses`. Witness entries are merged after a Checkpoint is emitted, so the value depended on when the previous Checkpoint was fetched: a copy taken before a merge did not reproduce a link made after it, and a merge made after the next Checkpoint was emitted broke the link for every reader. v0.2 links by a hash that witnesses cannot change.

**Checkpoint body.** The Checkpoint JSON object with the members named `signature` and `witnesses` removed.

- Only members of the top-level object are removed. A member named `signature` or `witnesses` inside another member, for example inside `notes`, is part of the body.
- Every other member is part of the body, including `notes` and any member a verifier does not recognise. A verifier MUST NOT drop a member it does not recognise before hashing.
- A Checkpoint with no `witnesses` member and a Checkpoint with `"witnesses": []` have the same body.

**Body bytes.** The RFC 8785 (JCS) serialization of the Checkpoint body, encoded as UTF-8.

- A Checkpoint MUST be valid I-JSON (RFC 7493). In particular it MUST NOT repeat a member name within one object. A verifier that can detect a repeated name MUST reject the Checkpoint.
- Every number in a Checkpoint body MUST be an integer with absolute value below 2^53. A verifier SHOULD reject a body that holds any other number.
- Strings are hashed as given: no Unicode normalization, no case folding, no trimming of whitespace.

**`checkpoint_hash`.** The SHA-256 of the body bytes, written as 64 lowercase hexadecimal characters. It identifies a Checkpoint: two copies are the same Checkpoint if and only if their `checkpoint_hash` is equal.

The body bytes are used three ways and no other byte string is defined for a Checkpoint: the operator signs them (Section 7), each Witness cosigns them (Section 8), and the next Checkpoint links to their hash.

**Chain link.** The `mca_version` of the Checkpoint that carries the link selects how the link is computed. It is part of the body, so the operator signs the choice.

- In a Checkpoint whose `mca_version` is `"0.2"`, `prev_checkpoint_hash` MUST be the `checkpoint_hash` of the Checkpoint of the same Log whose `range` ends at this Checkpoint's `from_seq - 1`. For the first Checkpoint of a Log it MUST be 64 zeros.
- In a Checkpoint whose `mca_version` is `"0.1"`, `prev_checkpoint_hash` is the v0.1 full form: SHA-256 of the canonical form of the whole previous Checkpoint, `signature` and `witnesses` included, as that Checkpoint stood when the link was made.
- A verifier MUST check the link in the form the linking Checkpoint's version selects and MUST NOT accept the other form in its place.
- A verifier MUST reject a link to a Checkpoint whose `log_id` differs from the linking Checkpoint's.

**Witness entries after emission.** A Log MAY add an entry to a Checkpoint's `witnesses` at any time, including after later Checkpoints have been emitted, when no `"0.1"` Checkpoint links to it (see legacy links below). The order of entries carries no meaning. A Log MUST NOT change anything else in a Checkpoint once it is signed, and MUST NOT add other members to it.

**Switching an existing Log.** A Log that has emitted `"0.1"` Checkpoints MAY switch without starting a new Log:

- From one Checkpoint onward, every Checkpoint the Log emits is `"0.2"`. The first of them links to the last `"0.1"` Checkpoint by that Checkpoint's `checkpoint_hash`.
- `log_id`, `seq` numbering and the AR chain do not change. Earlier links are not recomputed and earlier Checkpoints are not re-signed.
- The switch is one-way. A `"0.1"` Checkpoint that links to a `"0.2"` Checkpoint is INVALID.
- The `mca_version` of an AR and the `mca_version` of the Checkpoint that covers it are independent. A `"0.2"` Checkpoint MAY cover `"0.1"` ARs.

**Legacy links.** A `"0.1"` link covers the witness entries of the previous Checkpoint as they stood when the link was made.

- A Log MUST NOT add, remove or reorder the `witnesses` of a Checkpoint once a `"0.1"` Checkpoint links to it. Cosignatures that arrive later are served from the Witness's own origin (Section 8).
- When a `"0.1"` link does not reproduce from the previous Checkpoint as supplied, a verifier MUST test whether it reproduces after setting aside some of the supplied witness entries, keeping the order of the rest, and with no `witnesses` member when none are kept. If it does, the link holds: the hash still covers the whole body and the operator signature of the previous Checkpoint. The verifier MUST report `PREV_WITNESS_ADDED_AFTER_LINK:<witness_id>` for each entry set aside. A verifier MAY limit this test to leading runs of the entries when there are more than 12.
- A `"0.1"` link cannot be checked from a copy of the previous Checkpoint that lacks an entry the link covered. The reader fetches the served copy, confirms that its `checkpoint_hash` equals that of the copy it holds, and checks the link against the served copy.

## 7. Signatures

`signature` = `{ "alg": "ed25519", "key_id": "<log key identifier>", "sig": "<base64url>" }` over the canonical Checkpoint excluding `signature` and `witnesses`, that is, over the body bytes of Section 6.3.

- **Ed25519 is MANDATORY to implement** for public logs. ECDSA P-256 (`"es256"`) is OPTIONAL.
- **`key_id` derivation (0.1.1, normative for Ed25519):** `"ed25519:"` followed by the first 16 lowercase hex characters of SHA-256 over the key's SubjectPublicKeyInfo DER encoding. Verifiers MUST compute it from the published key rather than trust the field, and MUST refuse a Checkpoint whose `signature.key_id` does not match a key they hold for the Log.
- **HMAC-SHA256 (`"hs256"`) is permitted only in Private Deployment Mode** (single-organization logs where verifier and operator share trust); such Checkpoints are non-verifiable by third parties and MUST NOT be presented as public attestations. *(Note: the IONDRA reference log launched in HMAC private mode and migrates to Ed25519 public mode at MCA launch; both modes are conformant in their respective scopes.)*
- Log signing keys SHOULD be custodied in an HSM or equivalent; key rotation is announced via a `mca.log.key_rotated` AR and a policy-document update.

## 8. Witnessing

A Witness fetches a Checkpoint, verifies its internal consistency (Section 13.3) **and its `prev_checkpoint_hash` against the last Checkpoint that Witness itself witnessed**, and returns a countersignature over the same canonical bytes the operator signed (the Checkpoint excluding `signature` and `witnesses`).

*Chain check by a Witness (0.2).* A Witness records the `checkpoint_hash` (Section 6.3) of each Checkpoint it cosigns. For a `"0.2"` Checkpoint it compares `prev_checkpoint_hash` with the `checkpoint_hash` it recorded for the previous one; no second fetch is needed and witness entries merged in the meantime make no difference. For a `"0.1"` Checkpoint it fetches the served copy of the previous Checkpoint, confirms that copy has the `checkpoint_hash` it recorded, and checks the link against that copy as Section 6.3 describes.

**Witness entry (0.1.1):**

```json
{ "witness_id": "witness.example.org", "key_id": "ed25519:…", "alg": "ed25519",
  "timestamp": "<RFC 3339 UTC>", "sig": "<base64url>" }
```

`witness_id` is a domain-style name chosen by the Witness; `key_id` follows the Section 7 derivation of the Witness's own key; `alg` MUST be `"ed25519"` for public witnessing. A Checkpoint with >=1 witness entry is **witnessed**; verifiers MUST report witnessed status per entry (Section 13).

**Witness Descriptor (0.1.1).** A Witness publishes `https://<witness host>/.well-known/mca/witness.json` with `witness_id`, `operator` (a plain statement of who runs it — an operator-run witness MUST say so), `alg`, `key_id`, `public_key_pem`, the `log_id` it watches, and where its cosignatures can be fetched (`/witnessed/{checkpoint_id}` RECOMMENDED). It SHOULD also publish the `checkpoint_id` and `checkpoint_hash` (Section 6.3) of the last Checkpoint it cosigned, so that observers can compare what they were shown. A cosignature served from the Witness's own origin is authoritative whether or not the Log has merged it into the Checkpoint's `witnesses`; verifiers SHOULD fetch from the Witness, not only from the Log.

**Independence.** A witness run by the Log operator is permitted and is better than none, but it is not *independent*: verifiers and policies that require independence count only witnesses whose `operator` is a different party. **Split-view detection:** a Witness that observes a different body for a Checkpoint it has already witnessed, that is, the same `checkpoint_id` or `range` with a different `checkpoint_hash`, MUST stop cosigning and publish the divergence. A copy that differs only in its `witnesses` is the same Checkpoint and is not a split view. Gossip between verifiers and witnesses is RECOMMENDED and will be profiled in v0.2. Split-view attacks (showing different histories to different parties) are detected when any two observers compare `prev_checkpoint_hash` chains - gossip between verifiers and witnesses is RECOMMENDED and will be profiled in v0.2.

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

*Hash-only profile (0.1.1).* On a public Log, `amount` and `counterparty` MAY be omitted from the served AR (`record_profile: "hash-only"` in the Log Descriptor) so that traffic analysis of the public tree cannot reveal a tenant's volumes; they remain in the producer's private ledger and in the Evidence Bundle behind `evidence_hash`. The three hashes and `rail` MUST still be present for the AR to count as a Commerce Triple. The receipt descriptor that `payment_hash` commits to is rail-specific (for `x402`: network, asset, payTo, amount, txHash, facilitator; for `card`: processor and its intent/charge identifiers) and MUST NOT contain a PAN, CVC, or natural-person identifier.

### 9.2 Mandate Profile (informative in v0.1, normative in v0.2)
A Mandate is a signed JSON grant: `{ subject_id, scope: {domains|categories}, limits: {per_txn, daily, velocity}, expiry, delegation: {depth, narrowing}, signer, signature }`. ARs reference it by `mandate_ref`. Verifying that a payment *complied* with its mandate is an application-layer check; MCA guarantees only that the mandate referenced is the mandate that governed.

## 10. Privacy Requirements

Logs MUST NOT accept: payload bodies, raw request/response content, natural-person names, precise geolocation, or unhashed account/card identifiers. `subject_id` for human subjects MUST be a role or pseudonymous identifier. Amount and counterparty fields MAY be present (they are the point of commerce evidence) but producers MAY hash `counterparty` where confidentiality demands. Conformance testing includes negative vectors that a compliant Log MUST reject.

## 11. Versioning & Extensions

`mca_version` follows semver-minor within a major line; verifiers accept any `0.x` record whose MUST fields validate. For a Checkpoint, `mca_version` also selects the form of its chain link (Section 6.3), so a verifier MUST refuse a Checkpoint whose version it does not implement rather than guess the form. Extensions live under `ext` with reverse-domain namespaces (`"ext": {"com.iondra.sentinel": {...}}`) and MUST NOT alter verification semantics.

## 12. Registries (initial)

**Actions:** `commerce.payment.executed`, `commerce.payment.blocked`, `commerce.delivery.attested`, `commerce.dispute.opened`, `mandate.issued`, `mandate.revoked`, `mca.correction.appended`, `mca.log.key_rotated`, plus the `x.` prefix for unregistered experimental actions. **Rails:** `x402`, `ap2`, `card`, `ach`, `other`. Registry changes occur via pull request under GOVERNANCE.md. See `registries/`.

## 13. Verification Procedures

A conforming verifier implements four checks and reports each independently:

1. **Record integrity:** canonicalize AR -> `record_hash`; recompute `evidence_hash` if the Evidence Bundle is supplied.
2. **Chain integrity:** for a sequence of ARs, `prev_hash` linkage holds and `seq` is gapless.
3. **Checkpoint verification:** Merkle root over the range record_hash values matches; operator signature valid; `prev_checkpoint_hash` chain intact back to a trusted anchor (a pinned Checkpoint or genesis), each link checked in the form its Checkpoint's `mca_version` selects (Section 6.3).
4. **Inclusion proof:** given an AR and an RFC 6962 audit path, the AR is included under a signed Checkpoint root.

Output vocabulary: `VALID`, `INVALID(<reason>)`, `UNWITNESSED`, `WITNESSED:<witness_id>`, `WITNESS_UNVERIFIED:<witness_id>`, `PREV_WITNESS_ADDED_AFTER_LINK:<witness_id>`, `UNANCHORED`, `SEALED_HISTORY_PRESENT`. A verifier MUST NOT report overall validity while suppressing anchor or seal caveats.

*Witness reporting (0.1.1).* `UNWITNESSED` means exactly that the Checkpoint's `witnesses` array is empty. For each entry present, a verifier reports `WITNESSED:<witness_id>` when it holds that Witness's key and the countersignature verifies, `WITNESS_UNVERIFIED:<witness_id>` when it holds no key for it, and `INVALID(bad-witness-signature:<witness_id>)` when a key it holds fails to verify the entry.

*Chain link reporting (0.2).* `PREV_WITNESS_ADDED_AFTER_LINK:<witness_id>` accompanies a `VALID` result for a `"0.1"` link that reproduces only after that witness entry of the previous Checkpoint is set aside (Section 6.3). A link in the wrong form for its Checkpoint's version, a `"0.1"` Checkpoint that follows a `"0.2"` one, and a previous Checkpoint from another Log are each `INVALID(checkpoint-chain-broken:…)`.

*Inclusion proof, served form (0.1.1).* A Log serves an inclusion proof as `{ "checkpoint_id", "record_hash", "leaf_index", "tree_size", "audit_path": [ { "position": "left" | "right", "hash" } … ], "merkle_root" }`. `audit_path` is the RFC 6962 path bottom-up, `position` naming where the *sibling* sits. Verifiers MUST accept both this object and a bare `audit_path` array, and when the object names `merkle_root`, `checkpoint_id` or `record_hash`, each MUST agree with the Checkpoint and AR being verified or the proof is INVALID.

## 14. Security Considerations

The exposure window (Section 6) bounds silent-rewrite risk before first checkpointing; operators minimize it and MUST disclose it. Log-operator key compromise permits forged checkpoints going forward but cannot silently rewrite witnessed history - witnessing is the primary defense and multi-witness policies are RECOMMENDED for logs anchoring financial disputes. HMAC private mode provides no third-party verifiability by design. MCA proves what was *recorded*, not that recorded events were *wise*: garbage-in remains garbage, immutably. Producers are the trust boundary for evidence honesty; applications above MCA (governance, oracles) exist precisely to price that residual risk.

## Appendix A - Relationship to Prior Art
RFC 6962 (Certificate Transparency) supplies the log/checkpoint/inclusion architecture; MCA generalizes the leaf from certificate to commerce attestation and adds the Commerce Triple and subject/mandate model. RFC 8785 supplies canonicalization. x402/AP2/card agent protocols are *complementary*: they move value; MCA proves it moved and under whose authority.

## Appendix B - Conformance
An implementation claims conformance as **Producer**, **Log**, **Verifier**, or **Witness**, and MUST pass the corresponding vectors in `mca-verify/test/vectors` (positive chains, tampered-record, gap, forged-checkpoint, witnessed and witness-forged checkpoints, wrapped inclusion proof, wrong-canonicalization, privacy-rejection, sealed-history cases). Generated vectors regenerate deterministically via `npm test`; the `production/` vectors are static captures from the reference Log (`log.iondra.com/main/record-hash-v1`, Checkpoints `rh1-cp-5..8`, records `seq 0..5`, captured 2026-11-04, and the witnessed Checkpoints `rh1-cp-9..15`, captured 2026-11-18) and are the first conformance vectors taken from a running Log. The `v02/` vectors (0.2) are one Log of four Checkpoints that crosses the switch of Section 6.3, each Checkpoint as emitted and as served after a late witness merge, with the expected result of every case in `expected.json`. A **Witness** implementation additionally MUST refuse to cosign a Checkpoint whose operator signature or Merkle root fails, and MUST halt on a split view.

*Feedback: open an issue on this repository. v0.2 targets: delegation-chain normativity, witness gossip profile, multi-log cross-anchoring.*
