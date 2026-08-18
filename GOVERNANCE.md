# MCA Governance (v0.1 phase)

- **Editor & reference-log operator:** IONDRA (Silver Nsaka). The editor merges spec changes and operates the reference implementation.
- **Change process:** all normative changes via public pull request with a minimum 14-day comment window; registry additions (actions, rails) are lightweight PRs with a 7-day window.
- **Versioning:** semver; breaking changes only at major versions; drafts tagged `vX.Y-draft.N`.
- **Conformance:** the conformance vectors in the reference verifier repository (`mca-verify/test/vectors`) are normative companions to the spec text; a spec change that alters verification MUST land with updated vectors in the same release.
- **Neutral destination (stated intent):** upon meaningful multi-party adoption, stewardship moves to a neutral home — a foundation or an IETF Internet-Draft track. This intent is declared now, at v0.1, so adopters can rely on it.
- **License:** specification text CC-BY-4.0; all reference code Apache-2.0.
