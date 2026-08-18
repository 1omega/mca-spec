# MCA Action Registry (v0.1)

| Action | Meaning |
|---|---|
| commerce.payment.executed | A payment was executed by/for a machine subject |
| commerce.payment.blocked | A payment was denied by policy |
| commerce.delivery.attested | Delivered-content hash bound to a prior payment record |
| commerce.dispute.opened | A dispute case references prior records |
| mandate.issued | A commerce mandate was signed |
| mandate.revoked | A mandate was revoked |
| mca.correction.appended | Corrective record referencing an earlier record_id |
| mca.log.key_rotated | Log signing key rotation announcement |

Experimental actions use the `x.` prefix. Additions via PR (see GOVERNANCE.md).
