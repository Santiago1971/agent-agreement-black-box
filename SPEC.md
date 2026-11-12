# Agent Agreement Black Box — Specification v0.1

Status: v0.1. Licence: CC BY 4.0. Key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Entry
Each entry is a JSON object with exactly these members (see `schema/record.schema.json`):
`spec`, `chain_id`, `seq`, `prev_hash`, `ts`, `type`, `author`, `content`, `signatures`, `entry_hash`.

- `spec` MUST be `"agent-agreement-black-box/0.1"`.
- `seq` MUST be 0 for the genesis and increase by 1.
- `ts` is an RFC 3339 UTC time claimed by the author.
- `author` is the key id of the author.
- `type` is one of `genesis`, `proposal`, `counter`, `agreement`, `amendment`, `termination`, `seal`.

## 2. Keys
- Algorithm: Ed25519. Public keys are carried raw, base64url without padding.
- `kid = "ed25519:" + hex(SHA-256(raw public key))[0:16]`.
- The genesis `content.parties` array lists every party: `kid`, `name`, `pubkey`, optional `agent_card` URL.
  A verifier MUST check that each `kid` matches its `pubkey`.

## 3. Canonical form
`canonical(x)` = UTF-8 JSON with keys sorted lexicographically, no insignificant whitespace, no
floating-point numbers. This is a strict subset of RFC 8785 (JCS).

## 4. Signatures and hashes
- `body(e)` = `e` without `signatures` and `entry_hash`.
- Each signature is `{ "kid", "alg": "Ed25519", "sig": base64url(Ed25519(canonical(body(e)))) }`.
- `entry_hash = hex(SHA-256(canonical(e without entry_hash)))`; signatures are included.
- `prev_hash` MUST equal the previous entry's `entry_hash`; for the genesis it is 64 `"0"` characters.

## 5. Signing rules
- The author MUST sign its entry.
- `genesis`, `agreement` and `seal` MUST be signed by every party listed in the genesis.
- `seal.content.entries` MUST equal the number of entries before the seal. Nothing may follow a seal.

## 6. Privacy
- Raw messages MUST NOT be stored. Use `content.payload_sha256` (hex SHA-256 of the UTF-8 message).
- `content.summary` MAY be present only if `content.consent_to_publish_summary` is `true`;
  `content.summary_sha256` MUST match it.
- Public chains SHOULD NOT contain personal data.

## 7. Verification
A verifier MUST report failure if any rule in sections 1–5 is broken. It SHOULD accept an optional
expected head hash and report a mismatch. Result: `VERIFY OK` or `TAMPER DETECTED` with reasons.

## 8. Out of scope for v0.1
Trusted timestamps, key revocation and rotation, identity binding, more than two parties in the
reference tool (the format allows it), encryption.
