# Agent Agreement Black Box

> **This project continues as [BotVow](https://github.com/Santiago1971/botvow)** — the black box for Bots (Bot 2 Bot; agents of other AI platforms follow the same rules). New work happens there; this repository stays as the original prototype.
> *O projeto continua em [Santiago1971/botvow](https://github.com/Santiago1971/botvow).*


**A signed, tamper-evident receipt of what two AI agents agreed — verifiable by anyone, with nothing but public keys.**

Agents are starting to negotiate and commit on behalf of people and businesses (A2A, MCP, AP2).
When something goes wrong, the first question will be: *what exactly did your agent accept?*
Agent Agreement Black Box answers that with a tiny, open format: a hash-chained log in which every
entry is signed with Ed25519, and the agreement itself is co-signed by **both** agents.
Neither side can later rewrite, delete, reorder or quietly drop what was agreed without the
verification failing.

It is part of [Está no Ir](https://estanoir.grok.me/), an open travel notebook for people and agents
(see also [estanoir-agents](https://github.com/Santiago1971/estanoir-agents)).

> **What this is not.** This is a notebook-style open tool, not a legal notary, a timestamping
> authority or a contract. It provides *evidence* that the listed keys signed the listed content in
> the listed order. It does not prove who controls a key, that every message was recorded, or that
> a summary is truthful.

## Quick start

```bash
pip install -r requirements.txt     # cryptography (+ jsonschema, optional)
./run_demo.sh                       # build the sample, verify it, run 8 tamper tests, check the schema
```

Verify any log:

```bash
python3 tools/aabb.py verify examples/sample-log.json            # VERIFY OK, exit 0
python3 tools/aabb.py verify examples/sample-log-tampered.json   # TAMPER DETECTED, exit 1
python3 tools/aabb.py verify LOG.json --head <hex>               # also compare with a head hash published elsewhere
```

Saved output of the last run: [`examples/demo-output.txt`](examples/demo-output.txt).

## How it works (short)

| Element | Rule |
|---|---|
| Chain | Ordered JSON entries, each validated by [`schema/record.schema.json`](schema/record.schema.json) |
| `genesis` | Entry 0. Lists the parties (key id, name, raw Ed25519 public key, optional A2A Agent Card URL). Signed by all parties |
| Other entries | `proposal`, `counter`, `agreement`, `amendment`, `termination`, `seal` |
| Co-signing | `genesis`, `agreement` and `seal` must be signed by **all** parties; other entries by their author |
| Signature | Ed25519 over the canonical JSON of the entry without `signatures` and `entry_hash` |
| Entry hash | SHA-256 of the canonical JSON of the entry without `entry_hash` (signatures included) |
| Link | `prev_hash` = `entry_hash` of the previous entry; 64 zeros for genesis |
| Seal | Closes the chain and states how many entries precede it |

Full rules: [SPEC.md](SPEC.md).

### What the verifier checks
1. Genesis is well formed and every key id matches its public key.
2. Same `chain_id` everywhere; `seq` equals position (catches deleted or reordered entries).
3. `prev_hash` links and recomputed `entry_hash` (catches edits).
4. Every signature is valid and made by a party key; the author signed; multi-party entries carry all signatures.
5. The last entry is a `seal` with the right count (catches truncation of a closed chain).
6. Optionally, the head hash matches one the parties published elsewhere (catches forks and truncation).

### Tamper tests in `run_demo.sh`
Edit a field · edit and recompute the hash · delete an entry · reorder entries · rewrite and re-sign
with an outsider key · drop the seal · agreement with one signature only · edit the genesis.
Each one must be reported as `TAMPER DETECTED`.

## Privacy by default
- **Raw messages are never stored.** Proposals and counter-proposals are kept only as `payload_sha256`.
  A party can reveal a message later and anyone can check it against the hash.
- A human-readable `summary` is stored only when both parties set `consent_to_publish_summary: true`,
  and it must match `summary_sha256`.
- Do not put personal data in a public chain. For personal matters, keep the chain private and publish
  only the head hash.

## Sample
[`examples/sample-log.json`](examples/sample-log.json) records a no-money agreement between two
**fictional** agents: a guide agent may cite a fictional estate's visit hours, with attribution and
the date checked, until 2026-12-31. The demo keys are derived from fixed public seeds so the output is
reproducible. **Never use them for anything real.**

## Known limits
- Timestamps are claimed by the agents, not proven. Planned: RFC 3161 timestamps or a transparency log.
- Canonical JSON is a strict subset of RFC 8785 (sorted keys, no whitespace, UTF-8, no floats).
- Binding a key to a real organisation (signed A2A Agent Card, DNS) is out of scope for v0.1.

## Related work
This builds on, and is narrower than, existing work. Checked on 2026-11-11:
- A2A Agent Card signing (JWS + RFC 8785) — https://a2a-protocol.org/latest/specification/
- AP2 mandates and receipts for agent payments — https://ap2-protocol.org/ap2/specification/
- Agent Receipts / obsigna — https://github.com/agent-receipts/obsigna/
- Signet (signed, hash-chained tool-call receipts, bilateral co-signing) — https://github.com/Prismer-AI/signet/
- Aevum — https://github.com/aevum-labs/aevum · Logsiegel — https://logsiegel.com/en/ · AgentLedger — https://github.com/dembovvski/agentledger

Those focus mostly on one agent's own actions or on payments. This project focuses only on the
**bilateral agreement** between two agents.

## Licence
Code (`tools/`, `run_demo.sh`): MIT. Specification, docs, schema and examples: CC BY 4.0.
See [LICENSE](LICENSE).

## Contact
Está no Ir — hmv+estanoir@mail.grokbot.com · https://estanoir.grok.me/
