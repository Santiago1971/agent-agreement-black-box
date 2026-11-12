#!/usr/bin/env python3
"""Agent Agreement Black Box - reference tool for spec agent-agreement-black-box/0.1

Builds a hash-chained, Ed25519-signed record of what two agents agreed,
verifies it, and demonstrates that tampering is detected.

Usage:
  python3 tools/aabb.py demo                     # write examples/sample-log*.json and run all tamper tests
  python3 tools/aabb.py verify FILE [--head HEX]  # exit 0 = VERIFY OK, exit 1 = TAMPER DETECTED

Licence: MIT (see LICENSE).
"""
import base64, copy, hashlib, json, os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

SPEC = "agent-agreement-black-box/0.1"
HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLES = os.path.join(HERE, "..", "examples")
GENESIS_PREV = "0" * 64

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def ub64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def canon(obj):
    """Canonical JSON (JCS-like subset: sorted keys, no spaces, UTF-8).
    Valid for the record format here (strings, ints, bools, objects, arrays; no floats)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_hex(b): return hashlib.sha256(b).hexdigest()

def body_of(entry):
    return {k: v for k, v in entry.items() if k not in ("signatures", "entry_hash")}

def entry_hash(entry):
    # hash covers body AND signatures, so swapping a signature also breaks the chain
    return sha256_hex(canon({k: v for k, v in entry.items() if k != "entry_hash"}))

def pub_raw(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def kid_of(pub_bytes): return "ed25519:" + sha256_hex(pub_bytes)[:16]

def sign(entry, priv):
    sig = priv.sign(canon(body_of(entry)))
    entry.setdefault("signatures", []).append({"kid": kid_of(pub_raw(priv)), "alg": "Ed25519", "sig": b64u(sig)})

def make_entry(chain, seq, prev, ts, etype, author, content, signers):
    e = {"spec": SPEC, "chain_id": chain, "seq": seq, "prev_hash": prev, "ts": ts,
         "type": etype, "author": author, "content": content}
    for p in signers: sign(e, p)
    e["entry_hash"] = entry_hash(e)
    return e

def build_demo():
    # DEMO KEYS ONLY - deterministic seeds so the output is reproducible. Never use for real.
    a = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"demo-bot-A-guia").digest())
    b = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"demo-bot-B-quinta").digest())
    ka, kb = kid_of(pub_raw(a)), kid_of(pub_raw(b))
    agreement_text = ("Quinta Exemplo Bot (fictional) allows Guia Demo Bot to cite its harvest-visit "
                      "hours with attribution and the date checked. Valid 2026-11-11 to 2026-12-31. "
                      "No payment. Either party may end it with notice in this chain.")
    private_payloads = {  # NOT stored in the log; only hashes are.
        "proposal": "Raw message from A: may I cite your visit hours, with attribution?",
        "counter": "Raw message from B: yes, if you show the date you checked and stop after Dec 31.",
    }
    chain = "demo-" + sha256_hex(pub_raw(a) + pub_raw(b) + b"2026-11-11")[:12]
    log = []
    g = make_entry(chain, 0, GENESIS_PREV, "2026-11-11T22:00:00Z", "genesis", ka, {
        "purpose": "Record of an agreement between two fictional demo agents",
        "parties": [
            {"kid": ka, "name": "Guia Demo Bot (fictional)", "pubkey": b64u(pub_raw(a))},
            {"kid": kb, "name": "Quinta Exemplo Bot (fictional)", "pubkey": b64u(pub_raw(b))}],
        "privacy": "hashes-only for raw messages; summaries only with consent of both parties"}, [a, b])
    log.append(g)
    def add(ts, etype, author_priv, content, signers):
        prev = log[-1]
        log.append(make_entry(chain, prev["seq"] + 1, prev["entry_hash"], ts, etype,
                              kid_of(pub_raw(author_priv)), content, signers))
    add("2026-11-11T22:01:00Z", "proposal", a, {"payload_sha256": sha256_hex(private_payloads["proposal"].encode())}, [a])
    add("2026-11-11T22:02:00Z", "counter", b, {"payload_sha256": sha256_hex(private_payloads["counter"].encode())}, [b])
    add("2026-11-11T22:03:00Z", "agreement", a, {
        "summary": agreement_text, "summary_sha256": sha256_hex(agreement_text.encode()),
        "consent_to_publish_summary": True, "valid_from": "2026-11-11", "valid_until": "2026-12-31",
        "money": "none"}, [a, b])
    add("2026-11-11T22:04:00Z", "seal", b, {"entries": 4, "note": "chain closed by both parties"}, [a, b])
    return log, private_payloads

def verify(log, expected_head=None):
    errors = []
    if not log: return ["empty log"]
    g = log[0]
    if g.get("type") != "genesis" or g.get("seq") != 0 or g.get("prev_hash") != GENESIS_PREV:
        errors.append("entry 0 is not a valid genesis")
    keys = {}
    for p in g.get("content", {}).get("parties", []):
        raw = ub64u(p["pubkey"])
        if kid_of(raw) != p["kid"]: errors.append(f"genesis: kid {p['kid']} does not match its pubkey")
        keys[p["kid"]] = Ed25519PublicKey.from_public_bytes(raw)
    parties = set(keys)
    prev = None
    for i, e in enumerate(log):
        tag = f"entry {i} ({e.get('type')})"
        if e.get("spec") != SPEC: errors.append(f"{tag}: unknown spec")
        if e.get("chain_id") != g.get("chain_id"): errors.append(f"{tag}: chain_id mismatch (splice?)")
        if e.get("seq") != i: errors.append(f"{tag}: seq {e.get('seq')} != position {i} (deleted/reordered entry)")
        if i > 0 and e.get("prev_hash") != prev["entry_hash"]:
            errors.append(f"{tag}: prev_hash does not match hash of entry {i-1} (broken chain)")
        if entry_hash(e) != e.get("entry_hash"):
            errors.append(f"{tag}: entry_hash does not match content (entry was modified)")
        signed_by = set()
        msg = canon(body_of(e))
        for s in e.get("signatures", []):
            k = keys.get(s.get("kid"))
            if k is None or s.get("alg") != "Ed25519":
                errors.append(f"{tag}: signature by unknown key {s.get('kid')}"); continue
            try:
                k.verify(ub64u(s["sig"]), msg); signed_by.add(s["kid"])
            except InvalidSignature:
                errors.append(f"{tag}: INVALID signature by {s['kid']}")
        if e.get("author") not in signed_by: errors.append(f"{tag}: author did not sign")
        if e.get("type") in ("genesis", "agreement", "seal") and signed_by != parties:
            errors.append(f"{tag}: needs signatures of BOTH parties")
        c = e.get("content", {})
        if "summary" in c and sha256_hex(c["summary"].encode()) != c.get("summary_sha256"):
            errors.append(f"{tag}: summary text does not match summary_sha256")
        prev = e
    if log[-1].get("type") != "seal":
        errors.append("last entry is not a seal (log may be truncated)")
    elif log[-1].get("content", {}).get("entries") != len(log) - 1:
        errors.append("seal entry count does not match")
    if expected_head and log[-1].get("entry_hash") != expected_head:
        errors.append("head hash differs from the published/anchored head (truncation or fork)")
    return errors

def report(name, log, head=None, expect_ok=True):
    errs = verify(log, head)
    ok = not errs
    status = "PASS" if ok == expect_ok else "UNEXPECTED"
    print(f"[{status}] {name}: {'VERIFY OK' if ok else 'TAMPER DETECTED'}")
    for e in errs: print("      -", e)
    return ok == expect_ok

def demo():
    log, private = build_demo()
    os.makedirs(EXAMPLES, exist_ok=True)
    with open(os.path.join(EXAMPLES, "sample-log.json"), "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)
        f.write("\n")
    tampered = copy.deepcopy(log); tampered[3]["content"]["money"] = "EUR 500"
    with open(os.path.join(EXAMPLES, "sample-log-tampered.json"), "w", encoding="utf-8") as f:
        json.dump(tampered, f, indent=2, ensure_ascii=False)
        f.write("\n")
    head = log[-1]["entry_hash"]
    print(f"Spec {SPEC} - sample log with {len(log)} entries written to examples/sample-log.json")
    print(f"Head hash (what both agents would publish or anchor): {head}\n")
    results = [report("1. original log", log, head, True)]
    # privacy check: raw messages never stored
    raw_in_log = any(p in json.dumps(log, ensure_ascii=False) for p in private.values())
    print(f"[{'PASS' if not raw_in_log else 'UNEXPECTED'}] privacy: raw messages stored in log? {raw_in_log}")
    results.append(not raw_in_log)
    # proof a party can later reveal a raw message and anyone can check it against the hash
    match = sha256_hex(private["proposal"].encode()) == log[1]["content"]["payload_sha256"]
    print(f"[{'PASS' if match else 'UNEXPECTED'}] selective disclosure: revealed proposal matches its hash? {match}\n")
    results.append(match)

    t = copy.deepcopy(log); t[3]["content"]["valid_until"] = "2027-12-31"
    results.append(report("2. edit agreement date (no re-sign)", t, head, False))
    t = copy.deepcopy(log); t[3]["content"]["valid_until"] = "2027-12-31"; t[3]["entry_hash"] = entry_hash(t[3])
    results.append(report("3. edit date and recompute entry_hash", t, head, False))
    t = copy.deepcopy(log); del t[2]
    results.append(report("4. delete the counter-proposal", t, head, False))
    t = copy.deepcopy(log); t[1], t[2] = t[2], t[1]
    results.append(report("5. reorder entries", t, head, False))
    mallory = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"mallory").digest())
    t = copy.deepcopy(log); t[3]["content"]["money"] = "EUR 500"
    t[3]["signatures"] = []; sign(t[3], mallory); t[3]["entry_hash"] = entry_hash(t[3])
    results.append(report("6. rewrite agreement and sign with a third key", t, head, False))
    t = copy.deepcopy(log)[:4]
    results.append(report("7. truncate (drop seal)", t, None, False))
    t = copy.deepcopy(log); t[3]["signatures"] = t[3]["signatures"][:1]; t[3]["entry_hash"] = entry_hash(t[3])
    results.append(report("8. agreement with only one signature", t, None, False))
    t = copy.deepcopy(log); t[0]["content"]["purpose"] = "Something else"
    results.append(report("9. edit the genesis (parties/purpose)", t, None, False))
    print(f"\nSUMMARY: {sum(results)}/{len(results)} checks behaved as expected")
    return all(results)

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "verify":
        log = json.load(open(sys.argv[2], encoding="utf-8"))
        head = sys.argv[sys.argv.index("--head") + 1] if "--head" in sys.argv else None
        errs = verify(log, head)
        print("VERIFY OK" if not errs else "TAMPER DETECTED\n" + "\n".join(" - " + e for e in errs))
        sys.exit(0 if not errs else 1)
    sys.exit(0 if demo() else 1)
