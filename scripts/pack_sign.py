#!/usr/bin/env python3
"""ed25519 signing and verification for v2 detection packs.

Implements the signing protocol in docs/design/signed-feed.md -> "What gets
signed": the signature covers a canonical JSON serialisation of the pack with
metadata.signature.value cleared. The signature is stored in-band
(metadata.signature) and as a detached pack.yml.sig.

This is the trust primitive of the content feed: a customer's agent ships the
public key and refuses any pack whose signature does not verify.

Private keys are written with a .key extension and are gitignored. Only public
keys (.pub) and detached signatures (.sig) are safe to commit.

Subcommands:
    gen-key    generate an ed25519 keypair
    sign       sign a pack.yml in place + emit pack.yml.sig
    verify     verify a pack.yml against a public key

Demo (end to end):
    python3 scripts/pack_sign.py gen-key --key-id tinysocs-2026
    python3 scripts/pack_sign.py sign   packs/base/2026.23/pack.yml --key-id tinysocs-2026
    python3 scripts/pack_sign.py verify packs/base/2026.23/pack.yml --key-id tinysocs-2026
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_KEY_DIR = _REPO_ROOT / "keys"
_ALGORITHM = "ed25519"


def _rel(p: Path) -> str:
    """Repo-relative display path, robust to relative inputs."""
    try:
        return str(p.resolve().relative_to(_REPO_ROOT))
    except ValueError:
        return str(p)


# ---- canonicalisation -------------------------------------------------------

def canonical_bytes(pack: dict) -> bytes:
    """Deterministic signing input: pack as compact sorted-key JSON with the
    signature value cleared but algorithm + key_id retained (so they are signed).

    Must be byte-identical on signer and verifier. The pack is shipped as YAML
    but signed over its JSON projection -- YAML has too many equivalent
    encodings to canonicalise safely; JSON with sorted keys is one byte string.
    """
    clone = json.loads(json.dumps(pack))  # cheap deep copy via round-trip
    sig = clone.get("metadata", {}).get("signature")
    if sig is not None:
        sig["value"] = ""
    return json.dumps(
        clone, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# ---- key io -----------------------------------------------------------------

def _priv_path(key_dir: Path, key_id: str) -> Path:
    return key_dir / f"{key_id}.key"


def _pub_path(key_dir: Path, key_id: str) -> Path:
    return key_dir / f"{key_id}.pub"


def load_private(key_dir: Path, key_id: str) -> Ed25519PrivateKey:
    raw = base64.b64decode(_priv_path(key_dir, key_id).read_text(encoding="utf-8").strip())
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_public(key_dir: Path, key_id: str) -> Ed25519PublicKey:
    raw = base64.b64decode(_pub_path(key_dir, key_id).read_text(encoding="utf-8").strip())
    return Ed25519PublicKey.from_public_bytes(raw)


# ---- subcommands ------------------------------------------------------------

def cmd_gen_key(args) -> int:
    key_dir = Path(args.key_dir)
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path = _priv_path(key_dir, args.key_id)
    if priv_path.exists() and not args.force:
        print(f"refusing to overwrite existing {priv_path} (use --force)", file=sys.stderr)
        return 1

    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    priv_path.write_text(base64.b64encode(priv_raw).decode(), encoding="utf-8")
    priv_path.chmod(0o600)
    _pub_path(key_dir, args.key_id).write_text(base64.b64encode(pub_raw).decode(), encoding="utf-8")

    print(f"generated keypair {args.key_id!r}")
    print(f"  private: {priv_path}  (gitignored -- never commit)")
    print(f"  public:  {_pub_path(key_dir, args.key_id)}  (safe to ship/embed)")
    return 0


def cmd_sign(args) -> int:
    pack_path = Path(args.pack)
    pack = yaml.safe_load(pack_path.read_text(encoding="utf-8"))

    # Inject/refresh the signature block, then canonicalise with value cleared.
    pack.setdefault("metadata", {})["signature"] = {
        "algorithm": _ALGORITHM,
        "key_id": args.key_id,
        "value": "",
    }
    priv = load_private(Path(args.key_dir), args.key_id)
    sig = priv.sign(canonical_bytes(pack))
    sig_b64 = base64.b64encode(sig).decode()
    pack["metadata"]["signature"]["value"] = sig_b64

    pack_path.write_text(
        yaml.safe_dump(pack, sort_keys=False, default_flow_style=False, allow_unicode=True),
        encoding="utf-8",
    )
    (pack_path.parent / (pack_path.name + ".sig")).write_text(sig_b64, encoding="utf-8")

    print(f"signed {_rel(pack_path)} with {args.key_id!r}")
    print(f"  detached: {pack_path.name}.sig")
    return 0


def verify_pack(pack: dict, key_dir: Path, *, trusted_key_ids: set[str] | None = None) -> tuple[bool, str]:
    """Returns (ok, reason). Mirrors the agent-side verify in signed-feed.md."""
    sig_block = pack.get("metadata", {}).get("signature")
    if not sig_block or not sig_block.get("value"):
        return False, "no signature present"
    if sig_block.get("algorithm") != _ALGORITHM:
        return False, f"unexpected algorithm {sig_block.get('algorithm')!r}"
    key_id = sig_block.get("key_id")
    if trusted_key_ids is not None and key_id not in trusted_key_ids:
        return False, f"key_id {key_id!r} not trusted"
    try:
        pub = load_public(key_dir, key_id)
    except FileNotFoundError:
        return False, f"no public key for key_id {key_id!r}"
    try:
        pub.verify(base64.b64decode(sig_block["value"]), canonical_bytes(pack))
    except InvalidSignature:
        return False, "signature does not verify (tampered or wrong key)"
    return True, f"valid signature by {key_id!r}"


def cmd_verify(args) -> int:
    pack_path = Path(args.pack)
    pack = yaml.safe_load(pack_path.read_text(encoding="utf-8"))
    trusted = {args.key_id} if args.key_id else None
    ok, reason = verify_pack(pack, Path(args.key_dir), trusted_key_ids=trusted)
    status = "OK" if ok else "FAIL"
    print(f"[{status}] {_rel(pack_path)}: {reason}")
    return 0 if ok else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-key", help="generate an ed25519 keypair")
    g.add_argument("--key-id", required=True)
    g.add_argument("--key-dir", default=str(_DEFAULT_KEY_DIR))
    g.add_argument("--force", action="store_true")
    g.set_defaults(func=cmd_gen_key)

    s = sub.add_parser("sign", help="sign a pack in place + emit .sig")
    s.add_argument("pack")
    s.add_argument("--key-id", required=True)
    s.add_argument("--key-dir", default=str(_DEFAULT_KEY_DIR))
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="verify a pack against a public key")
    v.add_argument("pack")
    v.add_argument("--key-id", default=None, help="restrict to this trusted key_id")
    v.add_argument("--key-dir", default=str(_DEFAULT_KEY_DIR))
    v.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
