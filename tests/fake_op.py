"""A stand-in for `op inject`, so tests never touch a real vault.

Secrets come from the JSON file named by FAKE_OP_SECRETS and every invocation's
argv is appended to FAKE_OP_LOG; the template it was given goes to
FAKE_OP_STDIN when set. Both bare `op://...` references and `{{ op://... }}`
are substituted, as `op inject` does. FAKE_OP_TAMPER corrupts the output in
the ways passh must refuse to guess about.
"""

from __future__ import annotations

import json
import os
import re
import sys

ENCLOSED = re.compile(rb"\{\{\s*(op://[^}]*?)\s*\}\}")
BARE = re.compile(rb"op://[^\s\"'{}]+")


class Unresolved(Exception):
    pass


def inject(template: bytes, secrets: dict[str, str]) -> bytes:
    def resolve(ref: bytes) -> bytes:
        try:
            return secrets[ref.decode()].encode("utf-8", "surrogateescape")
        except KeyError:
            raise Unresolved(ref.decode()) from None

    out = ENCLOSED.sub(lambda m: resolve(m.group(1)), template)
    return BARE.sub(lambda m: resolve(m.group(0)), out)


def tamper(mode: str, template: bytes, out: bytes) -> bytes:
    first_marker = template.split(b"\n", 1)[0]
    if mode == "truncate":
        return out[:-12]
    if mode == "prefix":
        return b"stray\n" + out
    if mode == "suffix":
        return out + b"stray"
    if mode == "collide":
        # A value that happens to contain a marker line.
        return out.replace(b"\n", b"\n" + first_marker + b"\n", 2)
    if mode == "repeat":
        return out + out
    raise SystemExit(f"fake op: unknown FAKE_OP_TAMPER {mode!r}")


def main() -> int:
    log = os.environ.get("FAKE_OP_LOG")
    if log:
        with open(log, "a") as fh:
            fh.write(json.dumps(sys.argv[1:]) + "\n")
    if not sys.argv[1:] or sys.argv[1] != "inject":
        print("fake op: only 'inject' is supported", file=sys.stderr)
        return 2
    with open(os.environ["FAKE_OP_SECRETS"]) as fh:
        secrets = json.load(fh)
    template = sys.stdin.buffer.read()
    if os.environ.get("FAKE_OP_STDIN"):
        with open(os.environ["FAKE_OP_STDIN"], "wb") as fh:
            fh.write(template)
    if os.environ.get("FAKE_OP_FAIL"):
        # Partial output plus an error, the way a failing resolver might.
        sys.stdout.buffer.write(inject(template, secrets))
        print("[ERROR] simulated failure", file=sys.stderr)
        return 1
    try:
        out = inject(template, secrets)
    except Unresolved as exc:
        print(f'[ERROR] could not resolve "{exc}"', file=sys.stderr)
        return 1
    mode = os.environ.get("FAKE_OP_TAMPER")
    sys.stdout.buffer.write(tamper(mode, template, out) if mode else out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
