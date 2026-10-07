"""A stand-in for `op inject`, so tests never touch a real vault.

Secrets come from fixtures.SECRETS. Every invocation's argv is appended to
FAKE_OP_LOG; the template it was given (references only, no values) goes to
FAKE_OP_STDIN when set. Bare `op://...` references and `{{ op://... }}` are
substituted in one pass over the template, so a resolved value is never
scanned again. FAKE_OP_TAMPER corrupts the output in the ways passh must refuse
to guess about.
"""

from __future__ import annotations

import json
import os
import re
import sys

from fixtures import SECRETS

REFERENCE = re.compile(rb"\{\{\s*(op://[^}]*?)\s*\}\}|(op://[^\s\"'{}]+)")


class Unresolved(Exception):
    pass


def inject(template: bytes, secrets: dict[str, str]) -> bytes:
    def resolve(ref: bytes) -> bytes:
        try:
            return secrets[ref.decode()].encode("utf-8", "surrogateescape")
        except KeyError:
            raise Unresolved(ref.decode()) from None

    return REFERENCE.sub(lambda m: resolve(m.group(1) or m.group(2)), template)


# How a failing op might look: a recognisable message, then — the worst case
# passh has to survive — resolved values in both stderr and stdout.
FAILURES = {
    "generic": (3, b"[ERROR] 2026/10/07 12:00:00 something unexpected: "),
    "signin": (
        1,
        (
            b"[ERROR] 2026/10/07 12:00:00 You are not currently signed in. "
            b"Please run `op signin --help` for instructions\n"
        ),
    ),
    "timeout": (
        1,
        (
            b"[ERROR] 2026/10/07 12:00:00 error initializing client: "
            b"authorization timeout\n"
        ),
    ),
}


def failure(
    kind: str, template: bytes, secrets: dict[str, str]
) -> tuple[int, bytes, bytes]:
    rc, message = FAILURES[kind]
    values = inject(template, secrets)
    return rc, values, message + values


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
    secrets = SECRETS
    template = sys.stdin.buffer.read()
    if os.environ.get("FAKE_OP_STDIN"):
        with open(os.environ["FAKE_OP_STDIN"], "wb") as fh:
            fh.write(template)
    if os.environ.get("FAKE_OP_FAIL"):
        rc, out, err = failure(os.environ["FAKE_OP_FAIL"], template, secrets)
        sys.stdout.buffer.write(out)
        sys.stderr.buffer.write(err)
        return rc
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
