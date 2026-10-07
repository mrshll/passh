"""`passh run` must hand every resolved value to the child byte for byte.

All secrets are synthetic (fixtures.py) and stay in memory: the child compares
them itself and reports only booleans and lengths, and every assertion here is
on a precomputed boolean, so no failure can print a value.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import stat
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import fake_op
from fixtures import SECRETS

ROOT = Path(__file__).resolve().parent.parent
PASSH = ROOT / "passh"
ENV_CHECK = Path(__file__).parent / "env_check.py"

Part = tuple[str, str]


def ref(name: str) -> Part:
    return ("ref", name)


def lit(text: str) -> Part:
    return ("lit", text)


def check(ok: bool, message: str) -> None:
    """assert, with a message that must not contain a value."""
    assert ok, message


class Harness:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.log = tmp / "op.log"
        self.sent = tmp / "op-stdin"
        self.op = tmp / "op"
        self.op.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{Path(fake_op.__file__)}" "$@"\n'
        )
        self.op.chmod(self.op.stat().st_mode | stat.S_IXUSR)
        self.report = tmp / "report.json"
        self.env = {
            "PATH": os.environ["PATH"],
            "HOME": str(tmp),
            "PASSH_MODE": "local",
            "PASSH_OP": str(self.op),
            "FAKE_OP_LOG": str(self.log),
            "FAKE_OP_STDIN": str(self.sent),
        }

    def run(
        self,
        template: str,
        *flags: str,
        expect: dict[str, Part | list[Part]] | None = None,
        absent: tuple[str, ...] = (),
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        path = self.tmp / "template.env"
        path.write_text(template)
        if self.report.exists():
            self.report.unlink()
        self.expect = {
            k: [v] if isinstance(v, tuple) else v for k, v in (expect or {}).items()
        }
        spec = json.dumps({"expect": self.expect, "absent": list(absent)})
        return subprocess.run(
            [
                sys.executable,
                str(PASSH),
                "run",
                f"--env-file={path}",
                *flags,
                "--",
                sys.executable,
                str(ENV_CHECK),
                str(self.report),
                spec,
            ],
            env={**self.env, **(env or {})},
            capture_output=True,
            check=False,
            timeout=60,
        )

    def ok(
        self,
        template: str,
        *flags: str,
        expect: dict[str, Part | list[Part]] | None = None,
        absent: tuple[str, ...] = (),
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        """Run, and require that the child saw exactly what was expected."""
        proc = self.run(template, *flags, expect=expect, absent=absent, env=env)
        check(
            proc.returncode == 0,
            f"rc={proc.returncode} stderr_len={len(proc.stderr)}",
        )
        report = json.loads(self.report.read_text())
        for key, r in report["expect"].items():
            check(
                r["equal"],
                f"{key}: present={r['present']} len={r['len']} "
                f"want_len={r['want_len']} lines={r['lines']} "
                f"want_lines={r['want_lines']}",
            )
        for key, present in report["absent"].items():
            check(not present, f"{key} should not be set")
        return proc

    def refused(self, template: str, env: dict[str, str] | None = None) -> bytes:
        """Run, and require that it failed without starting the child."""
        proc = self.run(template, env=env)
        check(proc.returncode != 0, "expected a failure")
        check(not self.report.exists(), "the child ran anyway")
        check(not leaked(proc), "a secret appeared in passh's output")
        return proc.stderr

    def op_calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]


def leaked(proc: subprocess.CompletedProcess) -> bool:
    for value in SECRETS.values():
        for line in value.splitlines():
            needle = line.strip().encode("utf-8", "surrogateescape")
            if len(needle) >= 6 and (needle in proc.stderr or needle in proc.stdout):
                return True
    return False


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


# --- multiline -------------------------------------------------------------


@pytest.mark.parametrize("quote", ["", '"', "'"])
def test_multiline_pem_reaches_child_intact(h: Harness, quote: str) -> None:
    h.ok(f"PEM={quote}op://v/i/pem{quote}\n", expect={"PEM": ref("op://v/i/pem")})


def test_multiline_without_trailing_newline(h: Harness) -> None:
    h.ok(
        "PEM=op://v/i/pem-no-newline\n",
        expect={"PEM": ref("op://v/i/pem-no-newline")},
    )


def test_reference_with_space_in_field_name(h: Harness) -> None:
    h.ok('PEM="op://v/i/private key"\n', expect={"PEM": ref("op://v/i/private key")})


@pytest.mark.parametrize("quote", ["", '"', "'"])
def test_whole_value_references_with_spaces(h: Harness, quote: str) -> None:
    # The shapes dot's agent-gh and warren's secrets.env use.
    h.ok(
        f"GH_TOKEN={quote}op://Private/Github agent/Token{quote}\n"
        f"API={quote}op://v/Some Item/API Key{quote}  # comment\n",
        expect={
            "GH_TOKEN": ref("op://Private/Github agent/Token"),
            "API": ref("op://v/Some Item/API Key"),
        },
    )


def test_newline_edge_cases_are_byte_exact(h: Harness) -> None:
    h.ok(
        "E=op://v/i/edges\nZ=op://v/i/empty\n",
        expect={"E": ref("op://v/i/edges"), "Z": ref("op://v/i/empty")},
    )


def test_keys_after_a_multiline_value_still_set(h: Harness) -> None:
    h.ok(
        "PEM=op://v/i/pem\nAFTER=op://v/i/plain\n",
        expect={"PEM": ref("op://v/i/pem"), "AFTER": ref("op://v/i/plain")},
    )


def test_value_lines_are_never_parsed_as_assignments(h: Harness) -> None:
    h.ok(
        "S=op://v/i/smuggle\n",
        expect={"S": ref("op://v/i/smuggle")},
        absent=("SMUGGLED",),
    )


def test_blank_lines_inside_a_value_survive(h: Harness) -> None:
    h.ok("B=op://v/i/blank-lines\n", expect={"B": ref("op://v/i/blank-lines")})


def test_trailing_newline_of_a_value_is_kept(h: Harness) -> None:
    h.ok("T=op://v/i/trailing\n", expect={"T": ref("op://v/i/trailing")})


def test_resolved_value_is_never_resolved_again(h: Harness) -> None:
    h.ok(
        "A=op://v/i/looks-like-refs\n",
        expect={"A": ref("op://v/i/looks-like-refs")},
    )


# --- quoting ---------------------------------------------------------------


@pytest.mark.parametrize("quote", ['"', "'"])
def test_quotes_around_reference_are_removed(h: Harness, quote: str) -> None:
    h.ok(f"A={quote}op://v/i/plain{quote}\n", expect={"A": ref("op://v/i/plain")})


@pytest.mark.parametrize("name", ["quoted", "wrapped-dq", "wrapped-sq", "backslash"])
def test_quotes_and_backslashes_inside_a_secret_are_kept(h: Harness, name: str) -> None:
    r = ref(f"op://v/i/{name}")
    h.ok(f'A="op://v/i/{name}"\nB=op://v/i/{name}\n', expect={"A": r, "B": r})


def test_secret_is_never_shell_expanded(h: Harness) -> None:
    h.ok('A="op://v/i/shell"\n', expect={"A": ref("op://v/i/shell")})
    check(not (h.tmp / "pwned").exists(), "a command in a secret ran")


def test_literal_double_quoted_escapes(h: Harness) -> None:
    h.ok(
        'E="one\\ntwo\\tthree \\"q\\" back\\\\slash \\$ \\x"\n',
        expect={"E": lit('one\ntwo\tthree "q" back\\slash \\$ \\x')},
    )


def test_literal_single_quotes_are_raw(h: Harness) -> None:
    h.ok(
        "R='no \\n escapes, \"dq\" kept'\n",
        expect={"R": lit('no \\n escapes, "dq" kept')},
    )


def test_quoted_literal_may_span_lines(h: Harness) -> None:
    h.ok(
        "M=\"line one\nline two\"\nN='a\nb'\nAFTER=x\n",
        expect={"M": lit("line one\nline two"), "N": lit("a\nb"), "AFTER": lit("x")},
    )


def test_reference_embedded_in_quoted_literal(h: Harness) -> None:
    h.ok(
        'URL="postgres://u:{{ op://v/i/plain }}@db/x"\n'
        "TWO=a{{op://v/i/plain}}b{{ op://v/i/equals }}c\n",
        expect={
            "URL": [lit("postgres://u:"), ref("op://v/i/plain"), lit("@db/x")],
            "TWO": [
                lit("a"),
                ref("op://v/i/plain"),
                lit("b"),
                ref("op://v/i/equals"),
                lit("c"),
            ],
        },
    )


def test_no_interpolation_of_literal_text(h: Harness) -> None:
    h.ok(
        "A=\"$HOME ${HOME}\"\nB=$HOME\nC='${X:-d} {{ not a ref }}'\n",
        expect={
            "A": lit("$HOME ${HOME}"),
            "B": lit("$HOME"),
            "C": lit("${X:-d} {{ not a ref }}"),
        },
    )


def test_literal_text_never_reaches_op(h: Harness) -> None:
    # op inject expands $VARS in its template, so literals must not go there.
    h.ok(
        'URL="LITERAL_CANARY_1 $HOME {{ op://v/i/plain }} LITERAL_CANARY_2"\n'
        "L=LITERAL_CANARY_3\n",
        expect={
            "URL": [
                lit("LITERAL_CANARY_1 $HOME "),
                ref("op://v/i/plain"),
                lit(" LITERAL_CANARY_2"),
            ]
        },
    )
    sent = h.sent.read_bytes()
    check(b"LITERAL_CANARY" not in sent, "literal text was sent to op")
    check(b"$HOME" not in sent, "literal text was sent to op")


def test_repeated_reference_resolved_once(h: Harness) -> None:
    r = ref("op://v/i/plain")
    h.ok("A=op://v/i/plain\nB=op://v/i/plain\n", expect={"A": r, "B": r})
    check(h.sent.read_bytes().count(b"op://v/i/plain") == 1, "resolved twice")


def test_no_references_means_no_op_call(h: Harness) -> None:
    h.ok("A=plain\n# only a comment\n", expect={"A": lit("plain")})
    check(h.op_calls() == [], "op was called")


def test_empty_env_file_runs_child(h: Harness) -> None:
    h.ok("")
    check(h.op_calls() == [], "op was called")


def test_lookalike_scheme_is_literal(h: Harness) -> None:
    h.ok("A=shop://example\n", expect={"A": lit("shop://example")})


# --- equals, comments, blank lines, layout ---------------------------------


def test_equals_inside_values(h: Harness) -> None:
    h.ok(
        "A=op://v/i/equals\nB=x=y=z\nC='k=v'\n",
        expect={"A": ref("op://v/i/equals"), "B": lit("x=y=z"), "C": lit("k=v")},
    )


def test_comments_and_blank_lines(h: Harness) -> None:
    template = (
        "# a comment\n"
        "\n"
        "   \n"
        "  # indented comment\n"
        "# DISABLED=op://v/i/does-not-exist\n"
        "A=op://v/i/plain # trailing comment\n"
        'B="op://v/i/plain" # trailing comment\n'
        "C=op://v/i/hash\n"
        "D=value#not-a-comment\n"
        "E= # only a comment\n"
        "F=#leading-hash\n"
        "G='#quoted hash' # comment\n"
    )
    h.ok(
        template,
        expect={
            "A": ref("op://v/i/plain"),
            "B": ref("op://v/i/plain"),
            "C": ref("op://v/i/hash"),
            "D": lit("value#not-a-comment"),
            "E": lit(""),
            "F": lit("#leading-hash"),
            "G": lit("#quoted hash"),
        },
        absent=("DISABLED",),
    )


def test_template_without_final_newline(h: Harness) -> None:
    h.ok("A=op://v/i/plain", expect={"A": ref("op://v/i/plain")})


def test_crlf_template(h: Harness) -> None:
    h.ok(
        'A=op://v/i/plain\r\nB="x"\r\n',
        expect={"A": ref("op://v/i/plain"), "B": lit("x")},
    )


def test_export_prefix_and_whitespace(h: Harness) -> None:
    h.ok(
        "export A=op://v/i/plain\n  B = spaced  \nC=\n",
        expect={"A": ref("op://v/i/plain"), "B": lit("spaced"), "C": lit("")},
    )


def test_duplicate_key_last_wins(h: Harness) -> None:
    h.ok("A=first\nA=op://v/i/plain\n", expect={"A": ref("op://v/i/plain")})


def test_existing_environment_is_inherited(h: Harness) -> None:
    h.ok(
        "A=op://v/i/plain\n",
        expect={"KEEP_ME": lit("kept")},
        env={"KEEP_ME": "kept"},
    )


def test_non_utf8_bytes_survive(h: Harness) -> None:
    h.ok("Y=op://v/i/bytes\n", expect={"Y": ref("op://v/i/bytes")})


# --- errors never carry a value --------------------------------------------


@pytest.mark.parametrize(
    "template,key",
    [
        ('OPEN="op://v/i/plain\nOTHER=x\n', "OPEN"),
        ("OPEN='never closed\n", "OPEN"),
        ('TAIL="x" junk\n', "TAIL"),
        ("URL=postgres://u:op://v/i/plain@db\n", "URL"),
        ("INJ=op://v/i/plain }} LITERAL_CANARY\n", "INJ"),
        ("INJ=op://v/i/plain {{ op://v/i/equals }}\n", "INJ"),
        ('CTRL="op://v/i/pl\tain"\n', "CTRL"),
        ('MULTI="op://v/i/plain\nmore"\n', "MULTI"),
        ("PRE=prefix-op://v/i/plain\n", "PRE"),
        ("PRE=x.op://v/i/plain\n", "PRE"),
        ("PRE=a+op://v/i/plain\n", "PRE"),
        ("PRE=a_op://v/i/plain\n", "PRE"),
        ("NUL=a\x00b\nTOKEN=op://v/i/plain\n", "NUL"),
    ],
)
def test_malformed_values_fail_naming_the_key(
    h: Harness, template: str, key: str
) -> None:
    stderr = h.refused(template)
    check(key.encode() in stderr, "the error does not name the key")
    check(b"LITERAL_CANARY" not in stderr, "the error quotes the value")
    check(h.op_calls() == [], "op was called for a template that does not parse")


@pytest.mark.parametrize(
    "line", ["no equals sign here", "=novalue", "BAD KEY=x", "1X=y", "A-B=x"]
)
def test_malformed_lines_fail_naming_the_line(h: Harness, line: str) -> None:
    stderr = h.refused(f"A=ok\n{line}\n")
    check(b"line 2" in stderr, "the error does not name the line")
    check(line.encode() not in stderr, "the error quotes the line")


@pytest.mark.parametrize("mode", ["truncate", "prefix", "suffix", "collide", "repeat"])
def test_unexpected_op_output_fails_closed(h: Harness, mode: str) -> None:
    stderr = h.refused(
        "PEM=op://v/i/pem\nA=op://v/i/plain\nB=op://v/i/equals\n",
        env={"FAKE_OP_TAMPER": mode},
    )
    check(b"could not map" in stderr, "unexpected error message")


SIGNIN_HINT = b"looks like op is not signed in"
TIMEOUT_HINT = b"looks like 1Password was not unlocked in time"


def check_op_failure(proc: subprocess.CompletedProcess, h: Harness, kind: str) -> None:
    """op failed with values in its stderr and stdout; none may get out."""
    rc = fake_op.FAILURES[kind][0]
    check(proc.returncode == rc, f"rc={proc.returncode}, want {rc}")
    check(not h.report.exists(), "the child ran anyway")
    check(not leaked(proc), "a secret from op's output appeared in passh's output")
    check(b"op inject" not in proc.stdout, "diagnostics belong on stderr")
    check(f"op inject failed (exit {rc})".encode() in proc.stderr, "no fixed message")
    check(b"[ERROR]" not in proc.stderr, "op's raw stderr was forwarded")
    check((SIGNIN_HINT in proc.stderr) == (kind == "signin"), "sign-in hint wrong")
    check((TIMEOUT_HINT in proc.stderr) == (kind == "timeout"), "timeout hint wrong")


FAILING = "PEM=op://v/i/pem\nA=op://v/i/plain\nB=op://v/i/smuggle\n"


@pytest.mark.parametrize("kind", list(fake_op.FAILURES))
def test_op_failure_output_is_suppressed_locally(h: Harness, kind: str) -> None:
    proc = h.run(FAILING, env={"FAKE_OP_FAIL": kind})
    check_op_failure(proc, h, kind)


@pytest.mark.parametrize("kind", list(fake_op.FAILURES))
def test_op_failure_output_is_suppressed_in_fallback(h: Harness, kind: str) -> None:
    port = free_port()
    token = h.tmp / "token"
    token.write_text("unused")
    proc = h.run(
        FAILING,
        env={
            "FAKE_OP_FAIL": kind,
            "PASSH_MODE": "remote",
            "PASSH_PORT": str(port),
            "PASSH_TOKEN_FILE": str(token),
        },
    )
    check(b"Falling back" in proc.stderr, "no fallback notice")
    check_op_failure(proc, h, kind)


@pytest.mark.parametrize("kind", list(fake_op.FAILURES))
def test_op_failure_output_is_suppressed_over_the_tunnel(h: Harness, kind: str) -> None:
    FakePasshd.calls = []
    FakePasshd.fail = kind
    server = HTTPServer(("127.0.0.1", 0), FakePasshd)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    token = h.tmp / "token"
    token.write_text(FakePasshd.token)
    try:
        proc = h.run(
            FAILING,
            env={
                "PASSH_MODE": "remote",
                "PASSH_PORT": str(server.server_port),
                "PASSH_TOKEN_FILE": str(token),
            },
        )
    finally:
        server.shutdown()
        FakePasshd.fail = ""
    check(len(FakePasshd.calls) == 1, "passhd was not called once")
    check(h.op_calls() == [], "local op ran although the tunnel was up")
    check_op_failure(proc, h, kind)


def test_unresolved_reference_fails_without_running_child(h: Harness) -> None:
    h.refused("A=op://v/i/plain\nB=op://v/i/missing\n")


def test_nul_in_value_fails_naming_key(h: Harness) -> None:
    stderr = h.refused("Z=op://v/i/nul\n")
    check(b"Z:" in stderr, "the error does not name the key")


def test_no_value_leaks_on_success_output(h: Harness) -> None:
    names = [r for r in SECRETS if r != "op://v/i/nul"]
    template = "".join(f"K{i}={r}\n" for i, r in enumerate(names))
    proc = h.ok(template, expect={f"K{i}": ref(r) for i, r in enumerate(names)})
    check(not leaked(proc), "a secret appeared in passh's output")


# --- CLI contract ----------------------------------------------------------


def test_one_inject_call_with_account_passed_through(h: Harness) -> None:
    h.ok(
        "A=op://v/i/plain\nB=op://v/i/pem\n",
        "--account",
        "upstreamtech",
        expect={"A": ref("op://v/i/plain"), "B": ref("op://v/i/pem")},
    )
    check(h.op_calls() == [["inject", "--account", "upstreamtech"]], "op argv")


def test_account_equals_form_and_no_masking(h: Harness) -> None:
    h.ok(
        "A=op://v/i/plain\n",
        "--account=upstreamtech",
        "--no-masking",
        expect={"A": ref("op://v/i/plain")},
    )
    check(h.op_calls() == [["inject", "--account=upstreamtech"]], "op argv")


def test_child_exit_code_is_propagated(h: Harness) -> None:
    path = h.tmp / "t.env"
    path.write_text("A=op://v/i/plain\n")
    proc = subprocess.run(
        [
            sys.executable,
            str(PASSH),
            "run",
            f"--env-file={path}",
            "--",
            sys.executable,
            "-c",
            "import os, sys; sys.exit(7 if os.environ['A'] == 's3cr3t' else 1)",
        ],
        env=h.env,
        capture_output=True,
        check=False,
        timeout=60,
    )
    check(proc.returncode == 7, f"rc={proc.returncode}")


# --- the tunnel and the fallback take the same path ------------------------


class FakePasshd(BaseHTTPRequestHandler):
    token = "test-token"
    fail = ""
    calls: ClassVar[list[list[str]]] = []

    def log_message(self, fmt: str, *args: object) -> None:
        pass

    def do_POST(self) -> None:
        authorised = self.headers["Authorization"] == f"Bearer {self.token}"
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakePasshd.calls.append(req["args"])
        stdin = base64.b64decode(req["stdin"] or "")
        try:
            if self.fail == "malformed":
                # An unreadable reply that quotes a resolved value.
                rc, out, err = fake_op.inject(stdin, SECRETS).decode(), b"", b""
            elif self.fail:
                rc, out, err = fake_op.failure(self.fail, stdin, SECRETS)
            else:
                rc, out, err = 0, fake_op.inject(stdin, SECRETS), b""
        except fake_op.Unresolved as exc:
            rc, out, err = 1, b"", f"[ERROR] could not resolve {exc}\n".encode()
        body = json.dumps(
            {
                "rc": rc,
                "stdout": base64.b64encode(out).decode(),
                "stderr": base64.b64encode(err).decode(),
            }
        ).encode()
        self.send_response(200 if authorised else 401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_tunnel_path(h: Harness) -> None:
    FakePasshd.calls = []
    server = HTTPServer(("127.0.0.1", 0), FakePasshd)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    token = h.tmp / "token"
    token.write_text(FakePasshd.token)
    try:
        h.ok(
            "PEM=\"op://v/i/pem\"\nA='op://v/i/plain'\n",
            "--account",
            "upstreamtech",
            expect={"PEM": ref("op://v/i/pem"), "A": ref("op://v/i/plain")},
            env={
                "PASSH_MODE": "remote",
                "PASSH_PORT": str(server.server_port),
                "PASSH_TOKEN_FILE": str(token),
            },
        )
    finally:
        server.shutdown()
    check(FakePasshd.calls == [["inject", "--account", "upstreamtech"]], "argv")
    check(h.op_calls() == [], "the tunnel was up, so local op must not run")


def test_fallback_path_when_tunnel_is_down(h: Harness) -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    token = h.tmp / "token"
    token.write_text("unused")
    proc = h.ok(
        'PEM="op://v/i/pem"\n',
        expect={"PEM": ref("op://v/i/pem")},
        env={
            "PASSH_MODE": "remote",
            "PASSH_PORT": str(port),
            "PASSH_TOKEN_FILE": str(token),
        },
    )
    check(b"Falling back" in proc.stderr, "no fallback notice")
    check(h.op_calls() == [["inject"]], "op argv")


def test_malformed_passhd_reply_is_not_quoted(h: Harness) -> None:
    FakePasshd.fail = "malformed"
    server = HTTPServer(("127.0.0.1", 0), FakePasshd)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    token = h.tmp / "token"
    token.write_text(FakePasshd.token)
    try:
        h.refused(
            FAILING,
            env={
                "PASSH_MODE": "remote",
                "PASSH_PORT": str(server.server_port),
                "PASSH_TOKEN_FILE": str(token),
            },
        )
    finally:
        server.shutdown()
        FakePasshd.fail = ""


def test_launch_failure_does_not_quote_a_resolved_path(h: Harness) -> None:
    # execvpe searches the resolved PATH, and its error names what it tried.
    path = h.tmp / "t.env"
    path.write_text("PATH=op://v/i/path\n")
    proc = subprocess.run(
        [
            sys.executable,
            str(PASSH),
            "run",
            f"--env-file={path}",
            "--",
            "passh-test-no-such-command",
        ],
        env=h.env,
        capture_output=True,
        check=False,
        timeout=60,
    )
    check(proc.returncode == 127, f"rc={proc.returncode}")
    check(not leaked(proc), "the resolved PATH appeared in passh's output")
    check(b"passh-test-no-such-command" in proc.stderr, "command not named")


def test_no_fallback_when_disabled(h: Harness) -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    token = h.tmp / "token"
    token.write_text("unused")
    h.refused(
        'PEM="op://v/i/pem"\n',
        env={
            "PASSH_MODE": "remote",
            "PASSH_PORT": str(port),
            "PASSH_TOKEN_FILE": str(token),
            "PASSH_NO_FALLBACK": "1",
        },
    )
    check(h.op_calls() == [], "local op ran despite PASSH_NO_FALLBACK")
