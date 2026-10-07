"""`passh run` must hand every resolved value to the child byte for byte.

All secrets here are synthetic. Even so, assertions compare values without
letting pytest print them: a failure names the key and reports lengths, the
same discipline the real thing needs.
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

ROOT = Path(__file__).resolve().parent.parent
PASSH = ROOT / "passh"
ENV_DUMP = Path(__file__).parent / "env_dump.py"

PEM = (
    "-----BEGIN FAKE PRIVATE KEY-----\n"
    "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC\n"
    "Q0NDQ0NDQ0NDQ0NDQ0Nq==\n"
    "-----END FAKE PRIVATE KEY-----\n"
)

SECRETS = {
    "op://v/i/pem": PEM,
    "op://v/i/pem-no-newline": PEM.rstrip("\n"),
    "op://v/i/private key": PEM,
    "op://v/i/plain": "s3cr3t",
    "op://v/i/equals": "a=b==c",
    "op://v/i/quoted": "\"double\" and 'single'",
    "op://v/i/wrapped-dq": '"whole value in double quotes"',
    "op://v/i/wrapped-sq": "'whole value in single quotes'",
    "op://v/i/shell": "$(touch pwned) `id` $HOME ${PATH}",
    "op://v/i/smuggle": "first\nSMUGGLED=from-the-secret\nlast",
    "op://v/i/trailing": "ends with newline\n",
    "op://v/i/hash": "a # not a comment",
    "op://v/i/backslash": "C:\\path\\n\\t",
    "op://v/i/blank-lines": "\n\nmiddle\n\n",
    "op://v/i/edges": "  leading spaces\r\nCRLF line\rlone CR\n\n\n",
    "op://Private/Github agent/Token": "gh-synthetic",
    "op://v/Some Item/API Key": "api-synthetic",
    "op://v/i/empty": "",
}


def same(key: str, got: dict[str, str], want: str) -> None:
    """Assert got[key] == want without putting either value in the report."""
    present = key in got
    value = got.get(key, "")
    ok = present and value == want
    assert ok, (
        f"{key}: present={present} len={len(value)} want_len={len(want)} "
        f"lines={value.count(chr(10))} want_lines={want.count(chr(10))}"
    )


class Harness:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.secrets = tmp / "secrets.json"
        self.secrets.write_text(json.dumps(SECRETS))
        self.log = tmp / "op.log"
        self.op = tmp / "op"
        self.op.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{Path(fake_op.__file__)}" "$@"\n'
        )
        self.op.chmod(self.op.stat().st_mode | stat.S_IXUSR)
        self.out = tmp / "child-env.json"
        self.env = {
            "PATH": os.environ["PATH"],
            "HOME": str(tmp),
            "PASSH_MODE": "local",
            "PASSH_OP": str(self.op),
            "FAKE_OP_SECRETS": str(self.secrets),
            "FAKE_OP_LOG": str(self.log),
        }

    def run(
        self, template: str | bytes, *flags: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess:
        path = self.tmp / "template.env"
        path.write_bytes(template if isinstance(template, bytes) else template.encode())
        if self.out.exists():
            self.out.unlink()
        return subprocess.run(
            [
                sys.executable,
                str(PASSH),
                "run",
                f"--env-file={path}",
                *flags,
                "--",
                sys.executable,
                str(ENV_DUMP),
                str(self.out),
            ],
            env={**self.env, **(env or {})},
            capture_output=True,
            check=False,
            timeout=60,
        )

    def child_env(self, proc: subprocess.CompletedProcess) -> dict[str, str]:
        # Only rc and stderr length: stderr must never carry a value anyway.
        assert proc.returncode == 0, (
            f"rc={proc.returncode} stderr_len={len(proc.stderr)}"
        )
        return json.loads(self.out.read_text())

    def op_calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def assert_no_secret_leak(proc: subprocess.CompletedProcess) -> None:
    for ref, value in SECRETS.items():
        for line in value.splitlines():
            if len(line.strip()) >= 6:
                leaked = line.encode() in proc.stderr or line.encode() in proc.stdout
                assert not leaked, (
                    f"{ref}: a line of its value appeared in passh's output"
                )


# --- multiline -------------------------------------------------------------


@pytest.mark.parametrize("quote", ["", '"', "'"])
def test_multiline_pem_reaches_child_intact(h: Harness, quote: str) -> None:
    got = h.child_env(h.run(f"PEM={quote}op://v/i/pem{quote}\n"))
    same("PEM", got, PEM)


def test_multiline_without_trailing_newline(h: Harness) -> None:
    got = h.child_env(h.run("PEM=op://v/i/pem-no-newline\n"))
    same("PEM", got, PEM.rstrip("\n"))


def test_reference_with_space_in_field_name(h: Harness) -> None:
    got = h.child_env(h.run('PEM="op://v/i/private key"\n'))
    same("PEM", got, PEM)


@pytest.mark.parametrize("quote", ["", '"', "'"])
def test_whole_value_references_with_spaces(h: Harness, quote: str) -> None:
    # The shapes dot's agent-gh and warren's secrets.env use.
    template = (
        f"GH_TOKEN={quote}op://Private/Github agent/Token{quote}\n"
        f"API={quote}op://v/Some Item/API Key{quote}\n"
    )
    got = h.child_env(h.run(template))
    same("GH_TOKEN", got, "gh-synthetic")
    same("API", got, "api-synthetic")


def test_newline_edge_cases_are_byte_exact(h: Harness) -> None:
    got = h.child_env(h.run("E=op://v/i/edges\nZ=op://v/i/empty\n"))
    same("E", got, SECRETS["op://v/i/edges"])
    same("Z", got, "")


def test_keys_after_a_multiline_value_still_set(h: Harness) -> None:
    got = h.child_env(h.run("PEM=op://v/i/pem\nAFTER=op://v/i/plain\n"))
    same("PEM", got, PEM)
    same("AFTER", got, "s3cr3t")


def test_value_lines_are_never_parsed_as_assignments(h: Harness) -> None:
    got = h.child_env(h.run("S=op://v/i/smuggle\n"))
    same("S", got, SECRETS["op://v/i/smuggle"])
    assert "SMUGGLED" not in got


def test_blank_lines_inside_a_value_survive(h: Harness) -> None:
    got = h.child_env(h.run("B=op://v/i/blank-lines\n"))
    same("B", got, SECRETS["op://v/i/blank-lines"])


def test_trailing_newline_of_a_value_is_kept(h: Harness) -> None:
    got = h.child_env(h.run("T=op://v/i/trailing\n"))
    same("T", got, "ends with newline\n")


# --- quoting ---------------------------------------------------------------


def test_double_quotes_around_reference_are_removed(h: Harness) -> None:
    got = h.child_env(h.run('A="op://v/i/plain"\n'))
    same("A", got, "s3cr3t")


def test_single_quotes_around_reference_are_removed(h: Harness) -> None:
    got = h.child_env(h.run("A='op://v/i/plain'\n"))
    same("A", got, "s3cr3t")


@pytest.mark.parametrize("ref", ["quoted", "wrapped-dq", "wrapped-sq", "backslash"])
def test_quotes_and_backslashes_inside_a_secret_are_kept(h: Harness, ref: str) -> None:
    got = h.child_env(h.run(f'A="op://v/i/{ref}"\nB=op://v/i/{ref}\n'))
    same("A", got, SECRETS[f"op://v/i/{ref}"])
    same("B", got, SECRETS[f"op://v/i/{ref}"])


def test_secret_is_never_shell_expanded(h: Harness) -> None:
    got = h.child_env(h.run('A="op://v/i/shell"\n'))
    same("A", got, SECRETS["op://v/i/shell"])
    assert not (h.tmp / "pwned").exists()


def test_literal_double_quoted_escapes(h: Harness) -> None:
    got = h.child_env(h.run('E="one\\ntwo\\tthree \\"q\\" back\\\\slash \\$ \\x"\n'))
    same("E", got, 'one\ntwo\tthree "q" back\\slash \\$ \\x')


def test_literal_single_quotes_are_raw(h: Harness) -> None:
    got = h.child_env(h.run("R='no \\n escapes, \"dq\" kept'\n"))
    same("R", got, 'no \\n escapes, "dq" kept')


def test_quoted_literal_may_span_lines(h: Harness) -> None:
    got = h.child_env(h.run("M=\"line one\nline two\"\nN='a\nb'\nAFTER=x\n"))
    same("M", got, "line one\nline two")
    same("N", got, "a\nb")
    same("AFTER", got, "x")


def test_reference_embedded_in_quoted_literal(h: Harness) -> None:
    got = h.child_env(h.run('URL="postgres://u:{{ op://v/i/plain }}@db/x"\n'))
    same("URL", got, "postgres://u:s3cr3t@db/x")


def test_no_variable_interpolation(h: Harness) -> None:
    got = h.child_env(
        h.run("A=\"$HOME ${HOME}\"\nB=$HOME\nC='${X:-d} {{ not a ref }}'\n")
    )
    same("A", got, "$HOME ${HOME}")
    same("B", got, "$HOME")
    same("C", got, "${X:-d} {{ not a ref }}")


def test_literal_text_never_reaches_op(h: Harness) -> None:
    # op inject expands $VARS in its template, so literals must not go there.
    sent = h.tmp / "op-stdin"
    proc = h.run(
        'URL="LITERAL_CANARY_1 $HOME {{ op://v/i/plain }} LITERAL_CANARY_2"\nL=LITERAL_CANARY_3\n',
        env={"FAKE_OP_STDIN": str(sent)},
    )
    same("URL", h.child_env(proc), "LITERAL_CANARY_1 $HOME s3cr3t LITERAL_CANARY_2")
    assert b"LITERAL_CANARY" not in sent.read_bytes()
    assert b"$HOME" not in sent.read_bytes()


def test_repeated_reference_resolved_once(h: Harness) -> None:
    sent = h.tmp / "op-stdin"
    proc = h.run(
        "A=op://v/i/plain\nB=op://v/i/plain\n", env={"FAKE_OP_STDIN": str(sent)}
    )
    got = h.child_env(proc)
    same("A", got, "s3cr3t")
    same("B", got, "s3cr3t")
    assert sent.read_bytes().count(b"op://v/i/plain") == 1


def test_no_references_means_no_op_call(h: Harness) -> None:
    got = h.child_env(h.run("A=plain\n# only a comment\n"))
    same("A", got, "plain")
    assert h.op_calls() == []


def test_empty_env_file_runs_child(h: Harness) -> None:
    h.child_env(h.run(""))
    assert h.op_calls() == []


def test_bare_reference_inside_text_is_refused(h: Harness) -> None:
    proc = h.run("URL=postgres://u:op://v/i/plain@db\n")
    assert proc.returncode != 0
    assert b"URL" in proc.stderr
    assert not h.out.exists()
    assert h.op_calls() == []


def test_lookalike_scheme_is_literal(h: Harness) -> None:
    got = h.child_env(h.run("A=shop://example\n"))
    same("A", got, "shop://example")


# --- equals, comments, blank lines, layout ---------------------------------


def test_equals_inside_values(h: Harness) -> None:
    got = h.child_env(h.run("A=op://v/i/equals\nB=x=y=z\nC='k=v'\n"))
    same("A", got, "a=b==c")
    same("B", got, "x=y=z")
    same("C", got, "k=v")


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
    )
    got = h.child_env(h.run(template))
    same("A", got, "s3cr3t")
    same("B", got, "s3cr3t")
    same("C", got, "a # not a comment")
    same("D", got, "value#not-a-comment")
    assert "DISABLED" not in got


def test_template_without_final_newline(h: Harness) -> None:
    got = h.child_env(h.run("A=op://v/i/plain"))
    same("A", got, "s3cr3t")


def test_crlf_template(h: Harness) -> None:
    got = h.child_env(h.run('A=op://v/i/plain\r\nB="x"\r\n'))
    same("A", got, "s3cr3t")
    same("B", got, "x")


def test_export_prefix_and_whitespace(h: Harness) -> None:
    got = h.child_env(h.run("export A=op://v/i/plain\n  B = spaced  \nC=\n"))
    same("A", got, "s3cr3t")
    same("B", got, "spaced")
    same("C", got, "")


def test_duplicate_key_last_wins(h: Harness) -> None:
    got = h.child_env(h.run("A=first\nA=op://v/i/plain\n"))
    same("A", got, "s3cr3t")


def test_existing_environment_is_inherited(h: Harness) -> None:
    got = h.child_env(h.run("A=op://v/i/plain\n", env={"KEEP_ME": "kept"}))
    same("KEEP_ME", got, "kept")


# --- errors never carry a value --------------------------------------------


@pytest.mark.parametrize(
    "template,key",
    [
        ('OPEN="op://v/i/plain\nOTHER=x\n', "OPEN"),
        ("OPEN='never closed\n", "OPEN"),
        ('TAIL="x" junk\n', "TAIL"),
    ],
)
def test_malformed_quotes_fail_naming_the_key(
    h: Harness, template: str, key: str
) -> None:
    proc = h.run(template)
    assert proc.returncode != 0
    assert key.encode() in proc.stderr
    assert not h.out.exists()
    assert h.op_calls() == [], (
        "op must not be called for a template that does not parse"
    )


@pytest.mark.parametrize(
    "line", ["no equals sign here", "=novalue", "BAD KEY=x", "1X=y"]
)
def test_malformed_lines_fail_naming_the_line(h: Harness, line: str) -> None:
    proc = h.run(f"A=ok\n{line}\n")
    assert proc.returncode != 0
    assert b"line 2" in proc.stderr
    assert not h.out.exists()


@pytest.mark.parametrize("mode", ["truncate", "prefix", "suffix", "collide", "repeat"])
def test_unexpected_op_output_fails_closed(h: Harness, mode: str) -> None:
    proc = h.run(
        "PEM=op://v/i/pem\nA=op://v/i/plain\nB=op://v/i/equals\n",
        env={"FAKE_OP_TAMPER": mode},
    )
    assert proc.returncode != 0
    assert b"could not map" in proc.stderr
    assert not h.out.exists()
    assert_no_secret_leak(proc)


def test_op_failure_never_echoes_its_stdout(h: Harness) -> None:
    proc = h.run("PEM=op://v/i/pem\nA=op://v/i/plain\n", env={"FAKE_OP_FAIL": "1"})
    assert proc.returncode == 1
    assert b"simulated failure" in proc.stderr
    assert not h.out.exists()
    assert_no_secret_leak(proc)


def test_unresolved_reference_fails_without_running_child(h: Harness) -> None:
    proc = h.run("A=op://v/i/plain\nB=op://v/i/missing\n")
    assert proc.returncode != 0
    assert not h.out.exists()
    assert_no_secret_leak(proc)


def test_no_value_leaks_on_success_output(h: Harness) -> None:
    template = "".join(
        f"K{i}={ref}\n" for i, ref in enumerate(r for r in SECRETS if " " not in r)
    )
    proc = h.run(template)
    h.child_env(proc)
    assert_no_secret_leak(proc)


def test_nul_in_value_fails_naming_key(h: Harness) -> None:
    h.secrets.write_text(json.dumps({**SECRETS, "op://v/i/nul": "a\x00b"}))
    proc = h.run("Z=op://v/i/nul\n")
    assert proc.returncode != 0
    assert b"Z" in proc.stderr
    assert not h.out.exists()


def test_non_utf8_bytes_survive(h: Harness) -> None:
    h.secrets.write_text(json.dumps({**SECRETS, "op://v/i/bytes": "caf\udce9"}))
    proc = h.run("Y=op://v/i/bytes\n")
    assert proc.returncode == 0, f"rc={proc.returncode}"
    raw = json.loads(h.out.read_text())["Y"]
    ok = raw.encode("utf-8", "surrogateescape") == b"caf\xe9"
    assert ok, f"Y: len={len(raw)}"


# --- CLI contract ----------------------------------------------------------


def test_one_inject_call_with_account_passed_through(h: Harness) -> None:
    proc = h.run("A=op://v/i/plain\nB=op://v/i/pem\n", "--account", "upstreamtech")
    h.child_env(proc)
    assert h.op_calls() == [["inject", "--account", "upstreamtech"]]


def test_account_equals_form_and_no_masking(h: Harness) -> None:
    proc = h.run("A=op://v/i/plain\n", "--account=upstreamtech", "--no-masking")
    same("A", h.child_env(proc), "s3cr3t")
    assert h.op_calls() == [["inject", "--account=upstreamtech"]]


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
    assert proc.returncode == 7


# --- the tunnel and the fallback take the same path ------------------------


class FakePasshd(BaseHTTPRequestHandler):
    token = "test-token"
    secrets: ClassVar[dict[str, str]] = {}
    calls: ClassVar[list[list[str]]] = []

    def log_message(self, fmt: str, *args: object) -> None:
        pass

    def do_POST(self) -> None:
        assert self.headers["Authorization"] == f"Bearer {self.token}"
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakePasshd.calls.append(req["args"])
        stdin = base64.b64decode(req["stdin"] or "")
        try:
            rc, out, err = 0, fake_op.inject(stdin, self.secrets), b""
        except fake_op.Unresolved as exc:
            rc, out, err = 1, b"", f"[ERROR] could not resolve {exc}\n".encode()
        body = json.dumps(
            {
                "rc": rc,
                "stdout": base64.b64encode(out).decode(),
                "stderr": base64.b64encode(err).decode(),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_tunnel_path(h: Harness) -> None:
    FakePasshd.secrets = SECRETS
    FakePasshd.calls = []
    server = HTTPServer(("127.0.0.1", 0), FakePasshd)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    token = h.tmp / "token"
    token.write_text(FakePasshd.token)
    try:
        proc = h.run(
            "PEM=\"op://v/i/pem\"\nA='op://v/i/plain'\n",
            "--account",
            "upstreamtech",
            env={
                "PASSH_MODE": "remote",
                "PASSH_PORT": str(server.server_port),
                "PASSH_TOKEN_FILE": str(token),
            },
        )
        got = h.child_env(proc)
    finally:
        server.shutdown()
    same("PEM", got, PEM)
    same("A", got, "s3cr3t")
    assert FakePasshd.calls == [["inject", "--account", "upstreamtech"]]
    assert h.op_calls() == [], "the tunnel was up, so local op must not run"


def test_fallback_path_when_tunnel_is_down(h: Harness) -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    token = h.tmp / "token"
    token.write_text("unused")
    proc = h.run(
        'PEM="op://v/i/pem"\n',
        env={
            "PASSH_MODE": "remote",
            "PASSH_PORT": str(port),
            "PASSH_TOKEN_FILE": str(token),
        },
    )
    same("PEM", h.child_env(proc), PEM)
    assert b"Falling back" in proc.stderr
    assert h.op_calls() == [["inject"]]
