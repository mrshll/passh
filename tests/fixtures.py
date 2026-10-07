"""Synthetic secrets for the fake resolver. None of these are real."""

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
    "op://v/i/looks-like-refs": "op://v/i/missing and {{ op://v/i/missing }}",
    "op://v/i/empty": "",
    "op://v/i/nul": "a\x00b",
    "op://v/i/bytes": "caf\udce9",
    "op://Private/Github agent/Token": "gh-synthetic",
    "op://v/Some Item/API Key": "api-synthetic",
}
