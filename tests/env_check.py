"""Child process for `passh run` tests.

Compares its environment with expectations given on argv and writes only
booleans and lengths to the report file — never a value.
"""

import json
import os
import sys

from fixtures import SECRETS


def main() -> None:
    report_path, spec = sys.argv[1], json.loads(sys.argv[2])
    report: dict[str, dict] = {"expect": {}, "absent": {}}
    for key, parts in spec["expect"].items():
        want = "".join(SECRETS[text] if kind == "ref" else text for kind, text in parts)
        got = os.environ.get(key, "")
        report["expect"][key] = {
            "present": key in os.environ,
            "equal": key in os.environ and got == want,
            "len": len(got),
            "want_len": len(want),
            "lines": got.count("\n"),
            "want_lines": want.count("\n"),
        }
    for key in spec["absent"]:
        report["absent"][key] = key in os.environ
    with open(report_path, "w") as fh:
        json.dump(report, fh)


if __name__ == "__main__":
    main()
