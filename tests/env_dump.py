"""Child process for `passh run` tests: write the environment it got as JSON."""

import json
import os
import sys

with open(sys.argv[1], "w") as fh:
    json.dump({k: v for k, v in os.environ.items()}, fh)
