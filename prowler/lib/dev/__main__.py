"""Allow `python -m prowler.lib.dev` alongside the `prowler-dev` script."""

import sys

from prowler.lib.dev.cli import main

if __name__ == "__main__":
    sys.exit(main())
