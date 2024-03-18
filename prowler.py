#!/usr/bin/env python3

import sys

from dashboard.__main__ import dashboard
from prowler.__main__ import prowler

if __name__ == "__main__":
    if sys.argv[1] == "dashboard":
        sys.exit(dashboard.run(debug=True, port=11666))
    else:
        sys.exit(prowler())
