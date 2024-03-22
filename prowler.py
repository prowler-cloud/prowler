#!/usr/bin/env python3
import sys

if __name__ == "__main__":
    if sys.argv[1] == "dashboard":
        from dashboard.__main__ import dashboard

        sys.exit(dashboard.run(debug=True, port=11666, use_reloader=False))
    else:
        from prowler.__main__ import prowler

        sys.exit(prowler())
