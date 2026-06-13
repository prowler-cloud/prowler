#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: ./entrypoint.sh [main|uvicorn] [args...]

Modes:
  main (default)      Run prowler-mcp
  uvicorn             Run uvicorn prowler_mcp_server.server:app

All additional arguments are forwarded to the selected command.
EOF
}

mode="main"

if [ "$#" -gt 0 ]; then
  case "$1" in
    main|cli)
      mode="main"
      shift
      ;;
    uvicorn|asgi)
      mode="uvicorn"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      mode="main"
      ;;
  esac
fi

case "$mode" in
  main)
    exec prowler-mcp "$@"
    ;;
  uvicorn)
    export PROWLER_MCP_TRANSPORT_MODE="http"
    exec uvicorn prowler_mcp_server.server:app "$@"
    ;;
  *)
    usage
    exit 1
    ;;
esac
