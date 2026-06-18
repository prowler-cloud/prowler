#!/usr/bin/env bash
#
# Local dev for Prowler API + worker.
# Postgres / Valkey / Neo4j run in Docker via docker-compose-dev.yml;
# Django and Celery run natively.
#
# Quick start:
#   make dev-setup   first-time bootstrap (deps, migrations, fixtures)
#   make dev         launch api + worker + postgres logs in tmux
#   make dev-attach  attach to the tmux session in the current terminal pane
#   make dev-launch  use fixed ports and attach interactive local dev
#   make dev-stop    stop everything: tmux + stop + remove containers
#   make dev-clean   remove stopped containers only (data preserved)
#   make dev-wipe    full nuke: kill + clean + delete ./_data/
#
# Agent / non-interactive usage: 'make dev' is idempotent, runs
# everything detached, blocks until the API answers HTTP, and ends with
# parseable key=value lines (api_url=, api_log=, worker_log=,
# postgres_log=, attach_cmd=, stop_cmd=).
# Every pane is teed ANSI-stripped to _data/logs/{api,worker,postgres}.log
# (truncated per run), so logs are readable with tail -f, no tmux needed.
#
# 'attach' does not create Warp panes. It attaches to tmux inside the current
# terminal pane. If you want native Warp panes, use 'make dev-launch'
# from Warp instead.
#
# Inside the tmux session "prowler-dev-<compose-project>" the prefix key is Ctrl+b. After it:
#   d              detach (everything keeps running; reattach: make dev-attach)
#   <arrows>       move between panes
#   z              zoom current pane (toggle)
#   [              scrollback mode (q to exit)
#   x              kill current pane (asks for confirmation)
#   &              kill current window
#   :kill-session  end the whole session
#
# How to stop everything from inside tmux:
#   1) Ctrl+b then d           detach back to your shell
#   2) make dev-stop           tears down tmux + containers
# Alternative without detaching: open a new tmux window with Ctrl+b then c
# and run make dev-stop there; the session will close itself.
#
# Stop just the python procs (keep containers up to skip a slow neo4j boot next time):
#   ./scripts/development/dev-local.sh down
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

path_hash() {
  if command -v shasum >/dev/null 2>&1; then
    printf '%s' "$REPO_ROOT" | shasum | awk '{print substr($1, 1, 8)}'
  else
    printf '%s' "$REPO_ROOT" | cksum | awk '{print $1}'
  fi
}

compose_project_default() {
  local base hash
  base="$(basename "$REPO_ROOT" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9_-]+/-/g; s/^-+//; s/-+$//')"
  hash="$(path_hash)"
  printf '%s-%s' "${base:-prowler}" "$hash"
}

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$(compose_project_default)}"

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

export POSTGRES_HOST=localhost
export POSTGRES_PORT="${POSTGRES_PORT:-5432}"
export VALKEY_HOST=localhost
export VALKEY_PORT="${VALKEY_PORT:-6379}"
export VALKEY_SCHEME="${VALKEY_SCHEME:-redis}"
export NEO4J_HOST=localhost
export NEO4J_PORT="${NEO4J_PORT:-7687}"
export NEO4J_HTTP_PORT="${NEO4J_HTTP_PORT:-7474}"
export DJANGO_SETTINGS_MODULE=config.django.devel
export DJANGO_DEBUG="${DJANGO_DEBUG:-True}"
export DJANGO_PORT="${DJANGO_PORT:-8080}"
export DJANGO_LOGGING_FORMATTER="${DJANGO_LOGGING_FORMATTER:-human_readable}"
export DJANGO_LOGGING_LEVEL="${DJANGO_LOGGING_LEVEL:-info}"
export DJANGO_MANAGE_DB_PARTITIONS="${DJANGO_MANAGE_DB_PARTITIONS:-False}"

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
else
  COMPOSE=(docker-compose)
fi
COMPOSE_FILE="docker-compose-dev.yml"

log()  { printf '\033[1;34m→\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!\033[0m %s\n' "$*"; }

require_uv() {
  if ! command -v uv >/dev/null 2>&1; then
    warn "uv not found in PATH. Install: https://docs.astral.sh/uv/getting-started/installation/"
    exit 1
  fi
}

services_up() {
  log "Starting postgres + valkey + neo4j via Docker (waits for healthchecks)..."
  "${COMPOSE[@]}" -f "$COMPOSE_FILE" up -d --wait postgres valkey neo4j
  ok "Services ready: pg:${POSTGRES_PORT} / valkey:${VALKEY_PORT} / neo4j:${NEO4J_PORT} / neo4j-http:${NEO4J_HTTP_PORT}"
}

kill_tmux_session() {
  command -v tmux >/dev/null 2>&1 || return 0
  if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    log "Killing tmux session '$TMUX_SESSION'"
    tmux kill-session -t "$TMUX_SESSION"
  fi
}

tmux_pane_count() {
  tmux list-panes -t "$TMUX_SESSION:" 2>/dev/null | wc -l | tr -d ' '
}

# Tee a tmux pane's output to _data/logs/<name>.log so non-interactive
# consumers (scripts, agents) can follow the stack without attaching.
# ANSI codes are stripped; the file is truncated on session creation so
# its content always matches the current run.
pipe_pane_log() {
  local pane="$1" name="$2"
  local logfile="$REPO_ROOT/_data/logs/$name.log"
  : > "$logfile"
  tmux pipe-pane -t "$pane" -o "perl -pe 'BEGIN{\$|=1} s/\\e\\[[0-9;?]*[A-Za-z]//g' >> '$logfile'"
}

# Stop native dev processes (api/worker/beat) launched outside tmux, e.g. inside
# Warp panes. Scoped by cwd under REPO_ROOT so other prowler clones running their
# own stacks are not touched.
kill_native_procs() {
  command -v pgrep >/dev/null 2>&1 || return 0
  command -v lsof  >/dev/null 2>&1 || return 0

  local pids="" pid pcwd pat
  for pat in "manage.py runserver" "celery -A config.celery worker" "celery -A config.celery beat"; do
    while IFS= read -r pid; do
      [ -n "$pid" ] || continue
      pcwd="$(lsof -a -d cwd -p "$pid" 2>/dev/null | awk 'NR>1 {print $NF; exit}')"
      case "$pcwd" in
        "$REPO_ROOT"|"$REPO_ROOT"/*) pids="$pids $pid" ;;
      esac
    done < <(pgrep -f "$pat" 2>/dev/null)
  done

  pids="$(printf '%s\n' "$pids" | tr ' ' '\n' | sed '/^$/d' | sort -u | xargs)"
  [ -z "$pids" ] && return 0

  log "Stopping native dev procs ($pids) under $REPO_ROOT"
  # shellcheck disable=SC2086
  kill -TERM $pids 2>/dev/null || true
  sleep 0.5
  # shellcheck disable=SC2086
  kill -KILL $pids 2>/dev/null || true
}

services_down() {
  kill_tmux_session
  kill_native_procs
  log "Stopping postgres + valkey + neo4j..."
  "${COMPOSE[@]}" -f "$COMPOSE_FILE" stop postgres valkey neo4j
}

services_status() {
  "${COMPOSE[@]}" -f "$COMPOSE_FILE" ps postgres valkey neo4j
}

deps() {
  require_uv
  log "uv sync (api/)..."
  (cd api && uv sync)
}

migrate() {
  require_uv
  log "Applying migrations (admin DB)..."
  (
    cd api/src/backend
    uv run python manage.py check_and_fix_socialaccount_sites_migration --database admin
    uv run python manage.py migrate --database admin
  )
  ok "Migrations applied"
}

fixtures() {
  require_uv
  log "Loading dev fixtures..."
  (
    cd api/src/backend
    for fixture in api/fixtures/dev/*.json; do
      [ -f "$fixture" ] || continue
      echo "  loading $(basename "$fixture")"
      uv run python manage.py loaddata "$fixture" --database admin
    done
  )
  ok "Fixtures loaded"
}

api_run() {
  require_uv
  log "Starting Django API on [::]:${DJANGO_PORT} (IPv4 + IPv6 dual-stack)"
  cd api/src/backend
  exec uv run python manage.py runserver "[::]:${DJANGO_PORT}"
}

worker_run() {
  require_uv
  log "Starting Celery worker"
  cd api/src/backend
  exec uv run python -m celery -A config.celery worker \
    -l "${DJANGO_LOGGING_LEVEL}" \
    -Q celery,scans,scan-reports,deletion,backfill,overview,integrations,compliance,attack-paths-scans \
    -E
}

beat_run() {
  require_uv
  log "Starting Celery beat (DatabaseScheduler)"
  cd api/src/backend
  exec uv run python -m celery -A config.celery beat \
    -l "${DJANGO_LOGGING_LEVEL}" \
    --scheduler django_celery_beat.schedulers:DatabaseScheduler
}

TMUX_SESSION="prowler-dev-${COMPOSE_PROJECT_NAME}"
SCRIPT_PATH="$REPO_ROOT/scripts/development/dev-local.sh"

require_tmux() {
  if ! command -v tmux >/dev/null 2>&1; then
    warn "tmux not installed. Run: brew install tmux"
    exit 1
  fi
}

remove_repo_compose_containers() {
  command -v docker >/dev/null 2>&1 || return 0
  local ids
  ids="$(
    docker ps -aq 2>/dev/null \
      | while IFS= read -r id; do
          docker inspect --format '{{.ID}} {{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$id" 2>/dev/null || true
        done \
      | awk -v repo="$REPO_ROOT" '$2 == repo {print $1}'
  )"
  [ -n "$ids" ] || return 0
  warn "Removing existing Docker containers for this repo before launch"
  # shellcheck disable=SC2086
  docker rm -f $ids >/dev/null
}

remove_docker_containers_on_ports() {
  command -v docker >/dev/null 2>&1 || return 0
  local all_ids ids_to_remove="" id port published_ports
  all_ids="$(docker ps -aq 2>/dev/null || true)"
  [ -n "$all_ids" ] || return 0

  for id in $all_ids; do
    published_ports="$(docker inspect --format '{{range $containerPort, $bindings := .HostConfig.PortBindings}}{{range $bindings}}{{.HostPort}}{{"\n"}}{{end}}{{end}}' "$id" 2>/dev/null || true)"
    [ -n "$published_ports" ] || continue
    for port in "$@"; do
      if printf '%s\n' "$published_ports" | grep -qx "$port"; then
        ids_to_remove="$ids_to_remove $id"
        break
      fi
    done
  done

  ids_to_remove="$(printf '%s\n' "$ids_to_remove" | tr ' ' '\n' | sed '/^$/d' | sort -u | xargs)"
  [ -n "$ids_to_remove" ] || return 0
  warn "Removing Docker containers publishing fixed dev ports: $ids_to_remove"
  # shellcheck disable=SC2086
  docker rm -f $ids_to_remove >/dev/null
}

kill_listeners_on_ports() {
  command -v lsof >/dev/null 2>&1 || return 0
  local pids="" port port_pids
  for port in "$@"; do
    port_pids="$(lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
    [ -n "$port_pids" ] && pids="$pids $port_pids"
  done

  pids="$(printf '%s\n' "$pids" | tr ' ' '\n' | sed '/^$/d' | sort -u | xargs)"
  [ -n "$pids" ] || return 0
  warn "Killing local processes listening on fixed dev ports: $pids"
  # shellcheck disable=SC2086
  kill -TERM $pids 2>/dev/null || true
  sleep 0.5
  # shellcheck disable=SC2086
  kill -KILL $pids 2>/dev/null || true
}

clear_dev_port_conflicts() {
  local ports=("$DJANGO_PORT" "$POSTGRES_PORT" "$VALKEY_PORT" "$NEO4J_PORT" "$NEO4J_HTTP_PORT")
  log "Ensuring fixed dev ports are free: api:${DJANGO_PORT} pg:${POSTGRES_PORT} valkey:${VALKEY_PORT} neo4j:${NEO4J_PORT} neo4j-http:${NEO4J_HTTP_PORT}"
  remove_docker_containers_on_ports "${ports[@]}"
  kill_listeners_on_ports "${ports[@]}"
}

# Block until the API answers HTTP on DJANGO_PORT (any status code counts).
wait_for_api() {
  local timeout="${1:-90}" waited=0
  log "Waiting for API on :${DJANGO_PORT} (timeout ${timeout}s)..."
  until curl -s -o /dev/null --max-time 2 "http://localhost:${DJANGO_PORT}/"; do
    waited=$((waited + 1))
    if [ "$waited" -ge "$timeout" ]; then
      warn "API not responding after ${timeout}s. Check _data/logs/api.log"
      return 1
    fi
    sleep 1
  done
  ok "API responding on :${DJANGO_PORT}"
}

needs_db_bootstrap() {
  ! "${COMPOSE[@]}" -f "$COMPOSE_FILE" exec -T postgres \
      psql -U prowler -d prowler_db -c 'select 1' >/dev/null 2>&1
}

bootstrap_db_if_needed() {
  if needs_db_bootstrap; then
    warn "App DB user not ready. Bootstrapping (deps + migrate + fixtures)..."
    deps
    migrate
    fixtures
    ok "DB bootstrap complete"
  fi
}

all_run() {
  require_tmux
  require_uv
  services_up
  bootstrap_db_if_needed

  # Wrap a command so it auto-runs as the pane's foreground process and, on
  # exit (e.g. Ctrl+C), drops into the user's login shell instead of closing.
  # Avoids the `send-keys` race where keys arrive before zsh+starship are ready.
  local user_shell="${SHELL:-/bin/zsh}"
  pane_cmd() {
    printf 'bash -c %q' "$1; exec ${user_shell}"
  }
  local api_cmd worker_cmd pg_cmd
  api_cmd="$(pane_cmd "$SCRIPT_PATH api")"
  worker_cmd="$(pane_cmd "$SCRIPT_PATH worker")"
  pg_cmd="$(pane_cmd "${COMPOSE[*]} -f $COMPOSE_FILE logs -f postgres")"

  # If a tmux server is already running (e.g. another project's session), new
  # sessions inherit THAT server's env, not the launcher shell's env. Pass our
  # overrides explicitly so each pane sees the right project name, ports, etc.
  local -a env_args=()
  local var
  for var in COMPOSE_PROJECT_NAME \
             POSTGRES_HOST POSTGRES_PORT \
             VALKEY_HOST VALKEY_PORT VALKEY_SCHEME \
             NEO4J_HOST NEO4J_PORT NEO4J_HTTP_PORT \
             DJANGO_SETTINGS_MODULE DJANGO_DEBUG DJANGO_PORT \
             DJANGO_LOGGING_FORMATTER DJANGO_LOGGING_LEVEL \
             DJANGO_MANAGE_DB_PARTITIONS; do
    env_args+=(-e "${var}=${!var-}")
  done

  local expected_panes=3

  if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    local current_panes
    current_panes="$(tmux_pane_count)"
    if [ "$current_panes" -lt "$expected_panes" ]; then
      warn "Session '$TMUX_SESSION' has $current_panes pane(s), expected $expected_panes. Rebuilding it."
      tmux kill-session -t "$TMUX_SESSION"
    else
      log "Session '$TMUX_SESSION' already exists"
    fi
  fi

  if ! tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    log "Creating tmux session '$TMUX_SESSION' (api / worker / db logs)"
    tmux new-session -d -s "$TMUX_SESSION" -n services -c "$REPO_ROOT" "${env_args[@]}" "$api_cmd"
    tmux split-window -t "$TMUX_SESSION:0.0" -v -p 50 -c "$REPO_ROOT" "${env_args[@]}" "$worker_cmd"
    tmux split-window -t "$TMUX_SESSION:0.1" -h -p 50 -c "$REPO_ROOT" "${env_args[@]}" "$pg_cmd"
    tmux select-pane -t "$TMUX_SESSION:0.0"
    tmux set-option -t "$TMUX_SESSION" -g mouse on >/dev/null
    tmux set-option -t "$TMUX_SESSION" -g bell-action none >/dev/null
    tmux set-option -t "$TMUX_SESSION" -g visual-bell off >/dev/null
    tmux set-option -t "$TMUX_SESSION" -g monitor-bell off >/dev/null
    tmux set-option -t "$TMUX_SESSION" -g monitor-activity off >/dev/null
    tmux set-option -t "$TMUX_SESSION" -g visual-activity off >/dev/null
    tmux set-option -t "$TMUX_SESSION" -g activity-action none >/dev/null
    tmux set-option -t "$TMUX_SESSION" -g silence-action none >/dev/null
    tmux bind-key -T copy-mode MouseDragEnd1Pane send-keys -X copy-pipe-and-cancel "pbcopy" 2>/dev/null
    tmux bind-key -T copy-mode-vi MouseDragEnd1Pane send-keys -X copy-pipe-and-cancel "pbcopy" 2>/dev/null
    tmux set-option -t "$TMUX_SESSION" -g status-right " API:${DJANGO_PORT} | DB:${POSTGRES_PORT} | Broker:${VALKEY_PORT} " >/dev/null

    mkdir -p "$REPO_ROOT/_data/logs"
    pipe_pane_log "$TMUX_SESSION:0.0" api
    pipe_pane_log "$TMUX_SESSION:0.1" worker
    pipe_pane_log "$TMUX_SESSION:0.2" postgres
  fi

  wait_for_api 90

  ok "Dev stack ready (detached)"
  cat <<EOF
api_url=http://localhost:${DJANGO_PORT}/api/v1
api_log=_data/logs/api.log
worker_log=_data/logs/worker.log
postgres_log=_data/logs/postgres.log
EOF
  cat <<EOF
attach_cmd=make dev-attach
stop_cmd=make dev-stop
EOF
}

attach_run() {
  require_tmux
  if ! tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    warn "No session '$TMUX_SESSION'. Starting it with: $0 all"
    all_run
  else
    local current_panes
    current_panes="$(tmux_pane_count)"
    if [ "$current_panes" -lt 3 ]; then
      warn "Session '$TMUX_SESSION' only has $current_panes pane(s). Rebuilding with db logs."
      tmux kill-session -t "$TMUX_SESSION"
      all_run
    fi
  fi
  if [ -n "${TMUX:-}" ]; then
    tmux switch-client -t "$TMUX_SESSION"
  else
    tmux attach-session -t "$TMUX_SESSION"
  fi
}

clean_run() {
  log "Removing stopped containers from the compose project..."
  "${COMPOSE[@]}" -f "$COMPOSE_FILE" rm -f
  ok "Stopped containers removed (data volumes under ./_data/ untouched)"
}

wipe_run() {
  warn "DESTRUCTIVE: this will tear down everything AND delete ./_data/"
  warn "  postgres database, valkey state, neo4j graph, api jwt keys - all gone."
  warn "  Next start will require 'make dev-setup' from scratch."
  kill_run
  if [ -d ./_data ]; then
    log "Removing ./_data/ ..."
    rm -rf ./_data
  fi
  ok "Wipe complete. Run 'make dev-setup' for a fresh environment."
}

kill_run() {
  kill_tmux_session
  services_down
  clean_run
  ok "Dev stack stopped (tmux killed, containers stopped + removed)"
}

LAUNCH_TERMINAL="${DEV_LOCAL_TERMINAL:-}"
if [ -z "$LAUNCH_TERMINAL" ]; then
  if [ "${TERM_PROGRAM:-}" = "WarpTerminal" ]; then
    LAUNCH_TERMINAL="Warp"
  else
    LAUNCH_TERMINAL="Ghostty"
  fi
fi

warp_launch_run() {
  require_uv
  kill_tmux_session
  remove_repo_compose_containers
  clear_dev_port_conflicts

  log "Launching dev stack in tmux inside the current Warp pane"
  log "  api:${DJANGO_PORT} pg:${POSTGRES_PORT} valkey:${VALKEY_PORT} neo4j:${NEO4J_PORT} neo4j-http:${NEO4J_HTTP_PORT}"
  all_run
  attach_run
}

launch_run() {
  if [ "$LAUNCH_TERMINAL" = "Warp" ]; then
    warp_launch_run
    return
  fi

  kill_tmux_session
  remove_repo_compose_containers
  clear_dev_port_conflicts

  log "Launching dev stack in a new terminal window"
  log "  api:${DJANGO_PORT} pg:${POSTGRES_PORT} valkey:${VALKEY_PORT} neo4j:${NEO4J_PORT} neo4j-http:${NEO4J_HTTP_PORT}"
  log "  tmux session: ${TMUX_SESSION}"

  local cleanup_cmd
  case "$LAUNCH_TERMINAL" in
    Terminal)
      # shellcheck disable=SC2016
      cleanup_cmd='( sleep 1; osascript -e "tell application \"Terminal\" to close (every window whose name contains \"$WINDOW_TAG\") saving no" >/dev/null 2>&1 ) </dev/null >/dev/null 2>&1 & disown'
      ;;
    iTerm|iTerm2)
      # shellcheck disable=SC2016
      cleanup_cmd='( sleep 1; osascript -e "tell application \"iTerm\" to close (every window whose name contains \"$WINDOW_TAG\")" >/dev/null 2>&1 ) </dev/null >/dev/null 2>&1 & disown'
      ;;
    *)
      cleanup_cmd="pkill -f '/$LAUNCH_TERMINAL.app/Contents/MacOS/' 2>/dev/null || true"
      ;;
  esac

  local wrapper
  wrapper="$(mktemp -t dev-local-launch).sh"
  cat > "$wrapper" <<EOF
#!/usr/bin/env bash
WINDOW_TAG="dev-local-\$\$"
printf '\033]0;%s\007' "\$WINDOW_TAG"
export HISTFILE=/dev/null HISTSIZE=0 SAVEHIST=0
on_exit() {
  printf '#!/usr/bin/env bash\nexit 0\n' > '$wrapper'
  $cleanup_cmd
}
trap on_exit EXIT
cd "${REPO_ROOT}"
export DJANGO_PORT=${DJANGO_PORT}
export POSTGRES_PORT=${POSTGRES_PORT}
export VALKEY_PORT=${VALKEY_PORT}
export NEO4J_PORT=${NEO4J_PORT}
export NEO4J_HTTP_PORT=${NEO4J_HTTP_PORT}
"$SCRIPT_PATH" all
"$SCRIPT_PATH" attach
EOF
  chmod +x "$wrapper"

  case "$LAUNCH_TERMINAL" in
    Ghostty)
      open -na Ghostty --args --initial-command="bash '$wrapper'" --wait-after-command=false --quit-after-last-window-closed=true
      ;;
    iTerm|iTerm2)
      osascript -e "tell application \"iTerm\" to create window with default profile command \"bash '$wrapper'\""
      ;;
    Terminal)
      open -a Terminal "$wrapper"
      ;;
    *)
      open -na "$LAUNCH_TERMINAL" "$wrapper"
      ;;
  esac
  ok "Launched in $LAUNCH_TERMINAL (override with DEV_LOCAL_TERMINAL)"
}

setup() {
  services_up
  deps
  migrate
  fixtures
  ok "Setup complete."
  cat <<EOF

Next run everything in one window:
  make dev                    # api + worker in tmux

API will be available at http://localhost:${DJANGO_PORT}/api/v1/
EOF
}

usage() {
  cat <<EOF
Usage: $0 <command>

One-window dev (tmux inside the terminal):
  all        api + worker + postgres logs in 3 panes (detached,
             blocks until API responds,
             ends with parseable api_url= / *_log= / attach_cmd= / stop_cmd= lines)
  attach     Reattach to the existing dev session
             Attaches tmux inside the current terminal pane; it does not create
             native Warp panes.
             Pane output is also written to _data/logs/{api,worker,postgres}.log
             (ANSI-stripped, truncated per run) - usable without attaching
  kill       Stop tmux + stop containers + remove them (full teardown)
  launch     Use fixed ports, clear conflicts, then spawn the stack
             - From Warp: runs 'all' and attaches tmux in the current pane
             - Otherwise: opens a new Ghostty window running 'all' under tmux
             (override with DEV_LOCAL_TERMINAL=<App>, e.g. Ghostty/iTerm/Terminal)

State (containers postgres + valkey + neo4j):
  up         Start postgres + valkey + neo4j (waits for healthchecks)
  down       Stop tmux + postgres + valkey + neo4j (keeps containers around)
  status     Show container status
  clean      Remove all stopped containers in the project (data volumes preserved)
  wipe       Full nuke: kill + clean + delete ./_data/

Python (native, foreground - usually launched via 'all'):
  api        Run Django API (runserver)
  worker     Run Celery worker
  beat       Run Celery beat scheduler

One-shots:
  setup      up + deps + migrate + fixtures (first-time / fresh DB)
  deps       uv sync inside api/
  migrate    Apply migrations to admin DB
  fixtures   Load dev fixtures

Typical flow:
  make dev-setup              # first time only
  make dev                    # daily dev
  make dev-stop               # when done
EOF
}

case "${1:-help}" in
  all)       shift; if [ "$#" -gt 0 ]; then warn "'all $*' is not supported. Use: $0 all"; exit 1; fi; all_run ;;
  attach)    attach_run ;;
  kill)      kill_run ;;
  launch)    launch_run ;;
  clean)     clean_run ;;
  wipe)      wipe_run ;;
  up)        services_up ;;
  down)      services_down ;;
  status)    services_status ;;
  api)       api_run ;;
  worker)    worker_run ;;
  beat)      beat_run ;;
  setup)     setup ;;
  deps)      deps ;;
  migrate)   migrate ;;
  fixtures)  fixtures ;;
  help|-h|--help|*) usage ;;
esac
