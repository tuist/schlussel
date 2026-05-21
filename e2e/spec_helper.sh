# shellcheck shell=bash

REPO_ROOT="$(cd "$SHELLSPEC_PROJECT_ROOT" && pwd)"
SCHLUSSEL_BIN="${REPO_ROOT}/target/debug/schlussel"
OAUTH_SERVER_BIN="${REPO_ROOT}/target/debug/schlussel-oauth-test-server"
export REPO_ROOT SCHLUSSEL_BIN OAUTH_SERVER_BIN

spec_helper_precheck() {
  if [ ! -x "$SCHLUSSEL_BIN" ]; then
    abort "schlussel binary missing at $SCHLUSSEL_BIN - run '~/.cargo/bin/cargo build --workspace' first"
  fi
  if [ ! -x "$OAUTH_SERVER_BIN" ]; then
    abort "oauth test server missing at $OAUTH_SERVER_BIN - run '~/.cargo/bin/cargo build --workspace' first"
  fi
  command -v curl >/dev/null 2>&1 || abort "curl is required for e2e OAuth tests"
}

spec_helper_loaded() { :; }

setup_workspace() {
  WORKSPACE="$(mktemp -d -t schlussel-e2e.XXXXXX)"
  XDG_CACHE_HOME="$WORKSPACE/.xdg/cache"
  XDG_STATE_HOME="$WORKSPACE/.xdg/state"
  XDG_DATA_HOME="$WORKSPACE/.xdg/data"
  XDG_CONFIG_HOME="$WORKSPACE/.xdg/config"
  XDG_RUNTIME_DIR="$WORKSPACE/.xdg/runtime"
  mkdir -p "$XDG_CACHE_HOME" "$XDG_STATE_HOME" "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_RUNTIME_DIR"
  export WORKSPACE XDG_CACHE_HOME XDG_STATE_HOME XDG_DATA_HOME XDG_CONFIG_HOME XDG_RUNTIME_DIR
}

cleanup_workspace() {
  stop_oauth_server
  if [ -n "${WORKSPACE:-}" ] && [ -d "$WORKSPACE" ]; then
    rm -rf "$WORKSPACE"
  fi
  unset WORKSPACE XDG_CACHE_HOME XDG_STATE_HOME XDG_DATA_HOME XDG_CONFIG_HOME XDG_RUNTIME_DIR
  unset OAUTH_SERVER_PID OAUTH_PORT OAUTH_BASE_URL FORMULA_JSON
}

schlussel() {
  "$SCHLUSSEL_BIN" "$@"
}

start_oauth_server() {
  OAUTH_STATE_DIR="$WORKSPACE/oauth-server"
  mkdir -p "$OAUTH_STATE_DIR"
  "$OAUTH_SERVER_BIN" \
    --state-dir "$OAUTH_STATE_DIR" \
    --port-file "$OAUTH_STATE_DIR/port" \
    >"$OAUTH_STATE_DIR/server.log" 2>&1 &
  OAUTH_SERVER_PID=$!
  export OAUTH_SERVER_PID

  i=0
  while [ ! -f "$OAUTH_STATE_DIR/port" ] && [ "$i" -lt 100 ]; do
    sleep 0.1
    i=$((i + 1))
  done

  [ -f "$OAUTH_STATE_DIR/port" ] || abort "oauth server did not write a port file"

  OAUTH_PORT="$(cat "$OAUTH_STATE_DIR/port")"
  OAUTH_BASE_URL="http://127.0.0.1:${OAUTH_PORT}"
  export OAUTH_PORT OAUTH_BASE_URL
}

stop_oauth_server() {
  if [ -n "${OAUTH_SERVER_PID:-}" ]; then
    kill "$OAUTH_SERVER_PID" >/dev/null 2>&1 || true
    wait "$OAUTH_SERVER_PID" >/dev/null 2>&1 || true
  fi
}

write_local_formula() {
  FORMULA_JSON="$WORKSPACE/local-oauth.json"
  cat >"$FORMULA_JSON" <<EOF
{
  "schema": "v2",
  "id": "local",
  "label": "Local OAuth",
  "clients": [
    {
      "name": "local-cli",
      "id": "local-client",
      "methods": ["device_code", "authorization_code"]
    }
  ],
  "identity": {
    "label": "Account",
    "hint": "e.g. personal"
  },
  "methods": {
    "device_code": {
      "label": "Device Code",
      "endpoints": {
        "device": "${OAUTH_BASE_URL}/device/code",
        "token": "${OAUTH_BASE_URL}/token"
      },
      "scope": "read write"
    },
    "authorization_code": {
      "label": "Authorization Code",
      "endpoints": {
        "authorize": "${OAUTH_BASE_URL}/authorize",
        "token": "${OAUTH_BASE_URL}/token"
      },
      "scope": "read write"
    }
  },
  "apis": {
    "rest": {
      "base_url": "${OAUTH_BASE_URL}/api",
      "auth_header": "Authorization: Bearer {token}",
      "methods": ["device_code", "authorization_code"]
    }
  }
}
EOF
  export FORMULA_JSON
}

wait_for_log_line() {
  file="$1"
  pattern="$2"
  timeout_seconds="${3:-10}"
  i=0
  max_iterations=$((timeout_seconds * 10))
  while [ "$i" -lt "$max_iterations" ]; do
    if [ -f "$file" ] && grep -Fq "$pattern" "$file"; then
      return 0
    fi
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

extract_suffix() {
  file="$1"
  prefix="$2"
  grep -F "$prefix" "$file" | tail -n 1 | sed "s/.*${prefix}//"
}

approve_device_code() {
  user_code="$1"
  curl -fsS -X POST -d "user_code=${user_code}" "${OAUTH_BASE_URL}/approve-device" >/dev/null
}

follow_authorize_url() {
  authorize_url="$1"
  curl -fsSL "$authorize_url" >/dev/null
}

fetch_oauth_stats() {
  curl -fsS "${OAUTH_BASE_URL}/stats"
}
