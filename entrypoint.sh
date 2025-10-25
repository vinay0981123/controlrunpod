#!/usr/bin/env bash
set -euo pipefail

# Configurable
WORKDIR=${WORKDIR:-/workspace/hearmefinal}
LOGDIR="${WORKDIR}/logs"
ENTRYLOG="${LOGDIR}/entrypoint.log"
MAX_WAIT_SECONDS="${START_WAIT_SECONDS:-120}"

# Helpers
timestamp() { date -Is; }
log() {
  mkdir -p "$(dirname "$ENTRYLOG")"
  echo "[$(timestamp)] $*" | tee -a "$ENTRYLOG"
}

log "entrypoint: starting"

# Start sshd (daemon)
if command -v /usr/sbin/sshd >/dev/null 2>&1; then
  log "entrypoint: starting sshd"
  /usr/sbin/sshd || log "entrypoint: warning: sshd returned non-zero"
else
  log "entrypoint: sshd not found"
fi

# Ensure logdir exists so run.sh can write into it
mkdir -p "$LOGDIR"
touch "$LOGDIR/run.log" "$ENTRYLOG" || true

# Wait for the mounted workspace and required files (run.sh and venv)
log "entrypoint: waiting for WORKDIR=$WORKDIR (max ${MAX_WAIT_SECONDS}s) ..."
i=0
while true; do
  # Check for run.sh and venv
  run_sh="$WORKDIR/run.sh"
  venv_activate="$WORKDIR/venv/bin/activate"
  venv_py="$WORKDIR/venv/bin/python3"

  if [ -x "$run_sh" ] && ([ -f "$venv_activate" ] || [ -x "$venv_py" ]); then
    log "entrypoint: found run.sh and venv (or venv python)"
    break
  fi

  i=$((i+1))
  if [ "$i" -ge "$MAX_WAIT_SECONDS" ]; then
    log "entrypoint: timed out waiting for run.sh/venv after ${MAX_WAIT_SECONDS}s"
    break
  fi
  sleep 1
done

# Change into WORKDIR if exists
if [ -d "$WORKDIR" ]; then
  cd "$WORKDIR"
  log "entrypoint: cd $WORKDIR"
else
  log "entrypoint: WORKDIR $WORKDIR not present - continuing but nothing to run"
fi

# Activate venv if present and validate it
VENV_ACTIVATED="false"
if [ -f "$venv_activate" ]; then
  log "entrypoint: sourcing venv activate: $venv_activate"
  # shellcheck disable=SC1090
  source "$venv_activate" || {
    log "entrypoint: ERROR: failed to source $venv_activate"
  }
  # Verify python executable is from venv
  if command -v python3 >/dev/null 2>&1; then
    PY_PATH="$(python3 -c 'import sys; print(sys.executable)')" || PY_PATH=""
    PY_PREFIX="$(python3 -c 'import sys; print(sys.prefix)')" || PY_PREFIX=""
    log "entrypoint: python executable after activate: $PY_PATH"
    log "entrypoint: python prefix after activate: $PY_PREFIX"
    # Check if prefix points into our venv dir
    if [[ "$PY_PREFIX" == "$WORKDIR/venv" ]] || [[ "$PY_PATH" == "$WORKDIR/venv/"* ]]; then
      VENV_ACTIVATED="true"
      log "entrypoint: venv activation verified"
    else
      log "entrypoint: WARNING: venv activation did NOT appear to set python prefix to $WORKDIR/venv"
    fi
  else
    log "entrypoint: WARNING: python3 not found after sourcing venv"
  fi
elif [ -x "$venv_py" ]; then
  log "entrypoint: venv activation script not found, but venv python exists: $venv_py"
  # Use venv python by invoking venv python directly (no 'source')
  PY_PATH="$venv_py"
  VENV_ACTIVATED="true"
  log "entrypoint: will use venv python at $PY_PATH (no shell activation)"
else
  log "entrypoint: no venv found, will run run.sh without venv activation"
fi

# If run.sh present, execute it (let run.sh handle its own nohup backgrounding)
if [ -x "$run_sh" ]; then
  log "entrypoint: launching run.sh (will not background here; run.sh is expected to manage backgrounding)"
  # Make sure run.sh is executable
  chmod +x "$run_sh" || true

  if [ "$VENV_ACTIVATED" = "true" ]; then
    # Run via the shell that already has venv sourced
    log "entrypoint: executing run.sh with activated venv. Logging to $LOGDIR/run.log"
    # run.sh contains nohup & will background uvicorn; we capture its stdout/stderr in its own redirection
    bash -lc "./run.sh" >> "$LOGDIR/run.sh.out" 2>&1 || log "entrypoint: run.sh exited with non-zero status"
  else
    # Either venv python exists but we didn't source, or no venv: try invoking via venv python if present
    if [ -x "$venv_py" ]; then
      log "entrypoint: executing run.sh via venv python wrapper"
      bash -lc "./run.sh" >> "$LOGDIR/run.sh.out" 2>&1 || log "entrypoint: run.sh exited with non-zero status"
    else
      log "entrypoint: executing run.sh without venv"
      bash -lc "./run.sh" >> "$LOGDIR/run.sh.out" 2>&1 || log "entrypoint: run.sh exited with non-zero status"
    fi
  fi

  # After run.sh runs (it should have created uvicorn.pid), wait briefly and check pid/log
  sleep 1
  if [ -f "$LOGDIR/uvicorn.pid" ]; then
    PID="$(cat "$LOGDIR/uvicorn.pid" 2>/dev/null || true)"
    log "entrypoint: uvicorn.pid found -> $PID"
  else
    log "entrypoint: WARNING: uvicorn.pid not found after running run.sh"
  fi

  if [ -f "$LOGDIR/uvicorn.log" ]; then
    log "entrypoint: uvicorn.log exists, tailing it now"
    # tail updates live; also show entrypoint log alongside
    exec tail -n +1 -f "$LOGDIR/uvicorn.log" "$ENTRYLOG"
  else
    log "entrypoint: uvicorn.log does not exist yet; tailing run.sh.out and entrypoint.log"
    exec tail -n +1 -f "$LOGDIR/run.sh.out" "$ENTRYLOG"
  fi

else
  log "entrypoint: run.sh not found or not executable in $WORKDIR; nothing started"
  log "entrypoint: tailing entrypoint.log to keep container alive"
  exec tail -n +1 -f "$ENTRYLOG"
fi
