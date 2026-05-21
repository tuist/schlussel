# shellcheck shell=bash

Describe 'schlussel refresh locking'
  BeforeEach 'setup_workspace'
  BeforeEach 'start_oauth_server'
  BeforeEach 'write_local_formula'
  AfterEach 'cleanup_workspace'

  seed_device_code_token() {
    schlussel run local \
      --formula-json "$FORMULA_JSON" \
      --method device_code \
      --identity personal \
      --open-browser false \
      --json >"$WORKSPACE/run.out" 2>"$WORKSPACE/run.err" &
    run_pid=$!

    wait_for_log_line "$WORKSPACE/run.err" 'And enter code:' 10 || return 1
    user_code="$(extract_suffix "$WORKSPACE/run.err" 'And enter code: ')"
    approve_device_code "$user_code" || return 1
    wait "$run_pid" || return 1
  }

  run_parallel_refresh() {
    seed_device_code_token || return 1

    schlussel token get \
      --formula local \
      --formula-json "$FORMULA_JSON" \
      --method device_code \
      --identity personal \
      --json >"$WORKSPACE/token-1.out" &
    first_pid=$!

    schlussel token get \
      --formula local \
      --formula-json "$FORMULA_JSON" \
      --method device_code \
      --identity personal \
      --json >"$WORKSPACE/token-2.out" &
    second_pid=$!

    wait "$first_pid" || return 1
    wait "$second_pid" || return 1
    fetch_oauth_stats >"$WORKSPACE/stats.json"
  }

  It 'refreshes at most once when two processes request the same expiring token'
    When call run_parallel_refresh
    The status should be success
    The contents of file "$WORKSPACE/token-1.out" should include 'refreshed-refresh-device-1'
    The contents of file "$WORKSPACE/token-2.out" should include 'refreshed-refresh-device-1'
    The contents of file "$WORKSPACE/stats.json" should include '"refreshes":1'
  End
End
