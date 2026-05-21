# shellcheck shell=bash

Describe 'schlussel device code flow'
  BeforeEach 'setup_workspace'
  BeforeEach 'start_oauth_server'
  BeforeEach 'write_local_formula'
  AfterEach 'cleanup_workspace'

  run_device_flow_and_refresh() {
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

    schlussel token get \
      --formula local \
      --formula-json "$FORMULA_JSON" \
      --method device_code \
      --identity personal \
      --json >"$WORKSPACE/token.out"
  }

  It 'completes a real device code flow and refreshes the stored token'
    When call run_device_flow_and_refresh
    The status should be success
    The contents of file "$WORKSPACE/run.err" should include 'To authorize, visit:'
    The contents of file "$WORKSPACE/run.out" should include 'device-access-device-1'
    The contents of file "$WORKSPACE/token.out" should include 'refreshed-refresh-device-1'
  End
End
