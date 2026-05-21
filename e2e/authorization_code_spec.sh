# shellcheck shell=bash

Describe 'schlussel authorization code flow'
  BeforeEach 'setup_workspace'
  BeforeEach 'start_oauth_server'
  BeforeEach 'write_local_formula'
  AfterEach 'cleanup_workspace'

  run_authorization_code_flow() {
    schlussel run local \
      --formula-json "$FORMULA_JSON" \
      --method authorization_code \
      --identity personal \
      --open-browser false \
      --json >"$WORKSPACE/run.out" 2>"$WORKSPACE/run.err" &
    run_pid=$!

    wait_for_log_line "$WORKSPACE/run.err" 'Visit the following URL to authorize:' 10 || return 1
    authorize_url="$(grep '^http' "$WORKSPACE/run.err" | tail -n 1)"
    follow_authorize_url "$authorize_url" || return 1

    wait "$run_pid" || return 1
  }

  It 'completes a real authorization code flow through the local callback server'
    When call run_authorization_code_flow
    The status should be success
    The contents of file "$WORKSPACE/run.err" should include 'Visit the following URL to authorize:'
    The contents of file "$WORKSPACE/run.out" should include 'auth-access-code-1'
  End
End
