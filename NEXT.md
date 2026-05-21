# Next: Schlussel

Schlussel now centers on a smaller surface area: OAuth flows, token storage,
refresh coordination, and the FFI/runtime layers around them.

## Focus Areas

### 1. Provider Coverage

- Add or harden first-party OAuth presets for major providers
- Improve self-hosted configuration helpers where endpoint construction is repetitive
- Expand preset-specific tests so endpoint regressions are caught early

### 2. Token Storage Ergonomics

- Improve CLI token inspection and filtering
- Consider metadata support for stored sessions without weakening portability
- Make refresh and storage failure modes easier to diagnose from logs and exit codes

### 3. Runtime Robustness

- Strengthen cross-process refresh coordination tests
- Add more end-to-end coverage for callback and device flows
- Review platform-specific storage behavior for edge cases and cleanup failures

### 4. FFI and Integration Quality

- Keep the C API narrow and stable
- Improve Swift and Objective-C integration examples
- Audit memory ownership and error propagation in the FFI layer

### 5. Documentation

- Keep the README focused on the library and the token CLI
- Expand source doc comments so `cargo doc --workspace` is enough for day-to-day reference
- Add short troubleshooting guidance for common OAuth and storage failures

## Open Questions

- Should stored session metadata include enough context to support safer CLI refresh operations later?
- Where do provider presets stop being helpful and explicit `OAuthConfig.custom` should take over?
- What additional integration tests are worth the runtime cost in CI?
