# Schlussel

Cross-platform OAuth 2.0 runtime and library for command-line applications and agent workflows.

Schlussel handles PKCE, Device Code Flow, callback-based authorization, token storage, formula-driven provider definitions, and refresh coordination so applications can integrate OAuth without rebuilding the plumbing every time.

## Features

- Rust workspace with a reusable library crate and CLI crate
- C-compatible FFI surface plus a native Swift XCFramework API
- Device Code Flow and Authorization Code Flow with PKCE
- Dynamic client registration support
- Formula-driven provider definitions bundled from `src/formulas/*.json`
- Persistent token storage with cross-process-safe refresh locking
- ShellSpec end-to-end coverage against a local OAuth test server

## CLI Usage

Authenticate with a provider:

```bash
schlussel run github --method device_code --identity personal
```

Get the access token:

```bash
TOKEN=$(schlussel token get --formula github --method device_code --identity personal)
curl -H "Authorization: Bearer $TOKEN" https://api.github.com/user
```

Inspect or delete stored tokens:

```bash
schlussel token list
schlussel token list --formula github
schlussel token delete --formula github --method device_code --identity personal
```

Emit a resolved script document for an agent workflow:

```bash
schlussel script github --method device_code --resolve
```

## Custom Formulas

Load a formula file directly:

```bash
schlussel run local --formula-json ./formula.json --method authorization_code
```

If you later query or refresh tokens created from a custom formula, pass the same file again:

```bash
schlussel token get --formula local --formula-json ./formula.json --method authorization_code
```

## Swift Integration

Each GitHub release publishes a signed macOS `Schlussel.xcframework.zip` with a native Swift module named `Schlussel`:

```swift
import Schlussel

let client = try Client(
    formula: .builtin("github"),
    method: "device_code",
    appName: "MyApp"
)
```

Use `.builtin("<id>")` for bundled formulas or `.file(atPath: "/path/to/formula.json")` for a custom formula file. Pass `clientID` and `clientSecret` when the selected formula does not include a default OAuth client. `appName` enables secure token persistence; omit it to keep tokens in memory.

You can also inspect bundled formulas from Swift before creating a client:

```swift
let formulas = try Formula.builtins()
let github = try Formula.builtin("github").metadata()

print(formulas.map(\.id))
print(github.methods.map(\.name))
```

Preset helpers like `Client(githubClientID:...)` and `Client(googleClientID:...)` remain available when you do not need formula-driven setup. The framework wraps the Rust runtime behind Swift types like `Client`, `Token`, `RegistrationClient`, and `RegistrationResponse`. The underlying C header remains available for other native hosts.

## Development

Build the workspace:

```bash
mise exec -- cargo build --workspace
```

Run the test suite:

```bash
mise exec -- cargo test --workspace
shellspec
```

Check formatting:

```bash
mise exec -- cargo fmt --check
```

Add a new formula:

1. Create or update a JSON file in `src/formulas/`.
2. Run `mise exec -- cargo test --workspace`.
3. Run `shellspec` if the change affects CLI auth flows or refresh behavior.

## License

[MIT](LICENSE)
