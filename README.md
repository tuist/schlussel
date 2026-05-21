# Schlussel

Authentication runtime for agents and CLI applications.

Schlussel wraps OAuth device-code and authorization-code flows in formula-driven CLI commands so agents can authenticate without asking users to paste tokens by hand.

## Features

- Formula-driven provider definitions in `src/formulas/*.json`
- Device code and authorization code with PKCE
- Persistent token storage, token listing, and token deletion
- Automatic token refresh with cross-process locking
- Rust workspace with unit tests and ShellSpec e2e coverage

## Installation

Install via [mise](https://mise.jdx.dev/):

```bash
mise use -g github:pepicrft/schlussel
```

## Usage

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

## Development

Build the workspace:

```bash
mise exec -- cargo build --workspace
```

Run the test suite:

```bash
mise exec -- cargo test
shellspec
```

Check formatting:

```bash
mise exec -- cargo fmt --check
```

Add a new formula:

1. Create a JSON file in `src/formulas/`.
2. Run `mise exec -- cargo test`.
3. Run `pnpm --dir website run build:formulas` if the website output depends on the new formula.

## Documentation

- Docs: https://schlussel.me/docs
- Skill page: https://schlussel.me/skill.md

## License

[MIT](LICENSE)
