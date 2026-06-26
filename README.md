# Dependency Risk Analyzer

Dependency Risk Analyzer is the merged successor to FruitRollup and Dependency Validator.
It combines SBOM ingestion, vulnerability matching, direct dependency attribution,
license policy checks, optional ecosystem enrichment, and deterministic risk scoring.

## What It Does

- Reads an existing Syft JSON SBOM or runs Syft against a directory.
- Reads an existing Grype JSON result or runs Grype against the target.
- Detects direct dependencies from `Gemfile`, `package.json`, and `requirements.txt`.
- Optionally expands transitive dependency paths through Libraries.io.
- Applies local license policy files from `licenses/`.
- Optionally enriches package metadata from Libraries.io, GitHub, and NVD.
- Emits terminal, JSON, and CSV reports from one canonical result model.

## Requirements

- Ruby 4.0.5.
- Bundler 4.0.15.
- Syft for directory SBOM generation.
- Grype for local vulnerability matching.
- Optional `op` CLI for 1Password-managed API keys.
- Optional `gh` CLI for GitHub authentication.

## Setup

### 1. Install command line dependencies

On macOS with Homebrew:

```bash
brew install syft grype gh 1password-cli
```

Install Ruby 4.0.5 with your Ruby version manager of choice, then confirm the
active Ruby and Bundler match this project:

```bash
ruby -v
bundle -v
```

Expected versions:

```text
ruby 4.0.5
Bundler version 4.0.15
```

Install gems:

```bash
bin/setup
```

The executable isolates gems under `.bundle/gems/<ruby-version>-<ruby-arch>` so
native extensions from another Ruby build in `~/.gem` cannot be loaded by
accident. Run `bin/setup` once for each Ruby build you use, for example after
switching between a Nix-provided Ruby and a locally installed Ruby.

Confirm the scanner tools are available:

```bash
syft version
grype version
bin/dependency-risk --help
```

### 2. Create API keys

Remote enrichment is optional, but these keys make the tool much more useful:

- Libraries.io: required for `--enrich` package metadata and `--scan-depth`
  dependency graph expansion. Create or find your API key from your Libraries.io
  account/API page: <https://libraries.io/api>.
- NVD: optional for `--include-nvd`. Request a key from NVD:
  <https://nvd.nist.gov/developers/request-an-api-key>.
- GitHub: optional, but recommended for GitHub repository health enrichment.
  The easiest setup is `gh auth login`; the tool will use `gh auth token` when
  `GITHUB_TOKEN` is not set. You can also create a personal access token from
  GitHub Developer Settings and expose it as `GITHUB_TOKEN`:
  <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens>.

Recommended GitHub setup:

```bash
gh auth login
gh auth status
```

### 3. Store API keys in 1Password

The tool can read API keys directly from environment variables, or from
1Password secret references with the `op` CLI. Environment variables always win.

Credential lookup order:

```text
Libraries.io:
  LIBRARIES_IO_API_KEY
  LIBRARIES_IO_API_KEY_OP_PATH or LIBRARIES_IO_API_KEY_OP_REF
  op://Personal/Libraries.ioAPIToken/credential
  op://Private/Libraries.ioAPIToken/credential
  op://Employee/Libraries.ioAPIToken/credential

NVD:
  NVD_API_KEY
  NVD_API_KEY_OP_PATH or NVD_API_KEY_OP_REF
  op://Personal/NVDAPIKey/credential
  op://Private/NVDAPIKey/credential

GitHub:
  GITHUB_TOKEN
  GITHUB_TOKEN_OP_PATH or GITHUB_TOKEN_OP_REF
  gh auth token
```

Safer 1Password app setup:

1. Open 1Password.
2. Create an `API Credential` item in the `Personal` vault.
3. For Libraries.io, name the item `Libraries.ioAPIToken`.
4. Add a concealed field named `credential` containing the Libraries.io API key.
5. For NVD, name the item `NVDAPIKey` and add the same concealed `credential`
   field containing the NVD API key.
6. If you prefer 1Password over `gh auth token` for GitHub, create an item named
   `GitHubToken` with a concealed `credential` field, then export
   `GITHUB_TOKEN_OP_PATH` as shown below.

CLI convenience setup:

```bash
read -rsp "Libraries.io API key: " LIBRARIES_IO_API_KEY; echo
op item create \
  --category "API Credential" \
  --vault Personal \
  --title "Libraries.ioAPIToken" \
  "credential[concealed]=$LIBRARIES_IO_API_KEY"
unset LIBRARIES_IO_API_KEY

read -rsp "NVD API key: " NVD_API_KEY; echo
op item create \
  --category "API Credential" \
  --vault Personal \
  --title "NVDAPIKey" \
  "credential[concealed]=$NVD_API_KEY"
unset NVD_API_KEY
```

Assignment statements can be stored in shell history on some systems. Use the
1Password app or a JSON template from `op item template get "API Credential"` if
you need stricter local secret handling. See the 1Password CLI item creation and
secret reference docs:
<https://developer.1password.com/docs/cli/create-item/> and
<https://developer.1password.com/docs/cli/secret-references/>.

Validate the expected secret references:

```bash
op read op://Personal/Libraries.ioAPIToken/credential >/dev/null && echo "Libraries.io key loaded"
op read op://Personal/NVDAPIKey/credential >/dev/null && echo "NVD key loaded"
```

If your item or vault names differ, set explicit secret references in your shell
profile:

```bash
export LIBRARIES_IO_API_KEY_OP_PATH="op://Personal/Libraries.ioAPIToken/credential"
export NVD_API_KEY_OP_PATH="op://Personal/NVDAPIKey/credential"
export GITHUB_TOKEN_OP_PATH="op://Personal/GitHubToken/credential"
```

Direct environment variables also work:

```bash
export LIBRARIES_IO_API_KEY="$(op read op://Personal/Libraries.ioAPIToken/credential)"
export NVD_API_KEY="$(op read op://Personal/NVDAPIKey/credential)"
```

### 4. Verify enriched scanning

Run a local scan without remote enrichment:

```bash
bin/dependency-risk scan --directory .
```

Run a full enriched scan:

```bash
bin/dependency-risk scan \
  --directory . \
  --scan-depth 2 \
  --enrich \
  --include-nvd
```

With working credentials, the terminal report should include Libraries.io risk
factors when relevant and a `GitHub Repository Health` table with open issues,
open pull requests, most recent commit date, and commit age.

### Troubleshooting

- If you see `Libraries.io enrichment skipped: LIBRARIES_IO_API_KEY is not
  configured`, run `op read op://Personal/Libraries.ioAPIToken/credential`.
  If that succeeds, make sure the `op` CLI is installed and signed in.
- If `op` reports that `Employee` is not a vault, either use the default
  `Personal` item name above or set `LIBRARIES_IO_API_KEY_OP_PATH` to the exact
  secret reference that works in your account.
- If GitHub repository health is missing, run `gh auth status`. Either sign in
  with `gh auth login`, set `GITHUB_TOKEN`, or set `GITHUB_TOKEN_OP_PATH`.
- If native gem loading fails after changing Ruby versions, rerun `bin/setup`
  with the same Ruby that will run `bin/dependency-risk`.

## Usage

Run against a project directory:

```bash
bin/dependency-risk scan --directory .
```

Reuse existing scanner outputs:

```bash
bin/dependency-risk scan \
  --sbom syft.json \
  --grype grype.json \
  --format terminal,json,csv \
  --output dependency-risk-report
```

Include remote enrichment and transitive graph attribution:

```bash
bin/dependency-risk scan \
  --directory . \
  --scan-depth 2 \
  --enrich \
  --include-nvd
```

Analyze one dependency:

```bash
bin/dependency-risk dependency --name rack --type gem --version 2.2.6 --enrich
```

Analyze one CPE through NVD:

```bash
bin/dependency-risk dependency --cpe 'cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*' --include-nvd
```

## Commands

### `scan`

```text
usage: dependency-risk scan [options]
    --directory DIR
    --sbom FILE
    --grype FILE
    --no-grype
    --scan-depth N
    --enrich
    --include-nvd
    --license-dir DIR
    --cache-dir DIR
    --force
    --format terminal,json,csv
    --color auto|always|never
    --output BASE
```

### `dependency`

```text
usage: dependency-risk dependency [options]
    --name NAME
    --type TYPE
    --version VERSION
    --cpe CPE
    --enrich
    --include-nvd
    --license-dir DIR
    --cache-dir DIR
    --force
    --format terminal,json,csv
    --color auto|always|never
    --output BASE
```

## Architecture

```text
SBOM/Syft -> Package model -> Grype/NVD vulnerabilities
                         -> direct dependency detector
                         -> license policy
                         -> Libraries.io/GitHub enrichment
                         -> Libraries.io graph expansion
                         -> risk scorer
                         -> terminal/JSON/CSV reports
```

The old tools map into the new modules like this:

- FruitRollup's Syft/Grype matching and direct dependency attribution live under
  `DependencyRisk::Sbom`, `DependencyRisk::Scanners`, and `DependencyRisk::Graph`.
- Dependency Validator's Libraries.io, GitHub, NVD, and license policy enrichment live
  under `DependencyRisk::Enrichment` and `DependencyRisk::Policy`.
- Both tools now share one package model and one report writer.

## Development

Run tests:

```bash
bundle exec rake test
```

Run a fixture-backed smoke test:

```bash
bin/dependency-risk scan \
  --sbom test/fixtures/syft.json \
  --grype test/fixtures/grype_matches.json \
  --format terminal,json,csv \
  --output tmp/fixture-report
```
