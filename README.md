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
- `LIBRARIES_IO_API_KEY` for Libraries.io enrichment and dependency graph expansion.
- `NVD_API_KEY` for faster NVD enrichment.
- Optional `GITHUB_TOKEN` for higher GitHub API limits.

Install gems:

```bash
bin/setup
```

The executable isolates gems under `.bundle/gems/<ruby-version>-<ruby-arch>` so
native extensions from another Ruby build in `~/.gem` cannot be loaded by
accident. Run `bin/setup` once for each Ruby build you use, for example after
switching between a Nix-provided Ruby and a locally installed Ruby.

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
LIBRARIES_IO_API_KEY=... bin/dependency-risk scan \
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
