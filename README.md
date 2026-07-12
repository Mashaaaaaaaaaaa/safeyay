# safeyay

`safeyay` is a fail-closed security-review wrapper for `yay`. Before yay builds
an AUR package, safeyay sends its PKGBUILD and relevant auxiliary files to a
configurable AI reviewer and reports suspicious behavior for the user to inspect.

Official Arch repository packages are skipped. They are installed as signed,
prebuilt packages and do not execute an AUR PKGBUILD.

> [!WARNING]
> AI review is an additional signal, not a sandbox or a malware guarantee. Models
> can miss attacks and produce false positives. Continue checking source identity,
> signatures, checksums, package comments, and diffs.

## Features

- Reviews every AUR PKGBUILD selected by yay, including AUR dependencies.

- When `ks-aur-scanner` is installed, runs it as an independent first-pass
  scanner before safeyay's LLM review. The LLM review always runs regardless
  of what ks-aur-scanner reports, including on critical findings, since a
  static scanner finding can be a false positive and only the LLM reviews
  full context. Ks-aur-scanner's output is never included in safeyay's model
  prompt, so the two reviewers make independent decisions. Once both results
  are available, safeyay asks for confirmation before continuing, defaulting
  to reject unless both reviewers reported a completely clean result.

- Reviews each package base separately and reports per-package and cumulative
  review time.

- Includes referenced `.install`, patch, diff, shell, JavaScript, configuration,
  desktop, systemd, udev, pacman hook, and ecosystem build-control files.

- Examines npm, Yarn, pnpm, Bun, and Deno manifests, lockfiles, installers, and
  lifecycle hooks when they are available before the build.

- Checks remote patch ownership and flags patches controlled by unknown parties.

- Uses authoritative AUR RPC and GitHub repository metadata for provenance.
  Brave Search with a DuckDuckGo fallback is used only when authoritative sources
  cannot establish an identity.

- Treats package text and search results as untrusted prompt input.

- Requires explicit confirmation before continuing with a suspicious package.

- Fails closed when the reviewer, provenance lookup, or structured response fails.

- Supports local models, cloud APIs, authenticated agent CLIs, and custom commands.

## Requirements

- Arch Linux or an Arch-based system

- `yay`

- Python 3.11 or newer

- At least one configured AI backend

The default backend requires `ollama` and the `qwen3.6:35b-a3b` model.

For defence in depth, optionally install the `ks-aur-scanner` AUR package.
Safeyay detects its `aur-scan` executable automatically; its separate yay
hook or shell integration does not need to be enabled.

## Installation

### Arch package

Clone the repository and build the checksummed package with `makepkg`:

```sh
git clone https://github.com/Mashaaaaaaaaaaa/safeyay.git
cd safeyay
makepkg -si
```

The included [PKGBUILD](PKGBUILD) verifies every packaged source file with
SHA-256 and installs the launcher under `/usr/bin` and the scanner under
`/usr/lib/safeyay`. Review the PKGBUILD before building, as with any AUR-style
package.

### Per-user installation

From this directory:

```sh
./install.sh
```

The install script's default prefix is `~/.local`. Ensure `~/.local/bin` is on
`PATH`.

For the default backend, pull the model once:

```sh
ollama pull qwen3.6:35b-a3b
```

Ollama does not need to be running before safeyay starts. For a loopback Ollama
endpoint, the first review starts `ollama serve` when necessary. Safeyay stops
only the server it started, immediately after the complete review batch. An
already-running Ollama server is reused and left running.

## Usage

Use `safeyay` anywhere you would normally use yay:

```sh
safeyay -S package-name
safeyay -Syu
```

Safeyay forces yay's PKGBUILD edit phase and installs itself as the non-editing
review command. Yay resolves the transaction and invokes the reviewer once with
all selected AUR PKGBUILDs. Safeyay then reviews each package base independently.

When a model reports suspicious behavior, safeyay prints the findings and asks:

```text
Continue with this suspicious package? [y/N]
```

The default is to reject it.

## Configuration

User configuration is read from:

```text
~/.config/safeyay/config.toml
```

An annotated template is available at [config.example.toml](config.example.toml)
and is installed under `/usr/share/doc/safeyay/` by the Arch package or under
`~/.local/share/doc/safeyay/` by the per-user installer.

Common settings are:

```toml
backend = "ollama"
model = "qwen3.6:35b-a3b"
base_url = "http://127.0.0.1:11434"
timeout = 600
temperature = 0.1
max_tokens = 2048
```

Per-run environment overrides:

| Variable | Purpose |
| --- | --- |
| `SAFEYAY_CONFIG` | Use a different TOML configuration file |
| `SAFEYAY_BACKEND` | Override the configured backend |
| `SAFEYAY_MODEL` | Override the model identifier |
| `SAFEYAY_BASE_URL` | Override the API or Ollama base URL |
| `SAFEYAY_WEB_SEARCH=0` | Disable all provenance network lookups |
| `SAFEYAY_NONINTERACTIVE=1` | Reject suspicious results without prompting |

The older `SAFEYAY_OLLAMA_HOST` override remains accepted for Ollama, but
`SAFEYAY_BASE_URL` is preferred.

## AI backends

### Ollama

Ollama supports arbitrary installed local models and remote Ollama servers:

```toml
backend = "ollama"
model = "qwen3.6:35b-a3b"
base_url = "http://127.0.0.1:11434"
context_length = 16384
max_tokens = 2048
think = false
```

Automatic server startup is limited to loopback endpoints. An unreachable remote
Ollama endpoint fails closed and never causes an unrelated local server to start.

### OpenAI

```toml
backend = "openai"
model = "gpt-5.6-terra"
api_key_env = "OPENAI_API_KEY"
```

```sh
export OPENAI_API_KEY='...'
```

This backend uses the Responses API with strict structured output.

### Anthropic

```toml
backend = "anthropic"
model = "claude-sonnet-5"
api_key_env = "ANTHROPIC_API_KEY"
```

```sh
export ANTHROPIC_API_KEY='...'
```

The default Anthropic model is Claude Sonnet 5. This backend uses the Messages
API with `output_config.format` structured output.

### Google Gemini

```toml
backend = "gemini"
model = "gemini-2.5-pro"
api_key_env = "GEMINI_API_KEY"
```

```sh
export GEMINI_API_KEY='...'
```

### OpenAI-compatible endpoints

Use this backend for local vLLM or llama.cpp servers and compatible services such
as Groq, Mistral, OpenRouter, Together, and xAI:

```toml
backend = "openai_compatible"
model = "provider-model-id"
base_url = "https://provider.example/v1"
api_key_env = "PROVIDER_API_KEY"
api_key_header = "Authorization"
api_key_prefix = "Bearer "
```

Omit `api_key_env` for an unauthenticated local endpoint. Gateways with custom
authentication or URL shapes can set `api_key_header`, `api_key_prefix`, and an
exact `endpoint`, including query parameters:

```toml
endpoint = "https://gateway.example/deployment/chat/completions?api-version=..."
api_key_header = "api-key"
api_key_prefix = ""
```

### Codex CLI

```toml
backend = "codex"
model = "gpt-5.6-terra"
```

Safeyay uses the existing Codex authentication. Each review is ephemeral,
read-only, and isolated in an empty temporary directory. Project/user instructions
and execution rules are not loaded.

### Claude Code

```toml
backend = "claude"
model = "sonnet"
```

Safeyay uses the existing Claude Code authentication. Sessions are not persisted,
tools and slash commands are disabled, MCP configuration is empty, and reviews run
in an empty temporary directory.

### Custom command

Any non-interactive reviewer can be used with an argv array:

```toml
backend = "command"
command = ["my-review-agent", "--format", "json"]
timeout = 600
```

The command receives the complete review prompt on standard input. It must write
one JSON object matching safeyay's review schema to standard output. Commands are
executed directly without a shell and from an empty temporary directory.

## Credentials and privacy

API keys are not stored in the TOML configuration. `api_key_env` names the
environment variable containing the key. Safeyay does not write request headers
to evaluation logs.

Remote API, remote Ollama, Codex, Claude Code, and remote-capable custom backends
transmit PKGBUILD and auxiliary-file contents to their configured provider. Local
Ollama and local OpenAI-compatible endpoints keep model inference local.

By default, provenance checking also contacts the AUR RPC, GitHub API, and—only
when needed—public search engines. Use the following for a fully offline review:

```sh
SAFEYAY_WEB_SEARCH=0 safeyay -S package-name
```

Offline mode removes external provenance evidence and may reduce source-identity
accuracy.

## What is reviewed

Safeyay includes text files that are referenced by the PKGBUILD and available in
yay's build directory before compilation. This includes:

- PKGBUILDs and adjacent `.install` scripts

- `.patch` and `.diff` files

- Shell, Python, Perl, Ruby, and JavaScript installers

- `package.json`, npm lockfiles, and npm lifecycle hooks

- Yarn, pnpm, Bun, and Deno manifests and lockfiles

- Make, CMake, and Meson control files

- `.conf`, `.desktop`, systemd unit, udev rule, and pacman hook files

Files contained only inside a remote archive are not available during yay's
pre-build editor phase. The reviewer is instructed to flag important visibility
gaps, but safeyay does not download or extract untrusted source archives itself.

## Provenance checks

Safeyay derives package identity from the PKGBUILD without evaluating shell code.
It safely expands simple literal variables to resolve common source forms such as
`$pkgname` and `$_projectname`.

Evidence is collected in this order:

1. AUR RPC metadata for package identity, maintainer, version, and declared URL.
2. GitHub's repository API for sanitized `github.com/<owner>/<repository>` paths.
3. Brave Search with a DuckDuckGo fallback only when authoritative sources cannot
   establish provenance.

Search snippets are treated as untrusted and are never considered authoritative
on their own. Safeyay does not let the model request arbitrary URLs.

## Evaluation and tests

Run the unit suite:

```sh
python3 -m unittest -v
```

Run all active model fixtures:

```sh
./run_safeyay_evals.py
```

Or select specific fixture directories:

```sh
./run_safeyay_evals.py brave-bin-clean brave-bin-tampered
```

Each run is stored under `eval/results/<timestamp>/` with:

- The exact files shown to the model

- Provenance evidence

- Raw provider output

- Parsed review JSON

- Console output and a result manifest

Fixture directory labels such as `clean` and `tampered` are not exposed to the
model.

## Limitations

- AI models can miss malicious behavior and hallucinate findings.

- A clean PKGBUILD can download malicious upstream source code that is not visible
  during pre-build review.

- Correct checksums establish content consistency, not benign intent.

- Search indexes, repository metadata, maintainer accounts, and upstream projects
  can themselves be compromised.

- Binary packages cannot be meaningfully audited from packaging instructions
  alone.

- AUR helpers, including yay, are not official Arch Linux package-management
  interfaces.

Safeyay is intended as defense in depth. When risk matters, inspect changes,
verify upstream ownership, and build in an isolated environment.

## License

Safeyay is licensed under the [GNU General Public License version 3](LICENSE),
or (at your option) any later version (`GPL-3.0-or-later`).
