# Contributing

PACT is security-sensitive software. A good contribution is small enough to
review, tested enough to trust, and documented enough for a new user to
understand.

## Development setup

```bash
uv sync --locked
```

Run checks before opening a pull request:

```bash
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run python -m pytest tests -q
uv run cfn-lint deploy/aws/registry-compute.sam.yaml deploy/aws/gateway-rate-limit.yaml
uv run sphinx-build -W -b html docs docs/_build/html
uv build
```

## What every change needs

- Tests for behavior changes.
- Accurate type annotations.
- Documentation updates for public behavior, APIs, CLI output, deployment, or
  security boundaries.
- Changelog entries for user-visible changes.
- No generated build output, virtual environments, local data directories,
  credentials, private keys, nonces, prompts, provider responses, or raw private
  evidence.

## LLM assistance policy

LLM assistance is allowed. The contributor is still responsible for the design,
code, tests, and claims made in the pull request.

Do:

- review every generated line before committing it
- run the relevant tests and include what passed
- verify security-sensitive claims against the code
- simplify or remove text that sounds more confident than the implementation

Do not submit:

- code submitted without meaningful human review
- untested generated code or generated tests that were not run
- legal, security, or cryptography claims that were not checked against the code
- bulk rewrites that obscure the actual behavior change
- fabricated citations, benchmarks, compatibility statements, or test results

If you used an LLM materially, mention that in the pull request notes. Do not add
an "Authored-by" or "Co-authored-by" trailer for an LLM unless project policy
later requires it.

## Security mindset

Treat these as sensitive by default:

- identity private keys and encrypted identity exports
- local passcodes and recovery files
- device fingerprint source material
- private content nonces
- raw content for private claims
- probe text, prompts, provider responses, and analysis packages
- registry CA private keys and deployment secrets

Prefer explicit failure over silent downgrade. For example, do not fall back to
publishing plaintext, private nonces, raw device identifiers, or unsigned
profile state just to keep a workflow moving.

## Commits and pull requests

Use focused commits with one-line conventional commit messages, for example:

```text
fix(security): require device binding proof for profiles
docs: update release deployment guidance
```

Pull requests should explain:

- what changed
- why it changed
- how it was tested
- any known risk, compatibility issue, or follow-up

All continuous-integration checks must pass before merge.
