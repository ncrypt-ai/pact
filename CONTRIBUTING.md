# Contributing

## Development setup

Install the locked development environment:

```bash
uv sync --locked
```

## Quality checks

Run all checks before opening a pull request:

```bash
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run coverage run -m pytest
uv run coverage report
uv run sphinx-build -W -b html docs docs/_build/html
uv build
```

## Changes

- Add tests for behavior changes.
- Keep type annotations accurate.
- Update documentation for public API changes.
- Add user-visible changes to the Unreleased section of `CHANGELOG.md`.
- Do not commit generated files, virtual environments, or credentials.

## Commits and pull requests

Keep commits focused and describe the behavior and rationale in the pull
request. All continuous-integration checks must pass before merge.
