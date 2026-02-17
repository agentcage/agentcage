# Contributing to agentcage

## Development Setup

```bash
git clone https://github.com/agentcage/agentcage.git
cd agentcage
uv sync --dev
```

## Running Tests

```bash
uv run pytest
```

## Making Changes

1. Fork the repository and create a feature branch.
2. Make your changes and add tests where appropriate.
3. Run `uv run pytest` and ensure all tests pass.
4. Submit a pull request with a clear description of what changed and why.

## Code Style

- Follow existing patterns in the codebase.
- Keep changes focused — one concern per PR.

## Security Issues

Please **do not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
