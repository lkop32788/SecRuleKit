# Contributing to SecRuleKit

Thank you for your interest in contributing! This document covers how to report bugs, propose features, and submit pull requests.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Security Issues

**Do not open public issues for security vulnerabilities.** Follow the process in [SECURITY.md](SECURITY.md).

## How to Contribute

### Reporting Bugs

Before filing a bug report, please search existing issues. When opening a new issue, include:

- SecRuleKit version (`secrulekit --version`)
- Python version and OS
- Minimal reproduction case (rule file snippet if applicable)
- Expected vs actual behavior
- Full traceback if available

### Suggesting Features

Open a GitHub Issue with the `enhancement` label. Describe:

- The use case / problem being solved
- Proposed API or CLI interface
- Any alternative approaches you considered

### Pull Requests

1. **Fork** the repository and create a branch from `main`
2. **Install** development dependencies: `pip install -e ".[dev]"`
3. **Write tests** for any new functionality
4. **Run the test suite**: `pytest tests/ -v`
5. **Run linting**: `ruff check secrulekit/ && mypy secrulekit/`
6. **Update docs** if you changed public API
7. **Open the PR** against `main`, filling in the pull request template

#### Branch naming

| Type     | Pattern                 |
|----------|-------------------------|
| Feature  | `feat/short-description`|
| Bug fix  | `fix/short-description` |
| Docs     | `docs/short-description`|
| Refactor | `refactor/...`          |

#### Commit style

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(sigma): add QRadar AQL conversion target
fix(yara): handle multi-line string definitions with hex jumps
docs: update CLI reference for --strict flag
```

## Development Setup

```bash
git clone https://github.com/lkop32788/SecRuleKit.git
cd secrulekit
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=secrulekit

# Run linting
ruff check secrulekit/
mypy secrulekit/
```

## Adding a New Parser

1. Create `secrulekit/parsers/<format>_parser.py`
2. Subclass `BaseParser` from `secrulekit.parsers.base`
3. Implement `parse_file()`, `parse_string()`, and `parse_directory()`
4. Add format detection in `secrulekit/utils/helpers.py`
5. Register in `secrulekit/__init__.py`
6. Add tests in `tests/test_parsers.py`
7. Add example rules in `rules/<format>/`

## Adding a New Conversion Target

1. Add a method `to_<target>(self, rule: SigmaRule) -> str` in `secrulekit/converters/converter.py`
2. Register the target string in `SUPPORTED_TARGETS`
3. Add CLI mapping in `secrulekit/cli.py`
4. Add tests in `tests/test_converters.py`

## Review Process

All PRs require:
- At least one approving review from a maintainer
- CI passing (lint + tests)
- No unresolved review comments

Security-sensitive changes (parsers, file I/O, subprocess calls) require review from the **security maintainer** ([@lkop32788](https://github.com/lkop32788)).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
