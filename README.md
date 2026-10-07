# SecRuleKit

[![PyPI version](https://badge.fury.io/py/secrulekit.svg)](https://badge.fury.io/py/secrulekit)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/lkop32788/SecRuleKit/actions/workflows/ci.yml/badge.svg)](https://github.com/lkop32788/SecRuleKit/actions/workflows/ci.yml)

A Python toolkit for parsing, validating, converting, and managing security detection rules — supporting **YARA**, **Sigma**, and **Suricata/Snort** formats.

Security teams and researchers rely on SecRuleKit to validate rule syntax before deployment, convert rules across platforms, deduplicate rule libraries, and generate audit-ready reports.

## Features

- **Multi-format support** — Parse and validate YARA, Sigma, and Suricata rules from files, directories, or strings
- **Format conversion** — Convert Sigma rules to YARA skeleton, Suricata, ElasticSearch Query DSL, and Splunk SPL
- **Rule deduplication** — Fingerprint and detect duplicate/near-duplicate rules across large rule sets
- **Metadata enrichment** — Tag rules with MITRE ATT&CK tactics/techniques, severity, and platform
- **Batch reporting** — Export validation results as JSON, CSV, or HTML audit reports
- **CLI interface** — Full-featured command-line tool for CI/CD pipeline integration
- **Python API** — Clean library API for embedding in security tooling

## Installation

```bash
pip install secrulekit
```

Or install from source:

```bash
git clone https://github.com/lkop32788/SecRuleKit.git
cd secrulekit
pip install -e ".[dev]"
```

## Quick Start

### CLI

```bash
# Validate a directory of YARA rules
secrulekit validate --format yara ./rules/yara/

# Validate Sigma rules and output JSON report
secrulekit validate --format sigma ./rules/sigma/ --report report.json

# Convert Sigma rule to Splunk SPL
secrulekit convert --to splunk ./rules/sigma/lateral_movement.yml

# Deduplicate a large rule set
secrulekit dedup --format yara ./rules/ --output ./rules_deduped/

# Show rule metadata and ATT&CK mapping
secrulekit info ./rules/sigma/t1059_powershell.yml
```

### Python API

```python
from secrulekit import YaraParser, SigmaParser, RuleValidator, RuleConverter

# Parse and validate YARA rules
parser = YaraParser()
rules = parser.parse_directory("./rules/yara/")

validator = RuleValidator()
results = validator.validate_batch(rules)
print(f"Valid: {results.valid_count}, Errors: {results.error_count}")

# Convert Sigma to Splunk
converter = RuleConverter()
sigma = SigmaParser().parse_file("./rules/sigma/t1059.yml")
splunk_query = converter.to_splunk(sigma)
print(splunk_query)

# Generate HTML report
from secrulekit.reporters import HtmlReporter
HtmlReporter().generate(results, output="audit_report.html")
```

## Supported Rule Formats

| Format     | Parse | Validate | Convert From | Convert To |
|------------|-------|----------|--------------|------------|
| YARA       | ✅    | ✅       | —            | —          |
| Sigma      | ✅    | ✅       | ✅           | ✅         |
| Suricata   | ✅    | ✅       | —            | ✅         |
| Snort      | ✅    | ✅       | —            | —          |

## Sigma Conversion Targets

| Target              | Flag          |
|---------------------|---------------|
| Splunk SPL          | `--to splunk` |
| ElasticSearch Query | `--to elastic`|
| YARA-L              | `--to yaral`  |
| QRadar AQL          | `--to qradar` |
| Suricata            | `--to suricata`|

## CLI Reference

```
Usage: secrulekit [OPTIONS] COMMAND [ARGS]...

Commands:
  validate   Validate rule files for syntax and semantic errors
  convert    Convert rules between formats
  dedup      Find and remove duplicate rules
  info       Display rule metadata and ATT&CK mapping
  report     Generate audit reports from cached results
  stats      Show statistics for a rule collection

Options:
  --version  Show version
  --help     Show help
```

### `secrulekit validate`

```
Options:
  -f, --format [yara|sigma|suricata|snort|auto]
                  Rule format (default: auto-detect)
  -r, --recursive  Recurse into subdirectories
  --strict         Treat warnings as errors
  --report FILE    Write JSON/HTML report to FILE
  --no-color       Disable colored output
```

### `secrulekit convert`

```
Options:
  --to [splunk|elastic|yaral|qradar|suricata]
                  Target format (required)
  -o, --output FILE   Write output to file (default: stdout)
  --batch          Convert all .yml files in directory
```

## Project Structure

```
secrulekit/
├── secrulekit/
│   ├── parsers/
│   │   ├── yara_parser.py       # YARA rule parser
│   │   ├── sigma_parser.py      # Sigma rule parser
│   │   └── suricata_parser.py   # Suricata/Snort parser
│   ├── validators/
│   │   └── rule_validator.py    # Multi-format validator
│   ├── converters/
│   │   └── converter.py         # Format conversion engine
│   ├── reporters/
│   │   ├── json_reporter.py     # JSON output
│   │   └── html_reporter.py     # HTML audit report
│   ├── utils/
│   │   └── helpers.py           # Fingerprinting, dedup, ATT&CK mapping
│   └── cli.py                   # CLI entry point
├── tests/
├── rules/                       # Example rule sets
│   ├── yara/
│   └── sigma/
└── docs/
```

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

To report a security vulnerability in SecRuleKit itself (e.g., rule parsing that could cause denial-of-service or arbitrary code execution via crafted rule files), please follow the process in [SECURITY.md](SECURITY.md).

**Security Maintainer:** [@lkop32788](https://github.com/lkop32788)

## License

MIT © 2026 Cherno.x — see [LICENSE](LICENSE).
