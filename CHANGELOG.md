# Changelog

All notable changes to SecRuleKit are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). SecRuleKit uses [Semantic Versioning](https://semver.org/).

---

## [1.2.0] — 2026-09-15

### Added
- `secrulekit dedup` command: fingerprint-based deduplication for YARA and Sigma rule sets
- QRadar AQL conversion target for Sigma rules (`--to qradar`)
- `--strict` flag for `validate`: treats warnings as errors (useful in CI)
- HTML audit report template with severity breakdown chart
- MITRE ATT&CK tactic/technique tagging in rule metadata output

### Changed
- Sigma parser now handles `detection.condition` with `1 of` / `all of` quantifiers
- YARA parser performance improved ~3× for directories with 10k+ rules (lazy AST construction)
- CLI progress bar added for batch operations on directories

### Fixed
- YARA parser: incorrect line numbers reported in error messages for multi-file parsing (#34)
- Sigma converter: `keywords` field not included in Splunk output when no `selection` block present (#41)
- HTML reporter: XSS via unsanitized rule names in generated report (#47) — thanks @sec_researcher_x

### Security
- Fixed potential ReDoS in Suricata parser's `content` field regex (#52)
  Credit: responsible disclosure by @netblue_labs

---

## [1.1.2] — 2026-07-03

### Fixed
- Path traversal in `parse_directory()` when symlinks point outside the target directory (#29)
  Credit: reported by @vulnfinder via private advisory
- Sigma parser crash on empty `logsource` block (#31)

---

## [1.1.1] — 2026-06-10

### Fixed
- `secrulekit info` crashes when ATT&CK technique ID not found in local mapping table (#26)
- JSON reporter emitting non-UTF-8 bytes for rules with binary strings (#28)

---

## [1.1.0] — 2026-05-20

### Added
- Suricata rule parser and validator
- Snort rule parser (validate-only; conversion not yet supported)
- `secrulekit stats` command: rule counts by format, severity, and ATT&CK tactic
- Python API: `RuleConverter.to_elastic()` for ElasticSearch Query DSL output
- `--recursive` / `-r` flag for all commands that accept a directory

### Changed
- `RuleValidator` now returns structured `ValidationResult` objects instead of plain dicts
- Minimum Python version bumped from 3.7 to 3.8

---

## [1.0.0] — 2026-04-01

### Added
- YARA rule parser with full syntax validation
- Sigma rule parser (YAML-based)
- Sigma-to-Splunk SPL conversion
- `secrulekit validate` and `secrulekit convert` CLI commands
- JSON reporter
- MIT License

---

[Unreleased]: https://github.com/lkop32788/SecRuleKit/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/lkop32788/SecRuleKit/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/lkop32788/SecRuleKit/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/lkop32788/SecRuleKit/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/lkop32788/SecRuleKit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/lkop32788/SecRuleKit/releases/tag/v1.0.0
