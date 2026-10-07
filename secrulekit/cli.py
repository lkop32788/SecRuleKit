"""SecRuleKit CLI — entry point."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box

from secrulekit import __version__
from secrulekit.validators.rule_validator import RuleValidator, Severity
from secrulekit.converters.converter import RuleConverter, SUPPORTED_TARGETS, ConversionError
from secrulekit.parsers.sigma_parser import SigmaParser, SigmaParseError
from secrulekit.reporters.json_reporter import JsonReporter
from secrulekit.reporters.html_reporter import HtmlReporter

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.version_option(__version__, prog_name="secrulekit")
def main() -> None:
    """SecRuleKit — security detection rule parser, validator, and converter."""


# ------------------------------------------------------------------ #
#  validate
# ------------------------------------------------------------------ #

@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-f", "--format", "fmt",
              type=click.Choice(["yara", "sigma", "suricata", "snort", "auto"], case_sensitive=False),
              default="auto", show_default=True, help="Rule format")
@click.option("-r", "--recursive", is_flag=True, default=True, show_default=True,
              help="Recurse into subdirectories")
@click.option("--strict", is_flag=True, help="Treat warnings as errors")
@click.option("--report", "report_file", type=click.Path(), default=None,
              help="Write report to FILE (.json or .html)")
@click.option("--no-color", is_flag=True, help="Disable colored output")
def validate(path: str, fmt: str, recursive: bool, strict: bool, report_file: str | None, no_color: bool) -> None:
    """Validate rule files for syntax and semantic errors."""
    if no_color:
        console._force_terminal = False  # type: ignore[attr-defined]

    validator = RuleValidator(strict=strict)
    result = validator.validate_path(Path(path), fmt=fmt)

    # Print findings table
    table = Table(box=box.SIMPLE_HEAD, show_edge=False)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Code", width=10)
    table.add_column("Rule", width=30)
    table.add_column("Message")
    table.add_column("Location", style="dim")

    severity_style = {
        Severity.ERROR: "red",
        Severity.WARNING: "yellow",
        Severity.INFO: "blue",
    }

    for f in result.findings:
        table.add_row(
            f"[{severity_style[f.severity]}]{f.severity.value.upper()}[/]",
            f.code,
            f.rule_name or "",
            f.message,
            f"{f.file}:{f.line}" if f.file else "",
        )

    console.print(table)
    console.print(f"\n{result.summary()}")

    if report_file:
        rpath = Path(report_file)
        if rpath.suffix.lower() == ".html":
            HtmlReporter().generate(result, output=rpath)
        else:
            JsonReporter().generate(result, output=rpath)
        console.print(f"[dim]Report written to {rpath}[/]")

    sys.exit(0 if result.passed else 1)


# ------------------------------------------------------------------ #
#  convert
# ------------------------------------------------------------------ #

@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--to", "target",
              type=click.Choice(list(SUPPORTED_TARGETS), case_sensitive=False),
              required=True, help="Target format")
@click.option("-o", "--output", "output_file", type=click.Path(), default=None,
              help="Write output to FILE (default: stdout)")
@click.option("--batch", is_flag=True, help="Convert all .yml files in a directory")
def convert(path: str, target: str, output_file: str | None, batch: bool) -> None:
    """Convert Sigma rules to another format."""
    converter = RuleConverter()
    parser = SigmaParser()
    results = []

    if batch or Path(path).is_dir():
        rules = list(parser.parse_directory(Path(path)))
    else:
        try:
            rules = [parser.parse_file(Path(path))]
        except SigmaParseError as e:
            err_console.print(f"[red]Parse error:[/] {e}")
            sys.exit(1)

    for rule in rules:
        try:
            output = converter.convert(rule, target)
            results.append(output)
        except ConversionError as e:
            err_console.print(f"[yellow]Skipped '{rule.title}':[/] {e}")

    combined = "\n\n".join(results)
    if output_file:
        Path(output_file).write_text(combined, encoding="utf-8")
        console.print(f"[green]Wrote {len(results)} rule(s) to {output_file}[/]")
    else:
        console.print(combined)


# ------------------------------------------------------------------ #
#  info
# ------------------------------------------------------------------ #

@main.command()
@click.argument("path", type=click.Path(exists=True))
def info(path: str) -> None:
    """Display rule metadata and ATT&CK mapping."""
    from secrulekit.utils.helpers import iter_attack_tags

    parser = SigmaParser()
    try:
        rule = parser.parse_file(Path(path))
    except SigmaParseError as e:
        err_console.print(f"[red]Parse error:[/] {e}")
        sys.exit(1)

    console.print(f"[bold]{rule.title}[/]")
    if rule.id:
        console.print(f"  ID:          {rule.id}")
    if rule.status:
        console.print(f"  Status:      {rule.status}")
    if rule.level:
        console.print(f"  Severity:    {rule.level}")
    if rule.author:
        console.print(f"  Author:      {rule.author}")
    if rule.description:
        console.print(f"  Description: {rule.description}")

    tactics = rule.attack_tactics
    if tactics:
        console.print(f"  Tactics:     {', '.join(tactics)}")

    techniques = list(iter_attack_tags(rule))
    if techniques:
        console.print("  Techniques:")
        for tid, tname in techniques:
            console.print(f"    {tid}  {tname or '(unknown)'}")


# ------------------------------------------------------------------ #
#  stats
# ------------------------------------------------------------------ #

@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-f", "--format", "fmt",
              type=click.Choice(["sigma", "yara", "suricata", "auto"], case_sensitive=False),
              default="auto")
def stats(path: str, fmt: str) -> None:
    """Show statistics for a rule collection."""
    from secrulekit.parsers.yara_parser import YaraParser
    from secrulekit.parsers.suricata_parser import SuricataParser
    from collections import Counter

    p = Path(path)

    if fmt in ("sigma", "auto") and (p.is_dir() or p.suffix in (".yml", ".yaml")):
        rules = list(SigmaParser().parse_directory(p) if p.is_dir() else [SigmaParser().parse_file(p)])
        levels = Counter(r.level or "unknown" for r in rules)
        tactics = Counter(t for r in rules for t in r.attack_tactics)
        console.print(f"[bold]Sigma rules:[/] {len(rules)}")
        console.print("Severity breakdown:")
        for lvl, cnt in levels.most_common():
            console.print(f"  {lvl:15s} {cnt}")
        if tactics:
            console.print("Top ATT&CK tactics:")
            for tactic, cnt in tactics.most_common(5):
                console.print(f"  {tactic:30s} {cnt}")
    elif fmt in ("yara", "auto"):
        rules = list(YaraParser().parse_directory(p) if p.is_dir() else YaraParser().parse_file(p))
        console.print(f"[bold]YARA rules:[/] {len(rules)}")
        with_meta = sum(1 for r in rules if r.meta)
        console.print(f"  With metadata:  {with_meta}")
        console.print(f"  Without meta:   {len(rules) - with_meta}")


# ------------------------------------------------------------------ #
#  dedup
# ------------------------------------------------------------------ #

@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-f", "--format", "fmt",
              type=click.Choice(["yara", "sigma", "suricata", "auto"], case_sensitive=False),
              default="auto")
@click.option("-o", "--output", "output_dir", type=click.Path(), default=None,
              help="Write deduplicated rules to OUTPUT_DIR")
def dedup(path: str, fmt: str, output_dir: str | None) -> None:
    """Find and remove duplicate rules from a collection."""
    from secrulekit.utils.helpers import deduplicate_rules
    from secrulekit.parsers.yara_parser import YaraParser
    from secrulekit.parsers.suricata_parser import SuricataParser

    p = Path(path)

    if fmt in ("sigma", "auto") and (p.is_dir() or p.suffix in (".yml", ".yaml")):
        rules = list(SigmaParser().parse_directory(p) if p.is_dir() else [SigmaParser().parse_file(p)])
    else:
        rules = list(YaraParser().parse_directory(p) if p.is_dir() else YaraParser().parse_file(p))

    unique, dupes = deduplicate_rules(rules)
    console.print(f"Total: {len(rules)}  Unique: {len(unique)}  Duplicates: {len(dupes)}")

    if dupes:
        console.print("\n[yellow]Duplicate rules:[/]")
        for r in dupes:
            name = r.title if isinstance(r, SigmaParser.__class__) else getattr(r, "name", str(r))
            console.print(f"  {getattr(r, 'source_file', '')}  {getattr(r, 'title', getattr(r, 'name', ''))}")


if __name__ == "__main__":
    main()
