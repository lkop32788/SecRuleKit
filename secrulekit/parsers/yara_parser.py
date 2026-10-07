"""YARA rule parser — tokenizes and validates YARA rule syntax."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional


@dataclass
class YaraString:
    name: str
    type: str  # "text", "hex", "regex"
    value: str
    modifiers: List[str] = field(default_factory=list)


@dataclass
class YaraRule:
    name: str
    tags: List[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    strings: List[YaraString] = field(default_factory=list)
    condition: str = ""
    source_file: Optional[Path] = None
    line_number: int = 0

    @property
    def identifier(self) -> str:
        return self.name


_RULE_PATTERN = re.compile(
    r"(?:private\s+|global\s+)*rule\s+(\w+)"
    r"(?:\s*:\s*([\w\s]+?))?\s*\{(.*?)\}",
    re.DOTALL,
)
_META_ITEM = re.compile(r'(\w+)\s*=\s*(?:"([^"]*?)"|(\d+)|true|false)', re.MULTILINE)
_STRING_ITEM = re.compile(
    r'(\$\w*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\{[^}]+\})|(/(?:[^/\\]|\\.)+/\w*))',
    re.MULTILINE,
)
_CONDITION_BLOCK = re.compile(r"condition\s*:(.*?)(?=\}|\Z)", re.DOTALL)


class YaraParseError(Exception):
    def __init__(self, message: str, file: Optional[Path] = None, line: int = 0):
        self.file = file
        self.line = line
        super().__init__(f"{file}:{line}: {message}" if file else message)


class YaraParser:
    """Parse YARA rules from files, directories, or raw strings."""

    def parse_string(self, content: str, source_file: Optional[Path] = None) -> List[YaraRule]:
        """Parse all YARA rules from a string."""
        rules: List[YaraRule] = []
        for match in _RULE_PATTERN.finditer(content):
            rule = self._parse_rule_match(match, content, source_file)
            rules.append(rule)
        return rules

    def parse_file(self, path: Path | str) -> List[YaraRule]:
        """Parse YARA rules from a single file."""
        path = Path(path)
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise YaraParseError(f"Cannot read file: {e}", file=path)
        rules = self.parse_string(content, source_file=path)
        if not rules:
            raise YaraParseError("No YARA rules found in file", file=path)
        return rules

    def parse_directory(
        self,
        directory: Path | str,
        recursive: bool = True,
        extensions: tuple[str, ...] = (".yar", ".yara"),
    ) -> Iterator[YaraRule]:
        """Yield YARA rules from all matching files in a directory."""
        directory = Path(directory).resolve()
        if not directory.is_dir():
            raise YaraParseError(f"Not a directory: {directory}")

        glob = "**/*" if recursive else "*"
        for ext in extensions:
            for path in sorted(directory.glob(f"{glob}{ext}")):
                # Prevent symlink traversal outside the base directory
                if not path.resolve().is_relative_to(directory):
                    continue
                try:
                    yield from self.parse_file(path)
                except YaraParseError:
                    pass  # Individual file errors collected by validator

    def _parse_rule_match(
        self, match: re.Match, full_text: str, source_file: Optional[Path]
    ) -> YaraRule:
        name = match.group(1)
        tags_raw = match.group(2) or ""
        body = match.group(3)
        line_number = full_text[: match.start()].count("\n") + 1

        rule = YaraRule(
            name=name,
            tags=[t.strip() for t in tags_raw.split() if t.strip()],
            source_file=source_file,
            line_number=line_number,
        )

        # Extract meta section
        meta_match = re.search(r"meta\s*:(.*?)(?=strings:|condition:|$)", body, re.DOTALL)
        if meta_match:
            for m in _META_ITEM.finditer(meta_match.group(1)):
                rule.meta[m.group(1)] = m.group(2) or m.group(3) or ""

        # Extract strings section
        strings_match = re.search(r"strings\s*:(.*?)(?=condition:|$)", body, re.DOTALL)
        if strings_match:
            for s in _STRING_ITEM.finditer(strings_match.group(1)):
                name_s = s.group(1)
                if s.group(2) is not None:
                    ytype, value = "text", s.group(2)
                elif s.group(3) is not None:
                    ytype, value = "hex", s.group(3)
                else:
                    ytype, value = "regex", s.group(4)
                rule.strings.append(YaraString(name=name_s, type=ytype, value=value))

        # Extract condition
        cond = _CONDITION_BLOCK.search(body)
        if cond:
            rule.condition = cond.group(1).strip()

        return rule
