"""Suricata/Snort rule parser."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional


@dataclass
class SuricataRule:
    action: str
    protocol: str
    src_addr: str
    src_port: str
    direction: str
    dst_addr: str
    dst_port: str
    options: Dict[str, str] = field(default_factory=dict)
    raw: str = ""
    source_file: Optional[Path] = None
    line_number: int = 0

    @property
    def sid(self) -> Optional[str]:
        return self.options.get("sid")

    @property
    def msg(self) -> Optional[str]:
        return self.options.get("msg", "").strip('"')

    @property
    def classtype(self) -> Optional[str]:
        return self.options.get("classtype")


class SuricataParseError(Exception):
    def __init__(self, message: str, file: Optional[Path] = None, line: int = 0):
        self.file = file
        self.line = line
        super().__init__(f"{file}:{line}: {message}" if file else message)


# Matches the rule header: action proto src_addr src_port direction dst_addr dst_port
_HEADER = re.compile(
    r"^(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s+"
    r"(\w+)\s+"                    # protocol
    r"([\w\[\]!,./]+)\s+"         # src_addr
    r"([\w\[\]!,]+)\s+"           # src_port
    r"(<>|->)\s+"                  # direction
    r"([\w\[\]!,./]+)\s+"         # dst_addr
    r"([\w\[\]!,]+)\s*"           # dst_port
    r"\((.+)\)\s*$",               # options body
    re.IGNORECASE,
)

# Tokenize options: key:value; or key; pairs
_OPTION_TOKEN = re.compile(r'(\w+)\s*(?::\s*("(?:[^"\\]|\\.)*"|[^;]*))?;')


class SuricataParser:
    """Parse Suricata/Snort rules."""

    def parse_string(
        self, line: str, source_file: Optional[Path] = None, line_number: int = 0
    ) -> Optional[SuricataRule]:
        """Parse a single rule line. Returns None for comments/blank lines."""
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None

        m = _HEADER.match(stripped)
        if not m:
            raise SuricataParseError("Invalid rule syntax", file=source_file, line=line_number)

        opts: Dict[str, str] = {}
        for om in _OPTION_TOKEN.finditer(m.group(8)):
            opts[om.group(1)] = om.group(2) or ""

        return SuricataRule(
            action=m.group(1).lower(),
            protocol=m.group(2).lower(),
            src_addr=m.group(3),
            src_port=m.group(4),
            direction=m.group(5),
            dst_addr=m.group(6),
            dst_port=m.group(7),
            options=opts,
            raw=stripped,
            source_file=source_file,
            line_number=line_number,
        )

    def parse_file(self, path: Path | str) -> List[SuricataRule]:
        """Parse all rules from a .rules file."""
        path = Path(path)
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as e:
            raise SuricataParseError(f"Cannot read file: {e}", file=path)

        rules = []
        for i, line in enumerate(lines, start=1):
            rule = self.parse_string(line, source_file=path, line_number=i)
            if rule is not None:
                rules.append(rule)
        return rules

    def parse_directory(
        self, directory: Path | str, recursive: bool = True
    ) -> Iterator[SuricataRule]:
        """Yield rules from .rules files in a directory."""
        directory = Path(directory).resolve()
        if not directory.is_dir():
            raise SuricataParseError(f"Not a directory: {directory}")

        glob = "**/*.rules" if recursive else "*.rules"
        for path in sorted(directory.glob(glob)):
            if not path.resolve().is_relative_to(directory):
                continue
            try:
                yield from self.parse_file(path)
            except SuricataParseError:
                pass
