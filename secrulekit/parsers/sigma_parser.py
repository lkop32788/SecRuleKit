"""Sigma rule parser — parses YAML-based Sigma detection rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import yaml


@dataclass
class SigmaRule:
    title: str
    id: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    modified: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    logsource: Dict[str, Any] = field(default_factory=dict)
    detection: Dict[str, Any] = field(default_factory=dict)
    falsepositives: List[str] = field(default_factory=list)
    level: Optional[str] = None
    source_file: Optional[Path] = None

    @property
    def attack_techniques(self) -> List[str]:
        return [t.replace("attack.t", "T").replace("attack.T", "T") for t in self.tags if "attack.t" in t.lower()]

    @property
    def attack_tactics(self) -> List[str]:
        tactics = {
            "initial_access", "execution", "persistence", "privilege_escalation",
            "defense_evasion", "credential_access", "discovery", "lateral_movement",
            "collection", "command_and_control", "exfiltration", "impact",
        }
        return [t.replace("attack.", "") for t in self.tags if t.replace("attack.", "") in tactics]


class SigmaParseError(Exception):
    def __init__(self, message: str, file: Optional[Path] = None):
        self.file = file
        super().__init__(f"{file}: {message}" if file else message)


class SigmaParser:
    """Parse Sigma rules from YAML files or directories."""

    def parse_string(self, content: str, source_file: Optional[Path] = None) -> SigmaRule:
        """Parse a single Sigma rule from a YAML string."""
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise SigmaParseError(f"YAML parse error: {e}", file=source_file)

        if not isinstance(data, dict):
            raise SigmaParseError("Rule must be a YAML mapping", file=source_file)

        if "title" not in data:
            raise SigmaParseError("Missing required field: title", file=source_file)
        if "detection" not in data:
            raise SigmaParseError("Missing required field: detection", file=source_file)

        return SigmaRule(
            title=data["title"],
            id=data.get("id"),
            status=data.get("status"),
            description=data.get("description"),
            author=data.get("author"),
            date=str(data.get("date", "")),
            modified=str(data.get("modified", "")),
            tags=data.get("tags", []) or [],
            logsource=data.get("logsource", {}),
            detection=data["detection"],
            falsepositives=data.get("falsepositives", []) or [],
            level=data.get("level"),
            source_file=source_file,
        )

    def parse_file(self, path: Path | str) -> SigmaRule:
        """Parse a Sigma rule from a YAML file."""
        path = Path(path)
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as e:
            raise SigmaParseError(f"Cannot read file: {e}", file=path)
        return self.parse_string(content, source_file=path)

    def parse_directory(
        self,
        directory: Path | str,
        recursive: bool = True,
    ) -> Iterator[SigmaRule]:
        """Yield Sigma rules from all .yml/.yaml files in a directory."""
        directory = Path(directory).resolve()
        if not directory.is_dir():
            raise SigmaParseError(f"Not a directory: {directory}")

        glob = "**/*" if recursive else "*"
        for ext in ("*.yml", "*.yaml"):
            for path in sorted(directory.glob(f"{glob[:-1]}{ext[1:]}" if glob != "*" else ext)):
                if not path.resolve().is_relative_to(directory):
                    continue
                try:
                    yield self.parse_file(path)
                except SigmaParseError:
                    pass
