from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)

ENTRYPOINT_CANDIDATES = (
    "src/ingest.py",
    "src/detect.py",
    "src/convert.py",
    "src/checks.py",
    "src/discover.py",
)


@dataclass(frozen=True)
class SkillSpec:
    name: str
    description: str
    category: str
    capability: str
    skill_dir: Path
    entrypoint: Path | None

    @property
    def supported(self) -> bool:
        return self.entrypoint is not None

    @property
    def read_only(self) -> bool:
        return self.capability == "read-only"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def iter_skill_dirs(root: Path | None = None) -> list[Path]:
    base = (root or repo_root()) / "skills"
    return sorted(path.parent for path in base.glob("*/*/SKILL.md"))


def _extract_frontmatter(skill_md: Path) -> str:
    text = skill_md.read_text()
    match = FRONTMATTER_RE.match(text)
    if not match:
        raise ValueError(f"{skill_md} missing YAML frontmatter")
    return match.group(1)


def _parse_frontmatter(frontmatter: str) -> dict[str, str]:
    data: dict[str, str] = {}
    lines = frontmatter.splitlines()
    idx = 0

    while idx < len(lines):
        line = lines[idx]
        if not line.strip():
            idx += 1
            continue
        if line.startswith(" "):
            idx += 1
            continue
        if ":" not in line:
            idx += 1
            continue

        key, raw_value = line.split(":", 1)
        key = key.strip()
        value = raw_value.strip()

        if not value or value in {">-", "|", ">"}:
            idx += 1
            block: list[str] = []
            while idx < len(lines):
                child = lines[idx]
                if child.startswith("  "):
                    block.append(child.strip())
                    idx += 1
                    continue
                if not child.strip():
                    idx += 1
                    continue
                break
            data[key] = " ".join(part for part in block if part)
            continue

        data[key] = value.strip("\"'")
        idx += 1

    return data


def _derive_capability(skill_dir: Path, metadata: dict[str, str]) -> str:
    if "capability" in metadata and metadata["capability"]:
        return metadata["capability"]
    category = skill_dir.parent.name
    if category == "remediation" or skill_dir.name.startswith("remediate-"):
        return "write-remediation"
    if skill_dir.name.startswith("sink-"):
        return "write-sink"
    if skill_dir.name.startswith("runner-"):
        return "write-runner"
    return "read-only"


def _resolve_entrypoint(skill_dir: Path) -> Path | None:
    for candidate in ENTRYPOINT_CANDIDATES:
        path = skill_dir / candidate
        if path.exists():
            return path
    return None


def discover_skills(root: Path | None = None) -> list[SkillSpec]:
    base = root or repo_root()
    specs: list[SkillSpec] = []
    for skill_dir in iter_skill_dirs(base):
        metadata = _parse_frontmatter(_extract_frontmatter(skill_dir / "SKILL.md"))
        specs.append(
            SkillSpec(
                name=metadata["name"],
                description=metadata["description"],
                category=skill_dir.parent.name,
                capability=_derive_capability(skill_dir, metadata),
                skill_dir=skill_dir,
                entrypoint=_resolve_entrypoint(skill_dir),
            )
        )
    return specs


def supported_skills(root: Path | None = None) -> list[SkillSpec]:
    return [skill for skill in discover_skills(root) if skill.supported]


def tool_input_schema(skill: SkillSpec) -> dict[str, object]:
    description = "Inline stdin payload for the skill. Use this for JSON or JSONL filters."
    if skill.entrypoint and skill.entrypoint.name == "checks.py":
        description = "Optional stdin payload. Most benchmark/check skills use explicit CLI args instead."
    return {
        "type": "object",
        "properties": {
            "input": {
                "type": "string",
                "description": description,
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Explicit CLI arguments forwarded to the fixed skill entrypoint.",
            },
        },
        "additionalProperties": False,
    }


def tool_definition(skill: SkillSpec) -> dict[str, object]:
    tool: dict[str, object] = {
        "name": skill.name,
        "description": skill.description,
        "inputSchema": tool_input_schema(skill),
        "annotations": {
            "readOnlyHint": skill.read_only,
            "destructiveHint": not skill.read_only,
            "idempotentHint": skill.read_only,
        },
    }
    return tool


def tool_map(root: Path | None = None) -> dict[str, SkillSpec]:
    return {skill.name: skill for skill in supported_skills(root)}


def build_command(skill: SkillSpec, args: list[str]) -> list[str]:
    if not skill.entrypoint:
        raise ValueError(f"skill {skill.name} has no supported entrypoint")
    return [sys.executable, str(skill.entrypoint), *args]
