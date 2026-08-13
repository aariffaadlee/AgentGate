"""Fail when committed source contains a private-key file or common live-token shape."""

import re
import subprocess  # nosec B404 - fixed git command, no shell, no untrusted arguments
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "dist",
        "node_modules",
        "__pycache__",
    }
)
BINARY_SUFFIXES = frozenset({".gif", ".ico", ".jpeg", ".jpg", ".png", ".webp"})
FORBIDDEN_SUFFIXES = frozenset({".key", ".p12", ".pem", ".pfx"})
PATTERNS = {
    "private-key-block": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "aws-access-key": re.compile(r"(?<![A-Z0-9])AKIA[A-Z0-9]{16}(?![A-Z0-9])"),
    "github-token": re.compile(r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{30,}"),
    "google-api-key": re.compile(r"(?<![A-Za-z0-9])AIza[A-Za-z0-9_-]{30,}"),
    "openai-api-key": re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "slack-token": re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{20,}"),
}


def _repository_files() -> list[Path]:
    try:
        result = subprocess.run(  # nosec B603 - constant executable and arguments
            ["git", "ls-files", "-z"],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            timeout=10,
        )
        relative_paths = [
            Path(value) for value in result.stdout.decode("utf-8").split("\0") if value
        ]
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError):
        relative_paths = []
    if not relative_paths:
        relative_paths = [path.relative_to(PROJECT_ROOT) for path in PROJECT_ROOT.rglob("*")]
    return sorted(
        path
        for path in relative_paths
        if not any(part in EXCLUDED_PARTS or part.startswith(".tmp") for part in path.parts)
        and path.suffix.lower() not in BINARY_SUFFIXES
        and (PROJECT_ROOT / path).is_file()
    )


def main() -> int:
    """Report only safe finding metadata and fail on every matched pattern."""

    findings: list[tuple[str, str]] = []
    for relative_path in _repository_files():
        if relative_path.name == ".env" or relative_path.suffix.lower() in FORBIDDEN_SUFFIXES:
            findings.append((relative_path.as_posix(), "forbidden-secret-file"))
            continue
        try:
            content = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for name, pattern in PATTERNS.items():
            if pattern.search(content) is not None:
                findings.append((relative_path.as_posix(), name))

    if findings:
        for path, pattern_name in sorted(set(findings)):
            print(f"secret-pattern finding: {path} ({pattern_name})")
        return 1
    print("repository secret-pattern scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
