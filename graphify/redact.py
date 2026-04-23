"""
Redact sensitive information from source code before semantic analysis.

Mirrors source tree to graphify-out/redacted_mirror/ with:
- String literals → <STR>
- Numbers (>3 digits) → <NUM>
- PII patterns stripped from comments
- Business identifiers (from sensitive_terms.txt) → hashed ID_<8hex>

Saves deterministic hash map to graphify-out/redact_map.json for later dehashing.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from typing import Optional


def _hash_identifier(term: str, salt: str = "graphify") -> str:
    """Generate deterministic hash ID for a term."""
    h = hashlib.md5(f"{term}:{salt}".encode()).hexdigest()
    return f"ID_{h[:8]}"


class Redactor:
    """Redacts sensitive data from source files."""

    def __init__(self, sensitive_terms_file: Optional[Path] = None):
        """
        Args:
            sensitive_terms_file: Path to file with one sensitive term per line.
        """
        self.term_to_hash: dict[str, str] = {}
        self.hash_to_term: dict[str, str] = {}

        if sensitive_terms_file and sensitive_terms_file.exists():
            for line in sensitive_terms_file.read_text().splitlines():
                term = line.strip()
                if term and not term.startswith("#"):
                    hash_id = _hash_identifier(term)
                    self.term_to_hash[term] = hash_id
                    self.hash_to_term[hash_id] = term

    def redact_content(self, content: str, file_ext: str) -> str:
        """Redact sensitive data from file content.

        Args:
            content: File content
            file_ext: File extension (e.g. ".py", ".pck")

        Returns:
            Redacted content
        """
        # Order matters: do comments first, then strings, then identifiers
        content = self._redact_comments(content, file_ext)
        content = self._redact_strings(content, file_ext)
        content = self._redact_numbers(content)
        content = self._redact_identifiers(content)
        return content

    def _redact_comments(self, content: str, file_ext: str) -> str:
        """Strip PII and sensitive patterns from comments."""
        pii_patterns = [
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",  # CC
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # Phone
        ]

        if file_ext in (".py", ".js", ".ts", ".tsx", ".java", ".c", ".cpp", ".rb", ".go"):
            # Single-line comments: //
            content = re.sub(
                r"(//.*)$",
                lambda m: self._strip_pii_from_line(m.group(1), pii_patterns),
                content,
                flags=re.MULTILINE,
            )
        elif file_ext in (".sql", ".pck", ".pks", ".pkb", ".plb", ".prc", ".fnc"):
            # Single-line comments: --
            content = re.sub(
                r"(--.*)$",
                lambda m: self._strip_pii_from_line(m.group(1), pii_patterns),
                content,
                flags=re.MULTILINE,
            )

        # Block comments: /* ... */ (most languages)
        def redact_block_comment(m):
            comment = m.group(0)
            for pattern in pii_patterns:
                comment = re.sub(pattern, "<PII>", comment, flags=re.IGNORECASE)
            return comment

        content = re.sub(r"/\*.*?\*/", redact_block_comment, content, flags=re.DOTALL)
        return content

    def _strip_pii_from_line(self, line: str, pii_patterns: list) -> str:
        """Replace PII patterns in a single line with <PII>."""
        for pattern in pii_patterns:
            line = re.sub(pattern, "<PII>", line, flags=re.IGNORECASE)
        return line

    def _redact_strings(self, content: str, file_ext: str) -> str:
        """Replace string literals with <STR>.

        Handles:
        - Single/double quoted strings with escapes
        - PL/SQL q'[...]' syntax
        """
        # Single and double quoted strings (most languages)
        # Handle escaped quotes
        content = re.sub(r"'(?:''|[^'])*'", "<STR>", content)  # single quotes
        content = re.sub(r'"(?:\\"|[^"])*"', "<STR>", content)  # double quotes

        # PL/SQL q'[...]' and q'{...}' syntax
        if file_ext in (".sql", ".pck", ".pks", ".pkb", ".plb", ".prc", ".fnc"):
            content = re.sub(r"q'\[.*?\]'", "<STR>", content, flags=re.DOTALL | re.IGNORECASE)
            content = re.sub(r"q'\{.*?\}'", "<STR>", content, flags=re.DOTALL | re.IGNORECASE)
            content = re.sub(r"q'<.*?>'", "<STR>", content, flags=re.DOTALL | re.IGNORECASE)
            content = re.sub(r"q'\(.*?\)'", "<STR>", content, flags=re.DOTALL | re.IGNORECASE)

        return content

    def _redact_numbers(self, content: str) -> str:
        """Replace numbers with > 3 digits with <NUM>."""
        return re.sub(r"\b\d{4,}\b", "<NUM>", content)

    def _redact_identifiers(self, content: str) -> str:
        """Replace sensitive identifiers with hashed IDs."""
        # Sort by length descending so longer terms are replaced first
        for term in sorted(self.term_to_hash.keys(), key=len, reverse=True):
            # Case-insensitive replacement for identifiers
            pattern = r"\b" + re.escape(term) + r"\b"
            replacement = self.term_to_hash[term]
            content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
        return content

    def save_map(self, output_path: Path) -> None:
        """Save term→hash mapping for later dehashing."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(self.hash_to_term, f, indent=2)


def redact_directory(
    source_dir: Path,
    output_dir: Path,
    sensitive_terms_file: Optional[Path] = None,
) -> None:
    """Redact all code files in a directory.

    Args:
        source_dir: Source code directory
        output_dir: Output directory for redacted mirror
        sensitive_terms_file: Optional path to sensitive_terms.txt
    """
    redactor = Redactor(sensitive_terms_file)

    # Collect all code files
    code_exts = {
        ".py", ".js", ".ts", ".tsx", ".go", ".rs",
        ".java", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp",
        ".rb", ".cs", ".kt", ".kts", ".scala", ".php", ".swift",
        ".lua", ".toc", ".zig", ".ps1",
        ".m", ".mm",
        ".sql", ".pck", ".pks", ".pkb", ".plb", ".prc", ".fnc",
    }

    source_dir = source_dir.resolve()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    file_count = 0

    for source_file in source_dir.rglob("*"):
        # Skip files that live inside the output directory (avoids self-referential loops)
        try:
            source_file.relative_to(output_dir)
            continue
        except ValueError:
            pass
        if source_file.is_file() and source_file.suffix in code_exts:
            try:
                # Read source
                content = source_file.read_text(encoding="utf-8", errors="replace")

                # Redact
                redacted = redactor.redact_content(content, source_file.suffix)

                # Write to mirror
                rel_path = source_file.relative_to(source_dir)
                output_file = output_dir / rel_path
                output_file.parent.mkdir(parents=True, exist_ok=True)
                output_file.write_text(redacted, encoding="utf-8")

                file_count += 1
            except Exception as e:
                print(f"  ⚠️  {source_file}: {e}")

    # Save redaction map
    map_file = output_dir.parent / "redact_map.json"
    redactor.save_map(map_file)

    print(f"✓ Redacted {file_count} files to {output_dir}")
    print(f"✓ Saved redaction map to {map_file}")


def main() -> int:
    """CLI entry point for redacting source code."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Redact sensitive data from source code.")
    parser.add_argument("source", type=Path, help="Source code directory")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("graphify-out") / "redacted_mirror",
        help="Output directory for redacted mirror",
    )
    parser.add_argument(
        "--terms",
        type=Path,
        default=None,
        help="File with sensitive terms (one per line)",
    )
    args = parser.parse_args()

    source = args.source.resolve()
    output = args.output.resolve()

    if not source.exists():
        print(f"ERROR: Source directory not found: {source}", file=sys.stderr)
        return 1

    redact_directory(source, output, args.terms)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
