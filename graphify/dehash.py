"""
Dehash Obsidian vault notes after semantic analysis.

Reads redact_map.json and replaces hashed IDs (ID_<8hex>) back to real
identifiers in all vault markdown files. Run this locally after graphify
produces the vault from redacted sources.

Usage:
    graphify-dehash <vault-dir> --map redact_map.json
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path


def dehash_vault(vault_dir: Path, map_file: Path) -> int:
    """Replace all hashed IDs in vault with real names.

    Args:
        vault_dir: Obsidian vault directory
        map_file: Path to redact_map.json (hash → real name)

    Returns:
        Number of files modified
    """
    if not map_file.exists():
        print(f"ERROR: Map file not found: {map_file}", file=sys.stderr)
        return 0

    hash_to_term: dict[str, str] = json.loads(map_file.read_text())
    if not hash_to_term:
        print("Map file is empty — nothing to dehash.")
        return 0

    # Sort by key length descending to avoid partial replacements
    replacements = sorted(hash_to_term.items(), key=lambda x: len(x[0]), reverse=True)

    md_files = list(vault_dir.rglob("*.md"))
    if not md_files:
        print(f"No markdown files found in {vault_dir}")
        return 0

    modified = 0
    for md_file in md_files:
        content = md_file.read_text(encoding="utf-8", errors="replace")
        new_content = content
        for hash_id, real_name in replacements:
            new_content = new_content.replace(hash_id, real_name)
        if new_content != content:
            md_file.write_text(new_content, encoding="utf-8")
            modified += 1

    return modified


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Restore real names in Obsidian vault from redact_map.json."
    )
    parser.add_argument("vault_dir", type=Path, help="Obsidian vault directory")
    parser.add_argument(
        "--map",
        type=Path,
        default=Path("graphify-out") / "redact_map.json",
        help="Path to redact_map.json (default: graphify-out/redact_map.json)",
    )
    args = parser.parse_args()

    if not args.vault_dir.exists():
        print(f"ERROR: Vault directory not found: {args.vault_dir}", file=sys.stderr)
        return 1

    print(f"Dehashing vault: {args.vault_dir}")
    print(f"Map file: {args.map}")

    count = dehash_vault(args.vault_dir, args.map)
    print(f"✓ Restored real names in {count} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
