"""
graphify.local — Privacy-preserving local-only knowledge graph pipeline.

Runs AST extraction → clustering → Obsidian export entirely on your machine.
Zero network calls. No code leaves the machine.

Usage:
    graphify-local <source-dir> --obsidian-dir <vault-dir>
    graphify-local <source-dir> --redact --terms sensitive_terms.txt --obsidian-dir <vault-dir>

Privacy dials:
    (default)          Structural-only AST. Nothing leaves the machine.
    --redact           Redact strings, numbers, and sensitive terms before analysis.
    --terms FILE       Sensitive terms file used with --redact (one term per line).
    --dehash           After export, restore real names in vault from redact_map.json.
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

import networkx as nx

from graphify.extract import collect_files, extract
from graphify.cluster import cluster
from graphify.export import to_obsidian, to_json


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Local-only knowledge graph: extract → cluster → export (zero network)."
    )
    parser.add_argument("source", type=Path, help="Source directory to analyze")
    parser.add_argument(
        "--obsidian-dir",
        type=Path,
        default=None,
        help="Output directory for Obsidian vault (default: graphify-out/obsidian)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also export graph.json to graphify-out/",
    )
    parser.add_argument(
        "--cache",
        type=Path,
        default=None,
        help="Cache directory for AST extraction (default: graphify-out/cache)",
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="Redact strings, numbers, and sensitive terms before extraction.",
    )
    parser.add_argument(
        "--terms",
        type=Path,
        default=None,
        help="Sensitive terms file for --redact (one term per line).",
    )
    parser.add_argument(
        "--dehash",
        action="store_true",
        help="After export, restore real names in vault using redact_map.json.",
    )
    args = parser.parse_args()

    source = args.source.resolve()
    if not source.exists():
        print(f"ERROR: Source directory not found: {source}")
        return 1

    obsidian_dir = args.obsidian_dir or Path("graphify-out") / "obsidian"
    cache_root = args.cache or Path("graphify-out") / "cache"

    # ── Optional: Redact source before extraction ─────────────────────────────
    analysis_source = source
    redact_map_file: Path | None = None

    if args.redact:
        from graphify.redact import redact_directory
        redacted_dir = Path("graphify-out") / "redacted_mirror"
        redact_map_file = Path("graphify-out") / "redact_map.json"
        print(f"🔒 Redacting source → {redacted_dir}")
        redact_directory(source, redacted_dir, args.terms)
        analysis_source = redacted_dir
        print()

    print(f"📁 Source: {analysis_source}")
    print(f"📓 Obsidian output: {obsidian_dir}")
    print()

    # ── Step 1: Collect files ─────────────────────────────────────────────────
    print("Step 1: Discovering code files...")
    paths = collect_files(analysis_source)
    print(f"  Found {len(paths)} files")
    if not paths:
        print("  ⚠️  No code files found. Check --help for supported extensions.")
        return 1

    # ── Step 2: Extract AST ───────────────────────────────────────────────────
    print("Step 2: Extracting AST (tree-sitter, local only)...")
    result = extract(paths, cache_root=cache_root)
    nodes = result.get("nodes", [])
    edges = result.get("edges", [])
    print(f"  Extracted {len(nodes)} nodes and {len(edges)} edges")

    if not nodes:
        print("  ⚠️  No structures found in code.")
        return 1

    # ── Step 3: Build graph ───────────────────────────────────────────────────
    print("Step 3: Building knowledge graph...")
    G = nx.DiGraph()
    for node in nodes:
        node_id = node["id"]
        attrs = {k: v for k, v in node.items() if k != "id"}
        G.add_node(node_id, **attrs)
    for edge in edges:
        src, tgt = edge["source"], edge["target"]
        attrs = {k: v for k, v in edge.items() if k not in ("source", "target")}
        G.add_edge(src, tgt, **attrs)
    print(f"  Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # ── Step 4: Cluster ───────────────────────────────────────────────────────
    print("Step 4: Community detection (Leiden/Louvain, local only)...")
    communities = cluster(G)
    print(f"  Found {len(communities)} communities")
    for cid, nodes_in_comm in sorted(communities.items(), key=lambda x: -len(x[1]))[:5]:
        print(f"    Community {cid}: {len(nodes_in_comm)} nodes")

    # ── Step 5: Export to Obsidian ────────────────────────────────────────────
    print(f"Step 5: Exporting to Obsidian vault...")
    obsidian_dir.parent.mkdir(parents=True, exist_ok=True)
    count = to_obsidian(G, communities, str(obsidian_dir))
    print(f"  ✓ Wrote {count} notes to {obsidian_dir}")

    # ── Optional: Export to JSON ──────────────────────────────────────────────
    if args.json:
        out_json = Path("graphify-out") / "graph.json"
        out_json.parent.mkdir(parents=True, exist_ok=True)
        to_json(G, communities, str(out_json))
        print(f"  ✓ Wrote graph.json to {out_json}")

    # ── Optional: Dehash vault ────────────────────────────────────────────────
    if args.dehash:
        map_file = redact_map_file or Path("graphify-out") / "redact_map.json"
        if map_file.exists():
            from graphify.dehash import dehash_vault
            restored = dehash_vault(obsidian_dir, map_file)
            print(f"🔓 Dehashed: restored real names in {restored} vault files")
        else:
            print(f"⚠️  --dehash: map file not found at {map_file}")

    print()
    print("✅ Done. Open the vault in Obsidian:")
    print(f"   Obsidian → Open vault folder → {obsidian_dir.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
