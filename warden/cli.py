"""Warden CLI."""

import argparse
import sys
import os
from . import __version__
from .core import build_manifest, write_manifest, read_manifest, check_manifest, format_check_results, generate_report


def main():
    parser = argparse.ArgumentParser(prog="warden", description="File integrity monitor")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="Create baseline manifest")
    p.add_argument("path", nargs="?", default=".", help="Directory to scan")
    p.add_argument("-o", "--output", default="warden.manifest.json")
    p.add_argument("--algorithm", choices=["sha256", "sha1", "md5"], default="sha256")

    p = sub.add_parser("check", help="Verify files against manifest")
    p.add_argument("manifest", nargs="?", default="warden.manifest.json")
    p.add_argument("--report", metavar="FILE", help="Generate HTML report")

    p = sub.add_parser("update", help="Update manifest after changes")
    p.add_argument("manifest", nargs="?", default="warden.manifest.json")

    args = parser.parse_args()

    if args.command == "init":
        if not os.path.isdir(args.path):
            print(f"[ERR] Directory not found: {args.path}", file=sys.stderr)
            sys.exit(1)
        print(f"  Building manifest of {args.path}...", file=sys.stderr)
        manifest = build_manifest(args.path, args.algorithm)
        write_manifest(manifest, args.output)
        print(f"[OK] Manifest written: {args.output} ({len(manifest)} files)", file=sys.stderr)

    elif args.command == "check":
        if not os.path.exists(args.manifest):
            print(f"[ERR] Manifest not found: {args.manifest}", file=sys.stderr)
            sys.exit(1)
        manifest = read_manifest(args.manifest)
        root = os.path.dirname(args.manifest) or "."
        print(f"  Checking files against {args.manifest}...", file=sys.stderr)
        results = check_manifest(manifest, root)
        print(format_check_results(results))
        if args.report:
            path = generate_report(results, args.report)
            print(f"[OK] Report: {path}", file=sys.stderr)
        if results["modified"] or results["added"] or results["removed"]:
            sys.exit(2)

    elif args.command == "update":
        if not os.path.exists(args.manifest):
            print(f"[ERR] Manifest not found: {args.manifest}", file=sys.stderr)
            sys.exit(1)
        manifest = read_manifest(args.manifest)
        root = os.path.dirname(args.manifest) or "."
        results = check_manifest(manifest, root)
        # Rebuild manifest for changed files
        new_manifest = build_manifest(root, manifest.get("algorithm", "sha256"))
        write_manifest(new_manifest, args.manifest)
        changed = len(results["modified"]) + len(results["added"]) + len(results["removed"])
        print(f"[OK] Manifest updated: {args.manifest} ({changed} changes)")


if __name__ == "__main__":
    main()
