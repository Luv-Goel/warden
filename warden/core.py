"""Warden — File integrity monitor core."""

import os
import hashlib
import json
import time
from typing import List, Dict, Optional


def hash_file(path: str, algorithm: str = "sha256") -> str:
    """Compute file hash."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def get_file_info(path: str) -> Dict:
    """Get file metadata."""
    stat = os.stat(path)
    return {
        "path": path,
        "size": stat.st_size,
        "mtime": stat.st_mtime,
        "mode": stat.st_mode,
    }


SKIP_DIRS = {".git", ".svn", "__pycache__", "node_modules", ".venv", ".eggs", "dist", "build"}
SKIP_EXTS = {".pyc", ".o", ".so", ".dll", ".dylib"}


def should_index(path: str, root: str) -> bool:
    """Check if file should be included in manifest."""
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    if ext in SKIP_EXTS:
        return False
    rel = os.path.relpath(path, root)
    parts = rel.replace("\\", "/").split("/")
    for part in parts[:-1]:
        if part in SKIP_DIRS:
            return False
    return True


def build_manifest(root: str, algorithm: str = "sha256") -> List[Dict]:
    """Build a manifest of all files."""
    manifest = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if should_index(path, root):
                relpath = os.path.relpath(path, root)
                try:
                    file_hash = hash_file(path, algorithm)
                    info = get_file_info(path)
                    manifest.append({
                        "file": relpath,
                        "hash": file_hash,
                        "algorithm": algorithm,
                        "size": info["size"],
                        "mtime": info["mtime"],
                    })
                except Exception:
                    pass
    return manifest


def write_manifest(manifest: List[Dict], output_path: str) -> str:
    """Write manifest as JSON."""
    data = {
        "version": 1,
        "created": time.time(),
        "algorithm": manifest[0]["algorithm"] if manifest else "sha256",
        "files": manifest,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return output_path


def read_manifest(path: str) -> Dict:
    """Read manifest from JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def check_manifest(manifest: Dict, root: str) -> Dict:
    """Verify files against manifest."""
    algorithm = manifest.get("algorithm", "sha256")
    results = {"added": [], "removed": [], "modified": [], "unchanged": [], "errors": []}

    manifest_files = {f["file"]: f for f in manifest.get("files", [])}

    # Check current files
    current_files = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if should_index(path, root):
                relpath = os.path.relpath(path, root).replace("\\", "/")
                current_files.add(relpath)
                if relpath in manifest_files:
                    entry = manifest_files[relpath]
                    try:
                        current_hash = hash_file(path, algorithm)
                        if current_hash == entry["hash"]:
                            results["unchanged"].append(relpath)
                        else:
                            results["modified"].append({
                                "file": relpath,
                                "expected_hash": entry["hash"],
                                "current_hash": current_hash,
                            })
                    except Exception as e:
                        results["errors"].append({"file": relpath, "error": str(e)})
                else:
                    results["added"].append(relpath)

    # Find removed files
    for f in manifest_files:
        if f not in current_files:
            results["removed"].append(f)

    return results


def format_check_results(results: Dict) -> str:
    """Format check results."""
    lines = ["=" * 56, "  Warden Integrity Check", "=" * 56]
    total = len(results["unchanged"]) + len(results["modified"]) + len(results["added"]) + len(results["removed"])
    lines.append(f"  Files checked: {total}")
    lines.append(f"  Unchanged: {len(results['unchanged'])}")
    lines.append(f"  Modified: {len(results['modified'])}")
    lines.append(f"  Added: {len(results['added'])}")
    lines.append(f"  Removed: {len(results['removed'])}")
    lines.append(f"  Errors: {len(results['errors'])}")
    lines.append("")

    if results["modified"]:
        lines.append(f"  Modified ({len(results['modified'])}):")
        for m in results["modified"]:
            lines.append(f"    {m['file']}")
            lines.append(f"      expected: {m['expected_hash'][:16]}...")
            lines.append(f"      got:      {m['current_hash'][:16]}...")

    if results["added"]:
        lines.append(f"  Added ({len(results['added'])}):")
        for f in results["added"][:20]:
            lines.append(f"    + {f}")
        if len(results["added"]) > 20:
            lines.append(f"    ... and {len(results['added']) - 20} more")

    if results["removed"]:
        lines.append(f"  Removed ({len(results['removed'])}):")
        for f in results["removed"][:20]:
            lines.append(f"    - {f}")
        if len(results["removed"]) > 20:
            lines.append(f"    ... and {len(results['removed']) - 20} more")

    return "\n".join(lines)


def generate_report(results: Dict, output_path: str) -> str:
    """Generate HTML integrity report."""
    status = "INTACT" if not results["modified"] and not results["added"] and not results["removed"] else "CHANGED"
    color = "#22c55e" if status == "INTACT" else "#ef4444"

    modified_rows = ""
    for m in results.get("modified", []):
        modified_rows += f"<tr><td>{m['file']}</td><td><code>{m['expected_hash'][:16]}...</code></td><td><code>{m['current_hash'][:16]}...</code></td></tr>\n"

    added_rows = "".join(f"<tr><td>{f}</td><td>---</td><td>---</td></tr>\n" for f in results.get("added", [])[:50])
    removed_rows = "".join(f"<tr><td>{f}</td><td>---</td><td>---</td></tr>\n" for f in results.get("removed", [])[:50])

    def table_section(title, rows):
        if not rows.strip():
            return ""
        return f"<h2>{title}</h2><div class='card'><table class='table'><thead><tr><th>File</th><th>Expected</th><th>Current</th></tr></thead><tbody>{rows}</tbody></table></div>"

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Warden Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}}
h1{{font-size:2rem;margin-bottom:0.5rem}}
.status{{font-size:1.5rem;padding:1rem;border-radius:0.75rem;margin-bottom:1.5rem;text-align:center}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:2rem}}
.stat{{background:#1e293b;padding:1rem;border-radius:0.75rem;text-align:center}}
.stat-value{{font-size:1.5rem;font-weight:700}}
.stat-label{{font-size:0.8rem;color:#94a3b8}}
.card{{background:#1e293b;border-radius:0.75rem;margin-bottom:1rem;overflow:hidden}}
.card-header{{background:#334155;padding:0.75rem 1rem;font-weight:600}}
.card-body{{padding:1rem}}
.table{{width:100%;border-collapse:collapse}}
.table th{{text-align:left;padding:0.5rem;background:#1e293b;border-bottom:2px solid #334155;font-size:0.8rem}}
.table td{{padding:0.5rem;border-bottom:1px solid #334155;font-size:0.85rem}}
code{{color:#f87171;background:#1e293b;padding:0.1rem 0.3rem;border-radius:2px}}
</style></head><body>
<h1>File Integrity Report</h1>
<div class="status" style="background:{color}20;border:2px solid {color};color:{color}">{status}</div>
<div class="grid">
<div class="stat"><div class="stat-value">{len(results['unchanged'])}</div><div class="stat-label">Intact</div></div>
<div class="stat"><div class="stat-value">{len(results['modified'])}</div><div class="stat-label">Modified</div></div>
<div class="stat"><div class="stat-value">{len(results['added'])}</div><div class="stat-label">Added</div></div>
<div class="stat"><div class="stat-value">{len(results['removed'])}</div><div class="stat-label">Removed</div></div>
<div class="stat"><div class="stat-value">{len(results['errors'])}</div><div class="stat-label">Errors</div></div>
</div>
{table_section("Modified Files", modified_rows)}
{table_section("Added Files", added_rows)}
{table_section("Removed Files", removed_rows)}
<p style="margin-top:2rem;color:#64748b;font-size:0.8rem;">Warden — File Integrity Monitor</p>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path
