# Warden ðŸ›¡ï¸

<div align="center">

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-lightgrey)]()

**Tripwire-lite file integrity monitor â€” SHA256 manifests, change detection, HTML reports. Zero dependencies.**

</div>

---

## Features

- **Initialize manifests** â€” Scan a directory and create a SHA256 hash manifest
- **Integrity verification** â€” Compare current files against stored hashes
- **Change detection** â€” Identify added, modified, deleted, and tampered files
- **Update manifests** â€” Re-hash and update after approved changes
- **HTML reports** â€” Dark-mode reports with color-coded change summaries
- **Ignore patterns** â€” Skip files with fnmatch patterns
- **Zero dependencies** â€” Pure Python 3.8+, stdlib only

## Quick Start

```bash
pip install warden-fim

# Initialize integrity manifest
warden init /path/to/watch

# Check integrity (detect changes)
warden check /path/to/watch

# Update manifest after approved changes
warden update /path/to/watch

# Generate HTML report
warden report /path/to/watch
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `warden init [dir]` | Create SHA256 manifest for directory |
| `warden check [dir]` | Verify file integrity against manifest |
| `warden update [dir]` | Re-hash and update manifest |
| `warden report [dir]` | Generate HTML integrity report |

## How It Works

Warden works like a simple tripwire:

1. **`init`** walks a directory, hashes every file with SHA-256, and writes `warden.manifest.json`
2. **`check`** re-walks and re-hashes, comparing every file against the manifest
3. Changes are classified: **NEW** (added), **MODIFIED** (hash changed), **DELETED** (missing), **TAMPERED** (both exist but hash mismatched)
4. **`report`** generates an HTML page with the full analysis

## Project Structure

```
warden/
â”œâ”€â”€ warden/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ cli.py       # CLI entry point
â”‚   â””â”€â”€ core.py      # Manifest, hashing, diff, report
â”œâ”€â”€ pyproject.toml
â””â”€â”€ README.md
```

## License

MIT â€” see [LICENSE](LICENSE).
