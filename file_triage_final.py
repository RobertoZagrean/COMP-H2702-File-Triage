#!/usr/bin/env python3
"""
File Triage & Hash Analysis - COMP H2702 Scenario C
Inventories files, calculates SHA-256, compares to reference, finds duplicates.
"""

import argparse
import csv
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path


def load_reference(csv_path):
    """Load known SHA-256 hashes from CSV. Returns a set."""
    known = set()
    if not os.path.isfile(csv_path):
        print(f"[WARNING] Reference not found: {csv_path}")
        return known
    try:
        with open(csv_path, newline='', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                h = row.get('sha256') or row.get('hash') or next(iter(row.values()), '')
                if h:
                    known.add(h.strip().lower())
        print(f"[INFO] Loaded {len(known)} reference hashes")
    except Exception as e:
        print(f"[ERROR] Could not read reference CSV: {e}")
    return known


def file_info(path):
    """Return dict with filename, extension, size, mtime, sha256 or None on error."""
    try:
        p = Path(path)
        if not p.is_file():
            return None
        stat = p.stat()
        sha = hashlib.sha256()
        with open(p, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha.update(chunk)
        return {
            'filename': p.name,
            'extension': p.suffix.lower() or '(none)',
            'size_bytes': stat.st_size,
            'last_modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'sha256': sha.hexdigest()
        }
    except Exception as e:
        print(f"[ERROR] Could not process {path}: {e}")
        return None


def inventory(folder):
    """Scan folder and return list of file info dicts."""
    results = []
    folder = Path(folder)
    if not folder.is_dir():
        print(f"[ERROR] Folder not found: {folder}")
        return results
    try:
        for entry in folder.iterdir():
            if entry.is_file():
                info = file_info(entry)
                if info:
                    results.append(info)
    except Exception as e:
        print(f"[ERROR] Failed to read folder: {e}")
    print(f"[INFO] Inventoried {len(results)} files")
    return results


def analyse(files, known):
    """Classify files and find duplicates. Returns (files_with_status, duplicates)."""
    by_hash = {}
    for f in files:
        h = f['sha256'].lower()
        f['status'] = 'KNOWN/REFERENCE MATCH' if h in known else 'UNKNOWN'
        by_hash.setdefault(h, []).append(f['filename'])
    duplicates = {h: names for h, names in by_hash.items() if len(names) > 1}
    return files, duplicates


def save_reports(files, duplicates, out_dir='output'):
    """Write TXT, CSV and JSON reports."""
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    # JSON
    try:
        with open(os.path.join(out_dir, f'triage_{ts}.json'), 'w', encoding='utf-8') as f:
            json.dump({'files': files, 'duplicates': duplicates}, f, indent=2)
        print(f"[INFO] Saved JSON")
    except Exception as e:
        print(f"[ERROR] JSON write failed: {e}")

    # CSV
    try:
        with open(os.path.join(out_dir, f'triage_{ts}.csv'), 'w', newline='', encoding='utf-8') as f:
            if files:
                writer = csv.DictWriter(f, fieldnames=['filename', 'extension', 'size_bytes', 'last_modified', 'sha256', 'status'])
                writer.writeheader()
                writer.writerows(files)
        print(f"[INFO] Saved CSV")
    except Exception as e:
        print(f"[ERROR] CSV write failed: {e}")

    # TXT
    try:
        with open(os.path.join(out_dir, f'triage_{ts}.txt'), 'w', encoding='utf-8') as f:
            f.write(f"FILE TRIAGE REPORT - {datetime.now()}\n")
            f.write(f"Files: {len(files)} | Known: {sum(1 for x in files if x['status'].startswith('KNOWN'))} | Unknown: {sum(1 for x in files if x['status']=='UNKNOWN')}\n\n")
            for item in files:
                f.write(f"{item['filename']} | {item['extension']} | {item['size_bytes']} bytes | {item['last_modified']} | {item['sha256']} | {item['status']}\n")
            f.write("\nDUPLICATES:\n")
            if duplicates:
                for h, names in duplicates.items():
                    f.write(f"{h} -> {', '.join(names)}\n")
            else:
                f.write("None\n")
            f.write("\nNote: A hash match only proves identical content, not behaviour or safety.\n")
        print(f"[INFO] Saved TXT")
    except Exception as e:
        print(f"[ERROR] TXT write failed: {e}")


def main():
    parser = argparse.ArgumentParser(description="File Triage & Hash Analysis (COMP H2702 Scenario C)")
    parser.add_argument('folder', nargs='?', default='samples', help='Folder to triage (default: samples)')
    parser.add_argument('--reference', default='hashes_reference.csv', help='Reference CSV')
    parser.add_argument('--output', default='output', help='Output directory')
    args = parser.parse_args()

    known = load_reference(args.reference)
    files = inventory(args.folder)
    if not files:
        print("[WARNING] No files processed.")
        return

    files, duplicates = analyse(files, known)

    # Console summary
    known_count = sum(1 for f in files if f['status'].startswith('KNOWN'))
    print(f"\n=== TRIAGE SUMMARY ===")
    print(f"Files: {len(files)} | Known: {known_count} | Unknown: {len(files)-known_count} | Duplicate groups: {len(duplicates)}")
    if duplicates:
        print("Duplicates:")
        for h, names in duplicates.items():
            print(f"  {h[:16]}... -> {', '.join(names)}")
    print("A hash match confirms identical content only; it does not prove safety or intent.\n")

    save_reports(files, duplicates, args.output)
    print("[INFO] Done. Reports saved.")


if __name__ == "__main__":
    main()
