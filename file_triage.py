#!/usr/bin/env python3
"""
File Triage & Hash Analysis Tool
COMP H2702 - Scripting for Cybersecurity
Scenario C

Processes a folder of safe sample files, calculates SHA-256 hashes,
compares against a reference list, detects duplicates, and generates
analyst-friendly triage reports.
"""

import argparse
import csv
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path


def load_reference_hashes(csv_path):
    """
    Load known SHA-256 hashes from the reference CSV.
    Returns a set of known hashes (case-insensitive).
    Handles missing file or invalid data gracefully.
    """
    known_hashes = set()
    if not os.path.isfile(csv_path):
        print(f"[WARNING] Reference file not found: {csv_path}")
        return known_hashes

    try:
        with open(csv_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            # Support common column names: hash, sha256, SHA256, etc.
            for row in reader:
                hash_value = None
                for key in row:
                    if key and 'hash' in key.lower() or 'sha' in key.lower():
                        hash_value = row[key]
                        break
                if not hash_value:
                    # Fallback: take first column if no clear hash column
                    hash_value = next(iter(row.values()), None)
                if hash_value:
                    known_hashes.add(hash_value.strip().lower())
        print(f"[INFO] Loaded {len(known_hashes)} reference hashes from {csv_path}")
    except Exception as e:
        print(f"[ERROR] Failed to parse reference CSV: {e}")
    return known_hashes


def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file. Returns None on failure."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[ERROR] Could not hash {file_path}: {e}")
        return None


def get_file_metadata(file_path):
    """
    Collect metadata for a single file: name, extension, size, mtime, SHA-256.
    Returns a dict or None if the file cannot be processed.
    """
    try:
        path = Path(file_path)
        if not path.is_file():
            return None

        stat = path.stat()
        metadata = {
            'filename': path.name,
            'extension': path.suffix.lower() or '(none)',
            'size_bytes': stat.st_size,
            'last_modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'sha256': calculate_sha256(file_path),
            'full_path': str(path.resolve())
        }
        return metadata
    except Exception as e:
        print(f"[ERROR] Could not process {file_path}: {e}")
        return None


def inventory_folder(folder_path):
    """
    Scan a folder and collect metadata for all files (non-recursive by default).
    Returns a list of metadata dictionaries.
    """
    files = []
    folder = Path(folder_path)
    if not folder.is_dir():
        print(f"[ERROR] Folder not found or not a directory: {folder_path}")
        return files

    try:
        for entry in folder.iterdir():
            if entry.is_file():
                meta = get_file_metadata(entry)
                if meta and meta.get('sha256'):
                    files.append(meta)
                elif meta:
                    print(f"[WARNING] Skipped unreadable or unhashable file: {entry.name}")
    except Exception as e:
        print(f"[ERROR] Failed to inventory folder: {e}")

    print(f"[INFO] Inventoried {len(files)} files from {folder_path}")
    return files


def classify_and_find_duplicates(files, known_hashes):
    """
    Classify each file as KNOWN or UNKNOWN and group duplicates by hash.
    Returns (classified_files, duplicates_dict).
    """
    hash_to_files = {}
    classified = []

    for f in files:
        h = f['sha256'].lower()
        status = 'KNOWN/REFERENCE MATCH' if h in known_hashes else 'UNKNOWN'
        f['status'] = status
        classified.append(f)

        if h not in hash_to_files:
            hash_to_files[h] = []
        hash_to_files[h].append(f['filename'])

    # Keep only groups with more than one file
    duplicates = {h: names for h, names in hash_to_files.items() if len(names) > 1}
    return classified, duplicates


def generate_reports(classified_files, duplicates, output_dir='output'):
    """
    Generate TXT, CSV and JSON triage reports.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # --- JSON ---
    json_path = os.path.join(output_dir, f'triage_report_{timestamp}.json')
    report_data = {
        'generated': datetime.now().isoformat(),
        'file_count': len(classified_files),
        'duplicate_groups': len(duplicates),
        'files': classified_files,
        'duplicates': duplicates
    }
    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        print(f"[INFO] JSON report saved: {json_path}")
    except Exception as e:
        print(f"[ERROR] Could not write JSON: {e}")

    # --- CSV ---
    csv_path = os.path.join(output_dir, f'triage_report_{timestamp}.csv')
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            if classified_files:
                fieldnames = ['filename', 'extension', 'size_bytes', 'last_modified', 'sha256', 'status']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for item in classified_files:
                    writer.writerow(item)
        print(f"[INFO] CSV report saved: {csv_path}")
    except Exception as e:
        print(f"[ERROR] Could not write CSV: {e}")

    # --- TXT summary ---
    txt_path = os.path.join(output_dir, f'triage_summary_{timestamp}.txt')
    try:
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write("FILE TRIAGE & HASH ANALYSIS REPORT\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total files processed: {len(classified_files)}\n")
            f.write(f"Duplicate hash groups: {len(duplicates)}\n\n")

            f.write("FILE INVENTORY\n")
            f.write("-" * 50 + "\n")
            for item in classified_files:
                f.write(f"Filename:     {item['filename']}\n")
                f.write(f"Extension:    {item['extension']}\n")
                f.write(f"Size:         {item['size_bytes']} bytes\n")
                f.write(f"Modified:     {item['last_modified']}\n")
                f.write(f"SHA-256:      {item['sha256']}\n")
                f.write(f"Status:       {item['status']}\n")
                f.write("-" * 30 + "\n")

            if duplicates:
                f.write("\nDUPLICATE FILES (identical SHA-256)\n")
                f.write("-" * 50 + "\n")
                for h, names in duplicates.items():
                    f.write(f"Hash: {h}\n")
                    f.write(f"Files: {', '.join(names)}\n\n")
            else:
                f.write("\nNo duplicate files detected.\n")

            f.write("\nSECURITY NOTE\n")
            f.write("A hash match confirms identical file content only. It does not prove intent, behaviour, or safety.\n")
            f.write("Unknown files require further investigation.\n")
        print(f"[INFO] TXT summary saved: {txt_path}")
    except Exception as e:
        print(f"[ERROR] Could not write TXT: {e}")


def print_console_summary(classified_files, duplicates):
    """Print a clear analyst-friendly summary to the console."""
    print("\n" + "=" * 60)
    print("FILE TRIAGE SUMMARY")
    print("=" * 60)
    print(f"Files processed: {len(classified_files)}")
    known = sum(1 for f in classified_files if f['status'].startswith('KNOWN'))
    print(f"Reference matches: {known}")
    print(f"Unknown files: {len(classified_files) - known}")
    print(f"Duplicate groups: {len(duplicates)}")

    if duplicates:
        print("\nDuplicates found:")
        for h, names in duplicates.items():
            print(f"  {h[:16]}... → {', '.join(names)}")

    print("\nSecurity interpretation:")
    print("• A REFERENCE MATCH means the file content is identical to a known sample.")
    print("• It does NOT prove the file is safe or malicious by itself.")
    print("• Duplicate hashes indicate identical content under different names.")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="File Triage & Hash Analysis Tool (COMP H2702 Scenario C)"
    )
    parser.add_argument(
        'folder',
        nargs='?',
        default='samples',
        help='Path to the folder containing files to triage (default: samples)'
    )
    parser.add_argument(
        '--reference',
        default='hashes_reference.csv',
        help='Path to the reference hashes CSV (default: hashes_reference.csv)'
    )
    parser.add_argument(
        '--output',
        default='output',
        help='Directory to save reports (default: output)'
    )
    args = parser.parse_args()

    print(f"[INFO] Starting File Triage on folder: {args.folder}")
    print(f"[INFO] Reference file: {args.reference}")

    # Load reference hashes
    known_hashes = load_reference_hashes(args.reference)

    # Inventory the folder
    files = inventory_folder(args.folder)
    if not files:
        print("[WARNING] No valid files found. Exiting.")
        sys.exit(0)

    # Classify and find duplicates
    classified, duplicates = classify_and_find_duplicates(files, known_hashes)

    # Console output
    print_console_summary(classified, duplicates)

    # Save reports
    generate_reports(classified, duplicates, args.output)

    print("[INFO] Triage complete. Reports saved in the output directory.")


if __name__ == "__main__":
    main()
