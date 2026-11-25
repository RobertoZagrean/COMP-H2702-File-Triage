# File Triage & Hash Analysis

Python tool for COMP H2702 Scenario C: File Triage & Hash Analysis.

## What it does
- Inventories all files in a given folder
- Calculates SHA-256 hashes
- Compares against a reference hash list (`hashes_reference.csv`)
- Classifies files as KNOWN/REFERENCE MATCH or UNKNOWN
- Detects and groups files with identical hashes (duplicates)
- Generates analyst-friendly reports (TXT, CSV, JSON)

## Setup
1. Place the supplied sample files in a folder (e.g. `samples/`).
2. Place `hashes_reference.csv` in the same directory as the script (or specify its path).
3. No extra packages needed (standard library only).

## How to run
```bash
# Default: looks for ./samples and ./hashes_reference.csv
python file_triage_final.py

# Specify a different folder
python file_triage_final.py /path/to/your/files

# Custom reference and output directory
python file_triage_final.py samples --reference hashes_reference.csv --output reports
```

## Output
Reports are written to the `output/` folder (or the directory you specify) with a timestamp.

## Security note
A hash match only proves identical file content. It does not prove behaviour, intent, or that a file is safe or malicious. Always investigate further.
