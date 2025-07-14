"""
This script scans JSON samples for flagged static analysis results
and organizes them into separate folders for manual review.

It checks each .json file under input_folder for:
   - validation.syntax_ok.forbidden_tokens (e.g., presence of IPs, domains, credentials)
   - validation.syntax_ok.obfuscation_suspicious (high entropy + long length)

For each flagged file:
   - Copies it into a 'forbidden_tokens_flagged' folder or
     'obfuscation_suspicious_flagged' folder under the input folder.

Reports:
   - Total number of files analyzed.
   - Number of files flagged for each category.

Main purpose:
Helps quickly isolate and review samples that may need cleanup
or manual inspection before inclusion in analysis or publication.




NOT DONE YET AND NOT YET USED IN STATS




"""

import os
import json
import shutil

# === CONFIGURATION ===
input_folder = "data/samples/T1612/llm_jury_verdict/with_claude"
forbidden_folder = os.path.join(input_folder, "forbidden_tokens_flagged")
suspicious_folder = os.path.join(input_folder, "obfuscation_suspicious_flagged")

# Create output folders if they don't exist
os.makedirs(forbidden_folder, exist_ok=True)
os.makedirs(suspicious_folder, exist_ok=True)

# === COUNTERS ===
total_files = 0
forbidden_true = 0
suspicious_true = 0

# === LOOP FILES ===
for fname in os.listdir(input_folder):
    if not fname.endswith(".json"):
        continue

    total_files += 1
    filepath = os.path.join(input_folder, fname)

    with open(filepath, "r") as f:
        data = json.load(f)

    syntax_ok = data.get("validation", {}).get("syntax_ok", {})
    forbidden = syntax_ok.get("forbidden_tokens", False)
    suspicious = syntax_ok.get("obfuscation_suspicious", False)

    if forbidden:
        forbidden_true += 1
        shutil.copy(filepath, os.path.join(forbidden_folder, fname))
    if suspicious:
        suspicious_true += 1
        shutil.copy(filepath, os.path.join(suspicious_folder, fname))

# === RESULTS ===
print(f"\nTotal files analyzed: {total_files}")
print(f"Files with forbidden_tokens: {forbidden_true} → copied to '{forbidden_folder}'")
print(f"Files with obfuscation_suspicious: {suspicious_true} → copied to '{suspicious_folder}'\n")
