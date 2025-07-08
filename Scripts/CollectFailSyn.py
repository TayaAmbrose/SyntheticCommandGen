# This file moves each failed syntax command to a designated folder for examination.

import os
import json
import shutil

# Folder with your generated samples
base_dir = "data/samples/T1611"
failed_dir = os.path.join(base_dir, "failed_syn_check")

# Create the failed_syn_check folder if it doesn't exist
os.makedirs(failed_dir, exist_ok=True)

# Stats counters
total = 0
passed = 0
failed = 0
skipped = 0

# Loop through all JSON files
for file in os.listdir(base_dir):
    if not file.endswith(".json"):
        continue
    file_path = os.path.join(base_dir, file)

    # Skip files already in failed directory
    if os.path.commonpath([file_path, failed_dir]) == failed_dir:
        continue

    total += 1
    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        syntax_ok = data.get("validation", {}).get("syntax_ok", None)

        if syntax_ok is True:
            passed += 1
        elif syntax_ok is False:
            failed += 1
            dest_path = os.path.join(failed_dir, file)
            shutil.move(file_path, dest_path)
            print(f"[!] Moved {file} → failed_syn_check/")
        else:
            skipped += 1  # None or missing
    except Exception as e:
        print(f"[!] Error processing {file}: {e}")
        skipped += 1

# Print final stats
print("\n=== Syntax Check Summary ===")
print(f"Total files checked : {total}")
print(f"Passed syntax check : {passed}")
print(f"Failed syntax check : {failed}")
print(f"Skipped or unreadable: {skipped}")
