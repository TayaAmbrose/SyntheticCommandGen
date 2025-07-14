"""
This script counts the distribution of synthetic sample files by shell, tool, and platform.

It scans all JSON files in the specified folder:
    - Extracts 'shell', 'tool', and 'platform' fields.
    - Tallies how many files belong to each category.

By default, it prints:
    - Shell counts (e.g., bash, powershell, python, go)
    - Platform counts (e.g., linux, windows)

The tool counts are computed but currently commented out.

Main purpose:
Provides a summary of dataset composition to understand diversity
and balance across shell types, platforms, and tools.
Useful for dataset reporting, quality checks, and poster figures.
"""

import os
import json
from collections import Counter

# === CONFIGURATION: SET YOUR FOLDER PATH HERE ===
folder_path = "data/samples/T1612/llm_jury_verdict"

def count_by_fields(folder):
    shell_counter = Counter()
    tool_counter = Counter()
    platform_counter = Counter()

    for fname in os.listdir(folder):
        if not fname.endswith(".json"):
            continue

        fpath = os.path.join(folder, fname)
        try:
            with open(fpath, "r") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Failed to load {fname}: {e}")
            continue

        shell = data.get("shell", "unknown")
        tool = data.get("tool", "unknown")
        platform = data.get("platform", "unknown")

        shell_counter[shell] += 1
        tool_counter[tool] += 1
        platform_counter[platform] += 1

    return shell_counter, tool_counter, platform_counter

if __name__ == "__main__":
    shell_counts, tool_counts, platform_counts = count_by_fields(folder_path)

    print(f"\nCount by Shell:")
    for k, v in shell_counts.items():
        print(f"  {k}: {v}")

    # print(f"\nCount by Tool:")
    # for k, v in tool_counts.items():
    #     print(f"  {k}: {v}")

    print(f"\nCount by Platform:")
    for k, v in platform_counts.items():
        print(f"  {k}: {v}\n")
