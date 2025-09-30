#!/usr/bin/env python3
"""
Count .json files in directories.
Usage: python CountJsonFiles.py folder1 folder2 folder3 ...
"""

import os
import sys

def count_json_files(folder):
    if not os.path.exists(folder):
        return 0
    total = 0
    for fname in os.listdir(folder):
        if fname.endswith(".json"):
            total += 1
    return total

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python CountJsonFiles.py folder1 [folder2] [folder3] ...")
        sys.exit(1)
    
    folders = sys.argv[1:]
    
    for folder in folders:
        count = count_json_files(folder)
        print(f"{folder}: {count} files")
