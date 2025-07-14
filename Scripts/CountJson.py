# This file count the number of .json files in a directory

import os

# === CONFIGURATION: SET YOUR FOLDER PATHS HERE ===
initial = "data/samples/T1612"
gpt = "data/samples/T1612/llm_jury_verdict"
claude = "data/samples/T1612/llm_jury_verdict/with_claude"

def count_json_files(folder):
    total = 0
    for fname in os.listdir(folder):
        try:
            if fname.endswith(".json"):
                total += 1
        except Exception as e:
            print(f"[!] Failed to process {fname} in {folder}: {e}")
            continue
    return total

if __name__ == "__main__":
    initial_count = count_json_files(initial)
    gpt_count = count_json_files(gpt)
    claude_count = count_json_files(claude)

    print(f"\n[Initial run, no jury] Total .json files in '{initial}': {initial_count}\n")
    print(f"[GPT jury folder] Total .json files in '{gpt}': {gpt_count}\n")
    print(f"[GPT + Claude jury folder] Total .json files in '{claude}': {claude_count}\n")
