"""
This script summarizes final LLM jury results across evaluated JSON samples.

It loops through all .json files in the specified input folder.
For each file:
   - Extracts the final llm_verdict (likely_match, uncertain, likely_mismatch).
   - Extracts the llm_average_score (numeric confidence score).

It counts:
   - Number of samples per verdict category.
   - Total number of valid samples.

It computes:
   - Average score.
   - Minimum and maximum score.
   - Standard deviation of scores.

Main purpose:
Provides an overall quantitative summary of the LLM evaluation phase,
helping assess dataset quality and verdict distribution at a glance.
"""


import os
import json
import statistics

# === CONFIGURATION ===
input_folder = "data/samples/T1612/llm_jury_verdict/with_claude"

# === Initialize counters ===
verdict_counts = {
    "likely_match": 0,
    "uncertain": 0,
    "likely_mismatch": 0
}
scores = []

# === Process files ===
for fname in os.listdir(input_folder):
    if not fname.endswith(".json"):
        continue

    filepath = os.path.join(input_folder, fname)
    with open(filepath, "r") as f:
        data = json.load(f)

    validation = data.get("validation", {})
    verdict = validation.get("llm_verdict")
    avg_score = validation.get("llm_average_score")

    # Only count if both verdict and score are valid
    if verdict in verdict_counts and isinstance(avg_score, (int, float)):
        verdict_counts[verdict] += 1
        scores.append(avg_score)

# === Calculate statistics ===
if scores:
    total_samples = len(scores)
    average_score = round(statistics.mean(scores), 3)
    min_score = round(min(scores), 3)
    max_score = round(max(scores), 3)
    stdev_score = round(statistics.stdev(scores), 3) if len(scores) > 1 else 0.0
else:
    total_samples = 0
    average_score = min_score = max_score = stdev_score = None

# === Print summary ===
print("\n=== LLM Verdict Summary (Final Verdict Only) ===")
for verdict, count in verdict_counts.items():
    print(f"{verdict}: {count}")

print(f"\nTotal samples with score: {total_samples}")
print(f"Average llm_average_score: {average_score}")
print(f"Min llm_average_score: {min_score}")
print(f"Max llm_average_score: {max_score}")
print(f"Standard deviation: {stdev_score}")
