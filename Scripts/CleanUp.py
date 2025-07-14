# This file is not part of the main pipeline. This file makes sure that all json files
# match exact format output. Used for cleaning files that got weird during the generation
# testing and process. Only reorders, does not add new incites.

import os
import json

# Folder to process
input_folder = "data/samples/T1612/llm_jury_verdict"

for fname in os.listdir(input_folder):
    if not fname.endswith(".json"):
        continue

    file_path = os.path.join(input_folder, fname)

    with open(file_path, "r") as f:
        data = json.load(f)

    # Ensure validation block exists
    validation = data.get("validation", {})

    # Collect syntax_ok as sub-block
    syntax_ok = validation.get("syntax_ok", {
        "pass": None,
        "forbidden_tokens": None,
        "obfuscation_suspicious": None,
        "obfuscation_entropy": None,
        "command_length": None
    })

    # Collect llm_judgments array
    llm_judgments = validation.get("llm_judgments", [])

    # Collect scores
    llm_average_score = validation.get("llm_average_score")
    llm_verdict = validation.get("llm_verdict")

    # Keep sandbox + mitre (even if null)
    sandbox_trace_id = validation.get("sandbox_trace_id")
    mitre_match_score = validation.get("mitre_match_score")

    # Rewrite clean validation block
    data["validation"] = {
        "syntax_ok": syntax_ok,
        "llm_judgments": llm_judgments,
        "llm_average_score": llm_average_score,
        "llm_verdict": llm_verdict,
        "sandbox_trace_id": sandbox_trace_id,
        "mitre_match_score": mitre_match_score
    }

    # Overwrite the cleaned file
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[✓] Cleaned {fname}")
