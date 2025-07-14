"""
This script evaluates synthetic command samples using the Claude LLM API for security relevance.

It loops through all .json files in the 'input_folder' (typically files previously scored by GPT).
For each file:
   - Builds a prompt describing the command, platform, shell, privilege, and MITRE technique.
   - Sends the prompt to the Claude LLM (via Anthropic Messages API) for evaluation.
   - Extracts numeric scores for:
       - category_fit
       - attack_realism
       - maliciousness
       - technical_plausibility
       - privilege_relevance
Computes a weighted average score and classifies it as:
       - likely_match, uncertain, or likely_mismatch.
Updates the JSON file to include:
       - Individual Claude LLM judgment (appended to llm_judgments list)
       - Updated average submetrics across all LLMs
       - Final average score and verdict

Notes:
   - It expects existing llm_judgments from GPT-4-turbo or other models.
   - It preserves syntax check results and other fields.
   - Output files are saved into an output_folder for separate storage.
   - Uses hardcoded information of MITRE ATT&CK T1612 as grounding.

Main purpose:
To enrich multi-LLM evaluation by adding a second model's independent judgment,
improving overall assessment robustness for synthetic command samples.
"""

import os
import json
import time
import re
from datetime import datetime
from anthropic import Anthropic

# === CONFIGURATION ===
anthropic = Anthropic(api_key="api key here")

input_folder = "data/samples/T1612/llm_jury_verdict"
output_folder = os.path.join(input_folder, "with_claude")
os.makedirs(output_folder, exist_ok=True)

def now():
    return datetime.utcnow().isoformat() + "Z"

# === CLEAN LLM RESPONSE ===
def clean_llm_response(text):
    text = text.strip()
    if text.startswith("```json"):
        text = text.removeprefix("```json").removesuffix("```").strip()
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        return match.group(0)
    return text

# === PROMPT BUILDER ===
def build_prompt(data, mitre_description):
    return (
        f"Refer explicitly to the JSON record for MITRE ATT&CK Technique {data['technique_id']} as your sole source of truth.\n\n"
        f"Technique ID: {data['technique_id']}\n"
        f"Technique Description: {mitre_description}\n\n"
        f"Sample:\n"
        f"Command: {data['command']}\n"
        f"Explanation: {data['explanation']}\n"
        f"Platform: {data.get('platform')}\n"
        f"Privilege: {data.get('privilege')}\n"
        f"Shell: {data.get('shell')}\n\n"
        f"For each metric, assign a number 0-1 only:\n"
        f"- category_fit\n"
        f"- attack_realism\n"
        f"- maliciousness\n"
        f"- technical_plausibility\n"
        f"- privilege_relevance\n\n"
        f"Finally, provide one short sentence of reasoning.\n\n"
        f"Output as JSON only, like:\n"
        f'{{"category_fit": 0.9, "attack_realism": 0.85, "maliciousness": 0.8, "technical_plausibility": 0.9, "privilege_relevance": 0.85, "explanation": "Example reason."}}'
    )

# === VERDICT CALCULATOR ===
def compute_weighted_score(metrics):
    weights = {
        "category_fit": 0.3,
        "attack_realism": 0.2,
        "maliciousness": 0.2,
        "technical_plausibility": 0.2,
        "privilege_relevance": 0.1
    }
    return round(sum(metrics[k] * weights[k] for k in weights), 3)

def get_verdict(score):
    if score >= 0.85:
        return "likely_match"
    elif score >= 0.65:
        return "uncertain"
    else:
        return "likely_mismatch"

# === MAIN LOOP ===
mitre_description = (
    "Build Image on Host: Adversaries may build a container image directly on a host to bypass defenses, "
    "embedding malware in a custom image built from a benign base image."
)

for fname in os.listdir(input_folder):
    if not fname.endswith(".json"):
        continue

    with open(os.path.join(input_folder, fname), "r") as f:
        data = json.load(f)

    prompt = build_prompt(data, mitre_description)

    # === Send to Claude (Messages API) ===
    try:
        response = anthropic.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1000,
            temperature=0,
            system="You are a cybersecurity evaluator with access to the MITRE ATT&CK JSON database.",
            messages=[{"role": "user", "content": prompt}]
        )
        assistant_reply = response.content[0].text
    except Exception as e:
        print(f"[!] Claude API error for {fname}: {e}")
        continue

    cleaned_reply = clean_llm_response(assistant_reply)
    try:
        eval_result = json.loads(cleaned_reply)
    except json.JSONDecodeError:
        print(f"[!] JSON parse error in {fname}")
        continue

    # Build Claude judgment entry
    claude_judgment = {
        "model": "claude-3-opus-20240229",
        "category_fit": eval_result.get("category_fit"),
        "attack_realism": eval_result.get("attack_realism"),
        "maliciousness": eval_result.get("maliciousness"),
        "technical_plausibility": eval_result.get("technical_plausibility"),
        "privilege_relevance": eval_result.get("privilege_relevance"),
        "score": compute_weighted_score(eval_result),
        "reason": eval_result.get("explanation"),
        "timestamp": now()
    }

    # === Update judgments ===
    data.setdefault("validation", {})
    data["validation"].setdefault("llm_judgments", [])
    data["validation"]["llm_judgments"].append(claude_judgment)

    # === Compute average per sub-metric ===
    judgments = data["validation"]["llm_judgments"]
    sub_metrics = ["category_fit", "attack_realism", "maliciousness", "technical_plausibility", "privilege_relevance"]
    avg_submetrics = {}
    for metric in sub_metrics:
        avg_submetrics[metric] = round(
            sum(j[metric] for j in judgments if j.get(metric) is not None) / len(judgments), 3
        )

    # === Compute final weighted average score ===
    avg_score = compute_weighted_score(avg_submetrics)
    verdict = get_verdict(avg_score)

    # === Save to file: correct output format ===
    data["validation"] = {
        "syntax_ok": data["validation"].get("syntax_ok"),
        "llm_judgments": judgments,
        "llm_average_submetrics": avg_submetrics,
        "llm_average_score": avg_score,
        "llm_verdict": verdict,
        "sandbox_trace_id": None,
        "mitre_match_score": None
    }

    with open(os.path.join(output_folder, fname), "w") as out:
        json.dump(data, out, indent=2)

    print(f"[✓] {fname} → avg_score: {avg_score}, verdict: {verdict}")
