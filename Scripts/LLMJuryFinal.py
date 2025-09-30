#!/usr/bin/env python3
"""
Multi-LLM Command Evaluator with Syntactic and Semantic Scoring

Environment variables required:
  OPENROUTER_API_KEY
  ANTHROPIC_API_KEY
  GOOGLE_API_KEY

Usage:
  export OPENROUTER_API_KEY="..."
  export ANTHROPIC_API_KEY="..."
  export GOOGLE_API_KEY="..."
  python LLMJuryFinal.py

IMPORTANT:
  Change the MITRE description for each technique! Otherwise semantic scores will
  not be accurate!

"""

import os
import json
import time
import re
import openai
from datetime import datetime
from anthropic import Anthropic
import google.generativeai as genai

# === CONFIGURATION ===
def get_api_keys():
    """Get all API keys from environment variables."""
    keys = {
        'openrouter': os.environ.get('OPENROUTER_API_KEY'),
        'anthropic': os.environ.get('ANTHROPIC_API_KEY'),
        'google': os.environ.get('GOOGLE_API_KEY')
    }
    
    missing = [k for k, v in keys.items() if not v]
    if missing:
        raise ValueError(f"Missing API keys: {', '.join(missing.upper())}_API_KEY")
    
    return keys

# Initialize API clients
api_keys = get_api_keys()

# OpenRouter client for GPT models
openrouter_client = openai.OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=api_keys['openrouter']
)

anthropic = Anthropic(api_key=api_keys['anthropic'])
genai.configure(api_key=api_keys['google'])
gemini_model = genai.GenerativeModel('gemini-2.0-flash-thinking-exp')

input_folder = "../../Desktop/SyntheticCommandGen/Data/Samples/T1011/Initial"
output_folder = "../../Desktop/SyntheticCommandGen/Data/Samples/T1011/LLM Jury"

# Create output folder if it doesn't exist
os.makedirs(output_folder, exist_ok=True)

def now():
    return datetime.utcnow().isoformat() + "Z"

EXPECTED_MODELS = {
    "gpt-5": "gpt-5",
    "claude-3-7-sonnet": "claude-3-7-sonnet", 
    "gemini-2.0-flash-thinking-exp": "gemini-2.0-flash-thinking-exp"
}

# === CLEAN LLM RESPONSE ===
def clean_llm_response(text):
    text = text.strip()
    if text.startswith("```json"):
        text = text.removeprefix("```json").removesuffix("```").strip()
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        return match.group(0)
    return text

# === UNIFIED PROMPT BUILDER ===
def build_prompt(data, mitre_description):
    return f"""You are a cybersecurity command evaluator. Evaluate the command below on TWO independent axes:

MITRE ATT&CK Technique: {data['technique_id']}
Technique Description: {mitre_description}

Command to Evaluate:
- Command: {data['command']}
- Explanation: {data['explanation']}
- Platform: {data.get('platform')}
- Privilege: {data.get('privilege')}
- Shell: {data.get('shell')}

SCORING CRITERIA:

1. SYNTACTIC CORRECTNESS (0-5): Is the command well-formed and parseable?
   5 = Perfectly well-formed, no syntax errors, balanced quoting, valid flags
   4 = Minor formatting issues but parseable
   3 = Acceptable but imperfect, may fail in edge cases
   2 = Broken, likely to fail parsing
   1 = Fragment, not runnable as-is
   0 = Gibberish, unrecognizable

   Check for:
   - Balanced quotes/parentheses/braces
   - Proper command separators (;, &&, |)
   - Valid flag formats
   - No impossible constructs
   - Proper escape sequences

2. SEMANTIC CORRECTNESS (0-5): Does the command achieve the claimed intent?
   5 = Perfectly aligned with technique, operationally plausible
   4 = Mostly correct, minor realism gaps
   3 = Partially correct, rough flow but arguments reduce plausibility
   2 = Misaligned, wrong tool or incorrect semantics
   1 = Not aligned with claim
   0 = Nonsense, unrelated to technique

   Check for:
   - Tool appropriateness for the task
   - Argument semantics match intent
   - Resources/paths are consistent
   - Permissions requirements acknowledged
   - Operational feasibility
   - Realistic implementation of technique

3. CONFIDENCE (0-1): Your confidence in both scores

Output ONLY valid JSON with this exact structure:
{{
  "syntactic_score": <0-5>,
  "syntactic_justification": "<one sentence>",
  "semantic_score": <0-5>,
  "semantic_justification": "<one sentence>",
  "confidence": <0-1>
}}"""

# === VERDICT CALCULATOR ===
def compute_combined_score(syntactic, semantic):
    """Both scores must pass. If either fails, overall fails."""
    # If syntactic < 3 or semantic < 3, it's a failure
    if syntactic < 3 or semantic < 3:
        return round((syntactic + semantic) / 2, 3)
    # Both pass threshold, return average
    return round((syntactic + semantic) / 2, 3)

def get_verdict(syntactic, semantic):
    """Determine verdict based on both scores."""
    # Must pass both thresholds
    if syntactic >= 4 and semantic >= 3:
        return "likely_match"
    elif syntactic >= 3 and semantic >= 2:
        return "uncertain"
    else:
        return "likely_mismatch"

# === CHECK MISSING MODELS ===
def get_missing_models(data):
    existing_models = set()
    judgments = data.get('validation', {}).get('llm_judgments', [])
    for judgment in judgments:
        model = judgment.get('model')
        if model:
            existing_models.add(model)
    
    return [m for m in EXPECTED_MODELS.keys() if m not in existing_models]

# === EVALUATE WITH GPT-5 ===
def evaluate_with_gpt5(data, mitre_description):
    prompt = build_prompt(data, mitre_description)
    
    try:
        response = openrouter_client.chat.completions.create(
            model="openai/gpt-5",
            messages=[
                {"role": "system", "content": "You are a cybersecurity evaluator. Always respond with valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0
        )
        
        assistant_reply = response.choices[0].message.content
        cleaned_reply = clean_llm_response(assistant_reply)
        eval_result = json.loads(cleaned_reply)
        
        syntactic = eval_result.get("syntactic_score")
        semantic = eval_result.get("semantic_score")
        
        judgment = {
            "model": "gpt-5",
            "syntactic_score": syntactic,
            "syntactic_justification": eval_result.get("syntactic_justification"),
            "semantic_score": semantic,
            "semantic_justification": eval_result.get("semantic_justification"),
            "combined_score": compute_combined_score(syntactic, semantic),
            "confidence": eval_result.get("confidence"),
            "timestamp": now()
        }
        
        return judgment
        
    except Exception as e:
        print(f"    [!] GPT-5 API error: {e}")
        return None

# === EVALUATE WITH CLAUDE ===
def evaluate_with_claude(data, mitre_description):
    prompt = build_prompt(data, mitre_description)
    
    try:
        response = anthropic.messages.create(
            model="claude-3-7-sonnet-20250219",
            max_tokens=1000,
            temperature=0,
            system="You are a cybersecurity evaluator. Always respond with valid JSON only.",
            messages=[{"role": "user", "content": prompt}]
        )
        assistant_reply = response.content[0].text
        
        cleaned_reply = clean_llm_response(assistant_reply)
        eval_result = json.loads(cleaned_reply)
        
        syntactic = eval_result.get("syntactic_score")
        semantic = eval_result.get("semantic_score")
        
        judgment = {
            "model": "claude-3-7-sonnet",
            "syntactic_score": syntactic,
            "syntactic_justification": eval_result.get("syntactic_justification"),
            "semantic_score": semantic,
            "semantic_justification": eval_result.get("semantic_justification"),
            "combined_score": compute_combined_score(syntactic, semantic),
            "confidence": eval_result.get("confidence"),
            "timestamp": now()
        }
        
        return judgment
        
    except Exception as e:
        print(f"    [!] Claude API error: {e}")
        return None

# === EVALUATE WITH GEMINI ===
def evaluate_with_gemini(data, mitre_description):
    prompt = build_prompt(data, mitre_description)
    
    try:
        response = gemini_model.generate_content(prompt)
        assistant_reply = response.text
        
        cleaned_reply = clean_llm_response(assistant_reply)
        eval_result = json.loads(cleaned_reply)
        
        syntactic = eval_result.get("syntactic_score")
        semantic = eval_result.get("semantic_score")
        
        judgment = {
            "model": "gemini-2.0-flash-thinking-exp",
            "syntactic_score": syntactic,
            "syntactic_justification": eval_result.get("syntactic_justification"),
            "semantic_score": semantic,
            "semantic_justification": eval_result.get("semantic_justification"),
            "combined_score": compute_combined_score(syntactic, semantic),
            "confidence": eval_result.get("confidence"),
            "timestamp": now()
        }
        
        return judgment
        
    except Exception as e:
        print(f"    [!] Gemini API error: {e}")
        return None

MODEL_EVALUATORS = {
    "gpt-5": evaluate_with_gpt5,
    "claude-3-7-sonnet": evaluate_with_claude,
    "gemini-2.0-flash-thinking-exp": evaluate_with_gemini
}

# === RECALCULATE AVERAGED RESULTS ===
def recalculate_averages(data):
    judgments = data.get('validation', {}).get('llm_judgments', [])
    
    if not judgments:
        return None, None
    
    # Average syntactic and semantic scores separately
    syntactic_scores = [j['syntactic_score'] for j in judgments if j.get('syntactic_score') is not None]
    semantic_scores = [j['semantic_score'] for j in judgments if j.get('semantic_score') is not None]
    
    if not syntactic_scores or not semantic_scores:
        return None, None
    
    avg_syntactic = round(sum(syntactic_scores) / len(syntactic_scores), 3)
    avg_semantic = round(sum(semantic_scores) / len(semantic_scores), 3)
    avg_combined = compute_combined_score(avg_syntactic, avg_semantic)
    verdict = get_verdict(avg_syntactic, avg_semantic)
    
    data["validation"]["llm_average_syntactic"] = avg_syntactic
    data["validation"]["llm_average_semantic"] = avg_semantic
    data["validation"]["llm_average_score"] = avg_combined
    data["validation"]["llm_verdict"] = verdict
    
    return avg_combined, verdict

# === MAIN LOOP ===
# Note: Update mitre_description to match your technique
mitre_description = (
    "Exfiltration Over Other Network Medium: Adversaries may exfiltrate data over a different network medium "
    "than the command and control channel, such as using cellular, Wi-Fi, or Bluetooth to exfiltrate data "
    "when the primary network is being monitored."
)

total_files = 0
files_needing_updates = 0
total_evaluations_added = 0

for fname in os.listdir(input_folder):
    if not fname.endswith(".json"):
        continue
    
    total_files += 1
    input_filepath = os.path.join(input_folder, fname)
    output_filepath = os.path.join(output_folder, fname)
    
    # Read from input folder (read-only)
    with open(input_filepath, "r") as f:
        data = json.load(f)
    
    # Check if output file exists and load it instead to preserve existing evaluations
    if os.path.exists(output_filepath):
        with open(output_filepath, "r") as f:
            output_data = json.load(f)
        missing_models = get_missing_models(output_data)
        data = output_data  # Use the output file's data
    else:
        missing_models = get_missing_models(data)
    
    if not missing_models:
        print(f"[✓] {fname} - All models present, skipping")
        continue
    
    files_needing_updates += 1
    print(f"Processing {fname}...")
    print(f"  Missing models: {', '.join(missing_models)}")
    
    data.setdefault("validation", {})
    data["validation"].setdefault("llm_judgments", [])
    
    evaluations_added = 0
    
    for model in missing_models:
        if model not in MODEL_EVALUATORS:
            print(f"  [!] No evaluator available for {model}")
            continue
        
        print(f"  Evaluating with {model}...")
        evaluator = MODEL_EVALUATORS[model]
        judgment = evaluator(data, mitre_description)
        
        if judgment:
            data["validation"]["llm_judgments"].append(judgment)
            evaluations_added += 1
            total_evaluations_added += 1
            print(f"    ✓ {model} - syntactic: {judgment['syntactic_score']}, semantic: {judgment['semantic_score']}, combined: {judgment['combined_score']}")
        else:
            print(f"    ✗ {model} evaluation failed")
    
    if evaluations_added > 0:
        print(f"  Recalculating averages...")
        avg_score, verdict = recalculate_averages(data)
        
        if avg_score is not None:
            print(f"  Updated average score: {avg_score}, verdict: {verdict}")
            
            data["validation"] = {
                "syntax_ok": data["validation"].get("syntax_ok"),
                "llm_judgments": data["validation"]["llm_judgments"],
                "llm_average_syntactic": data["validation"]["llm_average_syntactic"],
                "llm_average_semantic": data["validation"]["llm_average_semantic"],
                "llm_average_score": data["validation"]["llm_average_score"],
                "llm_verdict": data["validation"]["llm_verdict"],
                "sandbox_trace_id": data["validation"].get("sandbox_trace_id"),
                "mitre_match_score": data["validation"].get("mitre_match_score")
            }
            
            # Only save to output folder (NOT input folder)
            with open(output_filepath, "w") as out:
                json.dump(data, out, indent=2)
            
            print(f"  [✓] {fname} updated with {evaluations_added} new evaluation(s)")
            print(f"  [✓] Saved to {output_folder}")
    
    print()

print("="*60)
print("INCREMENTAL EVALUATION SUMMARY")
print("="*60)
print(f"Total files processed: {total_files}")
print(f"Files needing updates: {files_needing_updates}")
print(f"Total evaluations added: {total_evaluations_added}")
print(f"Files with all models complete: {total_files - files_needing_updates}")
