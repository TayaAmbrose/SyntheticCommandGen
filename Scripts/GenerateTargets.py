#!/usr/bin/env python3
"""
Generate plausible target combinations and constraints for a MITRE ATT&CK technique
using a specific pre-built Assistant.

Usage:
  python GenerateTargets.py path/to/technique_json_file
"""

import argparse
import json
import os
import sys
import time
import re
from typing import Optional
import openai

# === CONFIGURATION ===
openai.api_key = "KEY HERE"
assistant_id   = "ID HERE"

OUTPUT_DIR = "GeneratedInput"

# ---- Prompt template for the assistant ----
USER_PROMPT_TEMPLATE = """MITRE ATT&CK Technique Info:
-----------------------------
{tech_text}

You are a security expert who generates realistic, PLAUSIBLE attack-target combinations and constraints grounded in MITRE ATT&CK details.

Task:
- Produce a Python snippet with TWO sections: targets and constraints.
- TARGETS section: a list of dicts with keys: platform, privilege, shell, tool.
  * Only include combinations that are realistic for the technique and platform(s) involved.
  * Prefer breadth and specificity (e.g., docker_group vs generic 'user').
  * Include both Linux and Windows when appropriate; include Kubernetes/cloud-native if relevant.
  * Avoid duplicates and fictional tools. Keep to well-known shells/tools for the technique.
  * Include 10–20 items unless the technique scope is very narrow.

- CONSTRAINTS section: a list of strings describing specific requirements for this technique.
  * The shell has to be Bash, Powershell, or Python.
  * Each constraint should be a clear, actionable guideline.
  * Focus on technique-specific behaviors (e.g., "Commands must specifically focus on deleting or wiping data").
  * Include realistic tooling relevant to the technique (e.g., PowerShell cmdlets, bash utilities, system commands).
  * Mention if obfuscation methods apply (base64, hex escapes, eval, aliases, etc.).
  * Specify that commands should avoid overlapping with other ATT&CK techniques.
  * Reference the technique ID explicitly (e.g., "Use the JSON file as ground truth for technique {tech_id}").
  * Include output format requirements (e.g., "Return ONLY valid JSON without markdown, comments, or explanation").
  * Add 5-10 constraints that are specific and relevant to this technique.

STRICT OUTPUT FORMAT:
Return ONLY this exact structure (no commentary, no markdown fences):
# Target combinations
targets = [
    {{ "platform": "...", "privilege": "...", "shell": "...", "tool": "..." }},
    ...
]

# Constraints
constraints = [
    "Constraint 1 specific to this technique...",
    "Constraint 2 about realistic tooling...",
    "Constraint 3 about obfuscation if applicable...",
    ...
]

Instructions:
Using the above details, generate both the `targets` and `constraints` lists for technique {tech_id}.
For Windows, use realistic shells/tools (e.g., PowerShell + relevant tool). 
For Linux, use realistic shells/tools (e.g., Bash + relevant tool).

Return ONLY the required Python snippet beginning with "# Target combinations".
"""

def extract_technique_id(data: dict, filepath: str) -> str:
    """Extract technique ID from JSON data or filename."""
    # Try to get from JSON data first
    if isinstance(data, dict):
        for key in ["technique_id", "id", "technique", "attack_id"]:
            if key in data:
                tid = str(data[key])
                # Clean up the ID
                match = re.search(r'T\d+(?:\.\d+)?', tid, re.IGNORECASE)
                if match:
                    return match.group(0).upper()
    
    # Fall back to filename
    basename = os.path.basename(filepath)
    match = re.search(r'T\d+(?:\.\d+)?', basename, re.IGNORECASE)
    if match:
        return match.group(0).upper()
    
    # Last resort: use filename without extension
    return os.path.splitext(basename)[0]

def read_technique_file(path: str) -> tuple[str, str]:
    """Read and flatten a MITRE ATT&CK technique file (JSON or text).
    Returns (formatted_text, technique_id)"""
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    
    technique_id = "UNKNOWN"
    try:
        data = json.loads(raw)
        technique_id = extract_technique_id(data, path)
        
        # Flatten common keys if present
        keys_priority = [
            "technique_id","technique_name","tactic","platforms",
            "description","procedure","examples","tools","datasources",
            "permissions_required","prerequisites"
        ]
        lines = []
        for k in keys_priority:
            if k in data:
                v = data[k]
                v_str = json.dumps(v, ensure_ascii=False, indent=2) if isinstance(v,(dict,list)) else str(v)
                lines.append(f"{k}: {v_str}")
        formatted = "\n".join(lines) if lines else raw
        return formatted, technique_id
    except Exception:
        technique_id = extract_technique_id({}, path)
        return raw, technique_id

def call_assistant(prompt: str, retries: int = 5, backoff: float = 1.5) -> str:
    """
    Send the prompt to the specified Assistant using the
    beta.threads interface and wait for the run to finish.
    """
    last_err: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            thread = openai.beta.threads.create()
            openai.beta.threads.messages.create(
                thread_id=thread.id,
                role="user",
                content=prompt
            )
            run = openai.beta.threads.runs.create(
                thread_id=thread.id,
                assistant_id=assistant_id
            )

            # Poll until completed or failed
            while True:
                run_status = openai.beta.threads.runs.retrieve(
                    thread_id=thread.id,
                    run_id=run.id
                )
                if run_status.status == "completed":
                    break
                elif run_status.status == "failed":
                    raise RuntimeError("Assistant run failed.")
                time.sleep(2)

            messages = openai.beta.threads.messages.list(thread_id=thread.id)
            response_text = ""
            for message in messages.data:
                if message.role == "assistant":
                    response_text += message.content[0].text.value

            # If the assistant wrapped the output in ``` blocks, strip them
            response_text = response_text.strip()
            if response_text.startswith("```"):
                response_text = response_text.strip("`").split("\n",1)[1]
            return response_text.strip()

        except Exception as e:
            last_err = e
            if attempt == retries:
                break
            time.sleep(backoff ** attempt)
    raise RuntimeError(f"Assistant call failed after {retries} attempts: {last_err}")

def main():
    parser = argparse.ArgumentParser(
        description="Generate plausible target combinations and constraints for a MITRE technique using a specific Assistant."
    )
    parser.add_argument("technique_file", help="Path to the MITRE ATT&CK technique file (JSON or text).")
    args = parser.parse_args()

    # Read technique file and extract ID
    tech_text, tech_id = read_technique_file(args.technique_file)
    
    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Generate output filename
    output_filename = f"{tech_id}_LLM_Input_Ready.txt"
    output_path = os.path.join(OUTPUT_DIR, output_filename)
    
    # Format prompt with technique ID
    user_prompt = USER_PROMPT_TEMPLATE.format(
        tech_text=tech_text.strip(),
        tech_id=tech_id
    )

    snippet = call_assistant(user_prompt)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(snippet + ("\n" if not snippet.endswith("\n") else ""))

    print(f"Wrote {output_path}\n")
    print(snippet)

if __name__ == "__main__":
    main()