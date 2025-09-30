#!/usr/bin/env python3
"""
Generate synthetic command samples for a MITRE ATT&CK technique
using targets and constraints from a generated input file.

Usage:
  export OPENROUTER_API_KEY="your-api-key-here"
  python GenerateSamples.py path/to/TXXX_LLM_Input_Ready.txt

  ex: python GenerateCommands.py GeneratedInput/T1601_LLM_Input_Ready.txt --model openai/gpt-5
"""

import openai
import time
import json
import os
import hashlib
import argparse
import re
from datetime import datetime

def get_api_key() -> str:
    """Get API key from environment variable."""
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError(
            "OPENROUTER_API_KEY environment variable not set.\n"
            "Please set it using: export OPENROUTER_API_KEY='your-api-key-here'"
        )
    return api_key

def extract_technique_id(filepath: str) -> str:
    """Extract technique ID from filename."""
    basename = os.path.basename(filepath)
    match = re.search(r'(T\d+(?:\.\d+)?)', basename, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    raise ValueError(f"Could not extract technique ID from filename: {filepath}")

def load_targets_and_constraints(filepath: str) -> tuple[list, list]:
    """Load targets and constraints from the generated input file."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Execute the Python code to get targets and constraints
    namespace = {}
    try:
        exec(content, namespace)
    except Exception as e:
        raise ValueError(f"Failed to execute input file: {e}")
    
    if "targets" not in namespace:
        raise ValueError("No 'targets' variable found in input file")
    if "constraints" not in namespace:
        raise ValueError("No 'constraints' variable found in input file")
    
    return namespace["targets"], namespace["constraints"]

def format_constraints(constraints: list) -> str:
    """Format constraints list into a readable string for the prompt."""
    return "\n".join(f"- {constraint}" for constraint in constraints)

def call_openrouter(prompt: str, api_key: str, model: str = "openai/gpt-4o") -> str:
    """
    Call OpenRouter API with the given prompt.
    
    Args:
        prompt: The prompt to send
        api_key: OpenRouter API key
        model: Model to use (default: openai/gpt-4o for ChatGPT-4)
    
    Returns:
        The model's response text
    """
    client = openai.OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )
    
    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.7,
    )
    
    return response.choices[0].message.content

def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic command samples for a MITRE technique using generated input file."
    )
    parser.add_argument("input_file", help="Path to the TXXX_LLM_Input_Ready.txt file")
    parser.add_argument("--technique-description", default="", 
                       help="Optional technique description (will be used if provided)")
    parser.add_argument("--model", default="openai/gpt-4o",
                       help="OpenRouter model to use (default: openai/gpt-4o)")
    args = parser.parse_args()

    # Get API key from environment
    try:
        api_key = get_api_key()
    except ValueError as e:
        print(f"[!] Error: {e}")
        return 1

    # Extract technique ID from filename
    technique_id = extract_technique_id(args.input_file)
    
    # Load targets and constraints
    targets, constraints = load_targets_and_constraints(args.input_file)
    
    print(f"[*] Loaded {len(targets)} targets and {len(constraints)} constraints for {technique_id}")
    print(f"[*] Using model: {args.model}")
    
    # Format constraints for prompt
    constraints_text = format_constraints(constraints)
    
    # Output directory
    output_dir = f"data/samples/{technique_id}"
    os.makedirs(output_dir, exist_ok=True)

    # === GENERATION LOOP ===
    for idx, target in enumerate(targets, 1):
        platform = target["platform"]
        privilege = target["privilege"]
        shell = target["shell"]
        tool = target["tool"]

        obfuscation_level = "heavy" if tool.endswith("-obf") else "none"
        base_tool = tool.replace("-obf", "")

        # Build the technique description line
        tech_desc_line = ""
        if args.technique_description:
            tech_desc_line = f' ("{args.technique_description}")'

        prompt = f"""
You are a cybersecurity expert tasked with generating synthetic but realistic malicious command-line examples.

For MITRE ATT&CK technique {technique_id}{tech_desc_line}, generate 10 commands aligned strictly with this behavior.

Context:
- Platform: {platform}
- Privilege Level: {privilege}
- Shell: {shell}
- Tool: {base_tool}
- Obfuscation: {"Apply base64, hex, eval, or indirect execution techniques" if obfuscation_level == "heavy" else "None"}

Output exactly 10 distinct JSON entries as a list, following this format:
{{
  "technique_id": "{technique_id}",
  "platform": "{platform}",
  "shell": "{shell}",
  "command": "...",
  "explanation": "...",
  "rationale_steps": ["...", "..."],
  "obfuscation_level": "{obfuscation_level}"
}}

Constraints:
{constraints_text}
"""

        # Prompt hash for traceability
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:8]

        print(f"[*] [{idx}/{len(targets)}] Generating samples for {platform}/{privilege}/{shell}/{base_tool}...")

        try:
            response_text = call_openrouter(prompt, api_key, args.model)
        except Exception as e:
            print(f"[!] API call failed for {shell} + {base_tool}: {e}")
            continue

        # Strip markdown code blocks if present
        response_text = response_text.strip()
        if response_text.startswith("```json"):
            response_text = response_text.removeprefix("```json").removesuffix("```").strip()
        elif response_text.startswith("```"):
            response_text = response_text.removeprefix("```").removesuffix("```").strip()

        try:
            entries = json.loads(response_text)
        except json.JSONDecodeError:
            print(f"[!] Could not decode response as JSON for {shell} + {base_tool}")
            print("\n--- RAW RESPONSE ---\n")
            print(response_text)
            print("\n--- END RAW RESPONSE ---\n")
            continue

        timestamp = datetime.utcnow().isoformat() + "Z"
        seen_hashes = set()

        for entry in entries:
            entry["technique_id"] = technique_id
            entry["platform"] = platform
            entry["shell"] = shell

            raw = json.dumps(entry, sort_keys=True).encode()
            content_hash = hashlib.sha1(raw).hexdigest()[:8]
            if content_hash in seen_hashes:
                continue
            seen_hashes.add(content_hash)

            entry_id = f"SYN-{shell.upper()}-{technique_id}-{prompt_hash}-{content_hash}"
            entry["id"] = entry_id
            entry["source_prompt_hash"] = prompt_hash
            entry["timestamp_utc"] = timestamp
            entry["validation"] = {
                "syntax_ok": None,
                "llm_judge": None,
                "sandbox_trace_id": None,
                "mitre_match_score": None
            }

            filepath = os.path.join(output_dir, f"{entry_id}.json")
            with open(filepath, "w") as f:
                json.dump(entry, f, indent=2)

        print(f"[+] Generated {len(seen_hashes)} unique entries for {shell} + {base_tool}")

    print(f"\n[✓] Completed generation for technique {technique_id}")
    print(f"[✓] Total targets processed: {len(targets)}")
    print(f"[✓] Output directory: {output_dir}")

if __name__ == "__main__":
    exit(main() or 0)