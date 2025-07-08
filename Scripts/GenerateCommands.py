# This file creates synthetic command material in a specific JSON format. Currently configured for 1611

import openai
import time
import json
import os
import hashlib
from datetime import datetime

# === CONFIGURATION ===
openai.api_key = "api-key-here"
assistant_id = "assistant-id-here"
technique_id = "T1611"
technique_description = "Escape the constraints of a privileged container and execute commands on the host system."

# Output directory
output_dir = f"data/samples/{technique_id}"
os.makedirs(output_dir, exist_ok=True)

# Shell/Platform combinations
targets = [
    # LINUX CONTAINER SCENARIOS
    {"platform": "linux", "privilege": "root", "shell": "bash", "tool": "bash"},
    {"platform": "linux", "privilege": "root", "shell": "sh", "tool": "sh"},
    {"platform": "linux", "privilege": "root", "shell": "bash", "tool": "docker"},
    {"platform": "linux", "privilege": "user", "shell": "bash", "tool": "unshare"},
    {"platform": "linux", "privilege": "root", "shell": "zsh", "tool": "zsh"},
    {"platform": "linux", "privilege": "user", "shell": "bash", "tool": "nsenter"},

    # WINDOWS CONTAINER SCENARIOS
    {"platform": "windows", "privilege": "Administrator", "shell": "powershell", "tool": "powershell"},
    {"platform": "windows", "privilege": "SYSTEM", "shell": "powershell", "tool": "docker"},
    {"platform": "windows", "privilege": "Administrator", "shell": "cmd", "tool": "cmd"},
    {"platform": "windows", "privilege": "user", "shell": "powershell", "tool": "powershell"},

    # MACOS (for theoretical coverage)
    {"platform": "macos", "privilege": "user", "shell": "zsh", "tool": "bash"},
    {"platform": "macos", "privilege": "root", "shell": "bash", "tool": "launchctl"},
]

# === GENERATION LOOP ===
for target in targets:
    platform = target["platform"]
    privilege = target["privilege"]
    shell = target["shell"]
    tool = target["tool"]

    prompt = f"""
You are a cybersecurity expert tasked with generating synthetic but realistic malicious command-line examples.

Use the attached file containing MITRE ATT&CK techniques as your sole source of truth.
For technique {technique_id}, retrieve the technique name and description from the file, and use them to generate 10 commands aligned strictly with that behavior.

Context:
- Platform: {platform}
- Privilege Level: {privilege}
- Shell: {shell}
- Tool: {tool}

Return exactly 10 distinct JSON entries in a list. Each should follow this structure:
{{
  "technique_id": "{technique_id}",
  "platform": "{platform}",
  "shell": "{shell}",
  "command": "...",
  "explanation": "...",
  "rationale_steps": ["...", "..."],
  "obfuscation_level": "none"
}}

Constraints:
- Each command must align ONLY with technique {technique_id}.
- Each must be syntactically correct and realistically usable.
- Do NOT include examples that fit other ATT&CK techniques.
- Make all examples distinct, grounded in adversarial behavior relevant to the technique.
- Use only the information retrieved from the provided MITRE technique file.
- Do not output anything except the JSON list.
"""

    # Create prompt hash for traceability
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:8]

    # Create thread
    thread = openai.beta.threads.create()
    openai.beta.threads.messages.create(thread_id=thread.id, role="user", content=prompt)
    run = openai.beta.threads.runs.create(thread_id=thread.id, assistant_id=assistant_id)

    # Wait for completion
    while True:
        run_status = openai.beta.threads.runs.retrieve(thread_id=thread.id, run_id=run.id)
        if run_status.status == "completed":
            break
        elif run_status.status == "failed":
            print(f"[!] Run failed for shell: {shell}")
            break
        time.sleep(2)

    # Retrieve messages
    messages = openai.beta.threads.messages.list(thread_id=thread.id)
    response_text = ""
    for message in messages.data:
        if message.role == "assistant":
            response_text += message.content[0].text.value

    # Remove ```json wrappers if present
    if response_text.strip().startswith("```json"):
        response_text = response_text.strip().removeprefix("```json").removesuffix("```").strip()

    try:
        entries = json.loads(response_text)
    except json.JSONDecodeError:
        print(f"[!] Could not decode response as JSON for shell: {shell}")
        print("\n--- RAW RESPONSE ---\n")
        print(response_text)
        print("\n--- END RAW RESPONSE ---\n")
        continue

    # Save entries
    timestamp = datetime.utcnow().isoformat() + "Z"
    seen_hashes = set()

    for entry in entries:
        # Force correct shell/platform in case LLM deviates
        entry["technique_id"] = technique_id
        entry["platform"] = platform
        entry["shell"] = shell

        # Create hash-based ID
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

    print(f"[+] Generated {len(seen_hashes)} unique entries for {shell} at {output_dir}")
