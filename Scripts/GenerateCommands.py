"""
This script automates the generation of synthetic, adversarial command-line samples 
for the MITRE ATT&CK technique T1612 ("Build Image on Host") using OpenAI's Assistant API
and model GPT 4 Turbo.

Key features:
- Iterates over a predefined list of platform, shell, privilege, and tool combinations 
  (including Linux, Windows, Kubernetes, Python, Go, Docker, Podman, Buildah, etc.).
- Sends structured prompts to GPT-4 Turbo (via Assistant) to generate 10 malicious command 
  samples per target referencing the MITRE JSON in files with information about the 
  technique, including variants with obfuscation (e.g., base64, hex, eval).
- Collects generated JSON outputs, enriches them with metadata (ID, timestamp, hashes), 
  and saves each as an individual .json file for further analysis.
- Ensures traceability by including prompt hashes and unique content hashes in filenames.
- The output directory is organized under data/samples/{technique_id}/ and ready 
  for static and semantic evaluation pipelines.

Main use case:
This script serves as the first stage of a larger research pipeline to synthetically 
augment cybersecurity datasets with realistic but controlled malicious examples 
to improve the evaluation and training of detection systems.
"""

import openai
import time
import json
import os
import hashlib
from datetime import datetime

# === CONFIGURATION ===
openai.api_key = "key here"
assistant_id = "assistant id here"
technique_id = "T1612"
technique_description = "Build a container image directly on a host to embed malicious content, avoiding detection by using vanilla base images."

# Output directory
output_dir = f"data/samples/{technique_id}"
os.makedirs(output_dir, exist_ok=True)

# Target combinations
targets = [
    # Linux host CLI tools
    {"platform": "linux", "privilege": "docker_group", "shell": "bash", "tool": "docker"},
    {"platform": "linux", "privilege": "docker_group", "shell": "bash", "tool": "podman"},
    {"platform": "linux", "privilege": "root", "shell": "bash", "tool": "buildah"},
    {"platform": "linux", "privilege": "docker_group", "shell": "bash", "tool": "nerdctl"},
    {"platform": "linux", "privilege": "docker_group", "shell": "bash", "tool": "docker-remote"},

    # Kubernetes in-cluster build systems
    {"platform": "linux", "privilege": "cluster_admin", "shell": "bash", "tool": "kaniko"},

    # Programming triggers
    {"platform": "linux", "privilege": "docker_group", "shell": "python", "tool": "docker-py"},
    {"platform": "linux", "privilege": "docker_group", "shell": "go", "tool": "docker-go-client"},

    # Windows Docker host
    {"platform": "windows", "privilege": "Administrator", "shell": "powershell", "tool": "docker"},

    # Obfuscated variants
    {"platform": "linux", "privilege": "docker_group", "shell": "bash", "tool": "docker-obf"},
    {"platform": "windows", "privilege": "Administrator", "shell": "powershell", "tool": "docker-obf"},
]

# === GENERATION LOOP ===
for target in targets:
    platform = target["platform"]
    privilege = target["privilege"]
    shell = target["shell"]
    tool = target["tool"]

    obfuscation_level = "heavy" if tool.endswith("-obf") else "none"
    base_tool = tool.replace("-obf", "")

    prompt = f"""
You are a cybersecurity expert tasked with generating synthetic but realistic malicious command-line examples.

For MITRE ATT&CK technique {technique_id} ("Build Image on Host"), generate 10 commands aligned strictly with this behavior.

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
- Commands must specifically focus on building container images on the host that embed malicious components or payloads.
- No overlapping ATT&CK techniques.
- Use realistic tooling: docker build, podman build, buildah bud, nerdctl build, kaniko, docker-py, docker-go-client.
- Include programming/script-based examples (Python, Go, PowerShell) where appropriate.
- If obfuscation is requested, apply base64 encoding, hex escapes, eval, aliases, or indirect payload fetching.
- Return ONLY valid JSON without markdown, comments, or explanation. Begin directly with open curly brace and provide just the JSON object.
"""

    # Prompt hash for traceability
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:8]

    # Run assistant
    thread = openai.beta.threads.create()
    openai.beta.threads.messages.create(thread_id=thread.id, role="user", content=prompt)
    run = openai.beta.threads.runs.create(thread_id=thread.id, assistant_id=assistant_id)

    # Wait for completion
    while True:
        run_status = openai.beta.threads.runs.retrieve(thread_id=thread.id, run_id=run.id)
        if run_status.status == "completed":
            break
        elif run_status.status == "failed":
            print(f"[!] Run failed for {shell} + {base_tool}")
            break
        time.sleep(2)

    # Retrieve messages
    messages = openai.beta.threads.messages.list(thread_id=thread.id)
    response_text = ""
    for message in messages.data:
        if message.role == "assistant":
            response_text += message.content[0].text.value

    if response_text.strip().startswith("```json"):
        response_text = response_text.strip().removeprefix("```json").removesuffix("```").strip()

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

    print(f"[+] Generated {len(seen_hashes)} unique entries for {shell} + {base_tool} at {output_dir}")