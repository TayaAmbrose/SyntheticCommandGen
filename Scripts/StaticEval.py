"""
This script performs static validation checks on synthetic command-line samples 
generated for the MITRE ATT&CK technique T1612 ("Build Image on Host").

Key features:
- Iterates through all .json sample files in the specified directory.
- Runs shell-specific syntax checks:
    • bash/sh/zsh: using shell -n
    • PowerShell: using PSParser tokenization
    • cmd (Windows): using cmd /C
- Scans commands for forbidden patterns:
    • IP addresses
    • Domain names (e.g., .com, .net, .io)
    • Credential keywords (e.g., password, token, apikey)
- Calculates string entropy to detect suspiciously obfuscated commands 
  (e.g., high randomness often indicates base64, hex, or encoded payloads).
- Flags commands exceeding entropy and length thresholds.
- Updates each sample’s JSON file by adding a 'validation.syntax_ok' block 
  with the following details:
    • pass (True/False/None)
    • forbidden_tokens (True/False)
    • obfuscation_suspicious (True/False)
    • obfuscation_entropy (float)
    • command_length (int)

Main purpose:
This script acts as the static analysis stage of the evaluation pipeline, 
helping identify malformed, dangerous, or suspicious command samples 
before they proceed to dynamic LLM-based evaluation.

NOTE: This file does not check Python or Go. These are flagged for later
and checked by LLM Jury.
"""

import os
import json
import tempfile
import subprocess
import re
import math
from collections import Counter

# === CONFIGURATION ===
sample_dir = "data/samples/T1612"

# === FORBIDDEN PATTERNS ===
forbidden_patterns = [
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b",  # IP address
    r"\b[a-zA-Z0-9.-]+\.(com|net|org|io|ru|cn|xyz)\b",  # domain
    r"\b(password|passwd|secret|token|apikey)\b",  # credential terms
]

# === ENTROPY CALCULATION ===
def calculate_entropy(s):
    if not s:
        return 0
    counts = Counter(s)
    probs = [count / len(s) for count in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

# === SYNTAX CHECK ===
def check_syntax(shell, command):
    try:
        if shell in ["bash", "sh", "zsh"]:
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".sh", delete=False) as temp:
                temp.write(command)
                temp.flush()
                result = subprocess.run([shell, "-n", temp.name],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return result.returncode == 0

        elif shell == "powershell":
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".ps1", delete=False) as temp:
                temp.write(command)
                temp.flush()
                ps_script = f"""[System.Management.Automation.PSParser]::Tokenize((Get-Content '{temp.name}' -Raw), [ref]$null)"""
                result = subprocess.run(["pwsh", "-Command", ps_script],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return result.returncode == 0 and b"Unexpected token" not in result.stderr

        elif shell == "cmd":
            result = subprocess.run(f'cmd /C ""{command}""',
                                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0

        else:
            return None  # unsupported shell

    except Exception as e:
        print(f"[!] Error checking {shell} command: {e}")
        return False

# === MAIN LOOP ===
for file in os.listdir(sample_dir):
    if not file.endswith(".json"):
        continue

    file_path = os.path.join(sample_dir, file)
    with open(file_path, "r") as f:
        data = json.load(f)

    shell = data.get("shell", "").lower()
    command = data.get("command", "")

    # Static checks
    is_valid_syntax = check_syntax(shell, command)
    forbidden_found = any(re.search(pattern, command, re.IGNORECASE) for pattern in forbidden_patterns)
    entropy = calculate_entropy(command)
    length = len(command)
    suspicious_obfuscation = (entropy > 4.5 and length > 200)  # tweak threshold as needed

    # Prepare new nested validation block
    data.setdefault("validation", {})
    data["validation"]["syntax_ok"] = {
        "pass": is_valid_syntax,
        "forbidden_tokens": forbidden_found,
        "obfuscation_suspicious": suspicious_obfuscation,
        "obfuscation_entropy": round(entropy, 2),
        "command_length": length
    }

    # Preserve other fields
    data["validation"].setdefault("llm_judge", None)
    data["validation"].setdefault("sandbox_trace_id", None)
    data["validation"].setdefault("mitre_match_score", None)

    # Save updated file
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[✓] {file} — pass: {is_valid_syntax}, forbidden: {forbidden_found}, "
          f"entropy: {entropy:.2f}, length: {length}, suspicious: {suspicious_obfuscation}")