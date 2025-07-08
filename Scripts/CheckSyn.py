# This file checks the syntax of the generated samples.

import os
import json
import tempfile
import subprocess
from collections import OrderedDict

# Path to your generated sample files
sample_dir = "data/samples/T1611"

# Shell-to-syntax-check logic
def check_syntax(shell, command):
    try:
        if shell in ["bash", "sh", "zsh"]:
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".sh", delete=False) as temp:
                temp.write(command)
                temp.flush()
                result = subprocess.run(
                    [shell, "-n", temp.name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                return result.returncode == 0

        elif shell == "powershell":
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".ps1", delete=False) as temp:
                temp.write(command)
                temp.flush()
                ps_script = f"""[System.Management.Automation.PSParser]::Tokenize((Get-Content '{temp.name}' -Raw), [ref]$null)"""
                result = subprocess.run(
                    ["pwsh", "-Command", ps_script],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                return result.returncode == 0 and b"Unexpected token" not in result.stderr

        elif shell == "cmd":
            # Windows-only best-effort check
            result = subprocess.run(
                f'cmd /C ""{command}""',
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return result.returncode == 0

        else:
            return None  # unsupported shell

    except Exception as e:
        print(f"[!] Error checking {shell} command: {e}")
        return False


# Loop through JSON files
for file in os.listdir(sample_dir):
    if not file.endswith(".json"):
        continue

    file_path = os.path.join(sample_dir, file)

    with open(file_path, "r") as f:
        data = json.load(f)

    shell = data.get("shell", "").lower()
    command = data.get("command", "")
    is_valid = check_syntax(shell, command)

    # Update validation block
    if "validation" not in data:
        data["validation"] = {}

    data["validation"]["syntax_ok"] = is_valid

    # Overwrite the file with updated result
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[+] Checked {file} — syntax_ok: {is_valid}")
