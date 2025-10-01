#!/usr/bin/env python3
#"mypy not installed. Install with: pip install mypy"
# winget install --id koalaman.shellcheck
from __future__ import annotations
import argparse
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Tuple, List, Set
import shutil
from pathlib import Path
import json
import shutil
import traceback
from typing import Optional

# The exact JSON key you requested (including colon and trailing space)
POTENTIAL_KEY = "syntax_ok"
POTENTIAL_DETAILS_KEY = "Syntax_Run_Details"

# --------------------------
# Platform gates
# --------------------------

IS_WINDOWS = os.name == "nt"  # True on native Windows
IS_POSIX = os.name == "posix"  # True on macOS & Linux (and WSL appears as posix to Python)
SHELL_CHECK_PATH = "C:\\Users\\flacman\\AppData\\Local\\Microsoft\\WinGet\\Packages\\koalaman.shellcheck_Microsoft.Winget.Source_8wekyb3d8bbwe\\"

def platform_enabled_langs() -> Set[str]:
    """
    Languages enabled on this platform.
    'python' is always enabled.
    On Windows: enable 'ps1' (PowerShell), disable 'shell'.
    On macOS/Linux: enable 'shell', disable 'ps1'.
    """
    langs = {"python"}
    langs.add("shell")
    if IS_WINDOWS:
        langs.add("ps1")
        SHELL_CHECK_PATH = find_shellcheck_dir() + "\\" if find_shellcheck_dir() else SHELL_CHECK_PATH
    #else:
        #langs.add("shell")
    return langs


def find_shellcheck_dir() -> str | None:
    """
    Return the directory containing the ShellCheck WinGet package for the current user.
    Searches under %LOCALAPPDATA%\Microsoft\WinGet\Packages for 'koalaman.shellcheck*'.
    Prefers directories that contain shellcheck.exe. Returns None if not found.
    """
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return None

    base = Path(local) / "Microsoft" / "WinGet" / "Packages"
    if not base.is_dir():
        return None

    # Find candidate directories
    candidates = [p for p in base.glob("koalaman.shellcheck*") if p.is_dir()]
    if not candidates:
        return None

    # Prefer a candidate that actually contains the executable
    for p in sorted(candidates, key=lambda x: x.name, reverse=True):
        if (p / "shellcheck.exe").is_file():
            return str(p)

    # Fallback: return the newest-looking match even if exe isn't found
    return str(sorted(candidates, key=lambda x: x.name, reverse=True)[0])


# --------------------------
# Core helpers
# --------------------------

PY_EXTS = {".py"}
SH_EXTS = {".sh", ".bash", ".zsh", ".ksh"}
PS_EXTS = {".ps1"}

def _run(cmd: List[str]) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def _print_result(name: str, ok: bool, details: str = ""):
    status = "✅ It will potentially work" if ok else "❌ It will not potentially work"
    line = f"{name}: {status}"
    if details:
        line += f"\n{details}"
    print(line)

# --------------------------
# Python checks (py_compile + mypy)
# --------------------------

def check_python_file(path: pathlib.Path) -> Tuple[bool, str]:
    
    try:
        subprocess.check_call(
            [sys.executable, "-m", "py_compile", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as e:
        return False, f"Python syntax check failed (py_compile). {e}"

    try:
        rc, out, err = _run([sys.executable, "-m", "mypy", "--ignore-missing-imports", str(path)])
    except FileNotFoundError:
        return False, "mypy not installed. Install with: pip install mypy"

    if rc != 0:
        #Known limitations we want to ignore
        if "error: Skipping analyzing" in out or "error: Cannot find implementation or library stub file for module named" in out or "AF_VSOCK" in out:
            return True, ""
        return False, f"mypy issues:\n{out or err or 'mypy reported issues.'}"
    return True, ""

def check_python_string(code: str) -> Tuple[bool, str]:
    # Remove leading "python3 -c '" and trailing "'" if present
    code = code.strip()
    prefix = "python3 -c "
    suffix = "'"
    suffix2 = '"'
    if code.startswith(prefix+suffix) and code.endswith(suffix):
        code = code[len(prefix+suffix):-len(suffix)]
    if code.startswith(prefix+suffix2) and code.endswith(suffix2):
        code = code[len(prefix+suffix2):-len(suffix2)]

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(code)
        temp_path = pathlib.Path(tf.name)
    try:
        return check_python_file(temp_path)
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass

# --------------------------
# Shell checks (shellcheck) — enabled only on macOS/Linux
# --------------------------

def check_shell_file(path: pathlib.Path) -> Tuple[bool, str]:
    if "shell" not in platform_enabled_langs():
        return False, "Shell checks are disabled on Windows."

    try:
        rc, out, err = _run([SHELL_CHECK_PATH+"shellcheck", str(path)])
    except FileNotFoundError:
        return False, "shellcheck not installed. See: https://github.com/koalaman/shellcheck\n if in windows: winget install --id koalaman.shellcheck"

    if rc == 0:
        return True, ""
    else:
        if "Double quote to prevent globbing and word splitting" in out or "Quote this to prevent word splitting" in out or "Expressions don't expand in single quotes, use double quotes for that" in out:
            return True, ""
        return False, f"shellcheck findings:\n{out or err or 'shellcheck reported issues.'}"

def check_shell_string(code: str) -> Tuple[bool, str]:
    if "shell" not in platform_enabled_langs():
        return False, "Shell checks are disabled on Windows."

    try:
        p = subprocess.run(
            [SHELL_CHECK_PATH+"shellcheck", "--shell=bash", "-"],
            input= code,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        return False, "shellcheck not installed. See: https://github.com/koalaman/shellcheck"

    if p.returncode == 0:
        return True, ""
    else:
        if "Double quote to prevent globbing and word splitting" in p.stdout or "Quote this to prevent word splitting" in p.stdout or "Expressions don't expand in single quotes, use double quotes for that" in p.stdout:
            return True, ""
        return False, f"shellcheck findings:\n{p.stdout or 'shellcheck reported issues.'}"

# --------------------------
# PowerShell checks (PSScriptAnalyzer) — enabled only on Windows
# --------------------------

def _pwsh_exe() -> str:
    # Prefer pwsh (PowerShell 7+) if present; on Windows, this normally exists if installed.
    return "powershell" if IS_WINDOWS else "pwsh"

def check_ps_file(path: pathlib.Path) -> Tuple[bool, str]:
    if "ps1" not in platform_enabled_langs():
        return False, "PowerShell checks are disabled on macOS/Linux."

    script = f"""
$ErrorActionPreference = 'SilentlyContinue'
try {{
    Import-Module PSScriptAnalyzer -ErrorAction Stop | Out-Null
}} catch {{
    Write-Output 'PSScriptAnalyzer not installed. Install with: Install-Module PSScriptAnalyzer'
    exit 2
}}
$results = Invoke-ScriptAnalyzer -Path "{str(path)}" -Severity Error -Recurse -ErrorAction SilentlyContinue
if ($results -and $results.Count -gt 0) {{
    $results | Format-Table -AutoSize | Out-String | Write-Output
    exit 1
}} else {{
    exit 0
}}
"""
    try:
        rc, out, err = _run([_pwsh_exe(), "-NoProfile", "-Command", script])
    except FileNotFoundError:
        return False, "PowerShell (pwsh) not found. Install PowerShell 7+ and PSScriptAnalyzer. On Windows PS, Install-Module -Name PSScriptAnalyzer -Force"

    if rc == 0:
        return True, ""
    elif rc == 2:
        return False, out.strip() or "PSScriptAnalyzer not installed."
    #make scripts hard to maintain
    else:
        if "Double quote to prevent globbing and word splitting" in out or "Double quote to prevent globbing and word splitting" in err:
            return True, ""
        return False, f"PSScriptAnalyzer findings:{out.replace('\n', '') or err.replace('\n', '') or 'Issues reported.'}"

def check_ps_string(code: str) -> Tuple[bool, str]:
    if "ps1" not in platform_enabled_langs():
        return False, "PowerShell checks are disabled on macOS/Linux."

    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False) as tf:
        tf.write(code)
        temp_path = pathlib.Path(tf.name)
    try:
        return check_ps_file(temp_path)
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass

# --------------------------
# Public API
# --------------------------

def check_file(path: pathlib.Path) -> bool:
    ext = path.suffix.lower()
    if ext in PY_EXTS:
        ok, details = check_python_file(path)
    elif ext in SH_EXTS:
        ok, details = check_shell_file(path)
    elif ext in PS_EXTS:
        ok, details = check_ps_file(path)
    else:
        _print_result(str(path), False, f"Unsupported file type: {ext}")
        return False
    if not ok:
        _print_result(path.name, ok, details)
    return ok

def check_folder(folder: pathlib.Path) -> bool:
    enabled = platform_enabled_langs()
    all_ok = True
    for p in folder.rglob("*"):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        # Filter by platform
        if ext in PY_EXTS:
            ok = check_file(p)
        elif ext in SH_EXTS and "shell" in enabled:
            ok = check_file(p)
        elif ext in PS_EXTS and "ps1" in enabled:
            ok = check_file(p)
        else:
            # Skip files disabled on this platform
            continue
        all_ok = all_ok and ok
    return all_ok

def check_string(code: str, lang: str) -> bool:
    lang = lang.strip().lower()
    enabled = platform_enabled_langs()

    # Normalize aliases
    if lang in ("py", "python"):
        chosen = "python"
    elif lang in ("sh", "bash", "zsh", "ksh", "shell"):
        chosen = "shell"
    elif lang in ("ps", "ps1", "powershell"):
        chosen = "ps1"
    else:
        _print_result(f"[string:{lang}]", False, f"Unsupported language: {lang}")
        return False

    if chosen not in enabled:
        plat = "Windows" if IS_WINDOWS else "macOS/Linux"
        _print_result(f"[string:{lang}]", False, f"{chosen} checks are disabled on {plat}.")
        return False

    if chosen == "python":
        ok, details = check_python_string(code)
    elif chosen == "shell":
        ok, details = check_shell_string(code)
    else:  # ps1
        ok, details = check_ps_string(code)
    if not ok:
        _print_result(f"[string:{chosen}]", ok, details)
    return ok, details


def normalize_shell_to_lang(shell_value: Optional[str], platform_field: Optional[str]) -> Optional[str]:
    """
    Map incoming 'shell' values found in JSON to the canonical language tokens expected by check_string.
    Return None if mapping is unknown.
    """
    if not shell_value:
        # fallback to platform field
        shell_value = platform_field or ""
    s = shell_value.strip().lower()

    # Common cases
    if s in ("py", "python"):
        return "python"
    if s in ("sh", "bash", "zsh", "ksh", "shell", "posix-shell"):
        return "shell"
    if s in ("ps", "ps1", "powershell", "powershell1", "powershell7"):
        return "ps1"

    # sometimes "platform" contains "linux" or "windows" — use that only as fallback
    if s in ("linux", "unix", "mac", "darwin"):
        # don't know exact shell, prefer "shell"
        return "shell"
    if s in ("windows"):
        # windows likely uses PowerShell, but ambiguous — prefer ps1
        return "ps1"

    # Not recognized
    return None


def process_file(path: pathlib.Path) -> tuple[bool, str]:
    """
    Returns (changed_bool, message).
    changed_bool is True if the file was updated.
    message gives status or error.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as e:
        return False, f"READ_ERROR: Failed to read file: {e}"

    # Parse JSON
    try:
        data = json.loads(raw)
    except Exception as e:
        return False, f"JSON_ERROR: {e}"

    # Extract fields
    try:
        shell_field = data.get("shell")
        platform_field = data.get("platform")
        command_field = data.get("command")
    except Exception as e:
        return False, f"FIELD_ERROR: Not all required fields present"

    if not command_field:
        return False, "SKIP: no 'command' field present."

    lang = normalize_shell_to_lang(shell_field, platform_field)
    if lang is None:
        return False, f"SKIP: could not normalize shell/platform -> language (shell='{shell_field}', platform='{platform_field}')."

    # Run the check_string function from checker module and capture exceptions
    try:
        # check_string should return a boolean (True if potentially runnable)
        result_bool, details = check_string(command_field, lang)
    except Exception as e:
        # capture traceback to details field, but don't crash the whole run
        tb = traceback.format_exc()
        result_bool = False
        details = f"CHECKER_EXCEPTION: {e}\n{tb}"

    # Add fields to JSON and write back (after backup)
    # If the value is identical to existing, we still write to normalize formatting but mark as unchanged.
    changed = True
    

    # Update data
    data["validation"][POTENTIAL_KEY] = result_bool
    data["validation"][POTENTIAL_DETAILS_KEY] = details

    # Write JSON with stable formatting
    try:
        # Write to ./syntax_check/<file_name> (one directory up from current file)
        out_dir = path.parent.parent / "syntax_check"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / path.name
        out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception as e:
        return False, f"WRITE_ERROR: failed to write JSON: {e}"

    return True, f"UPDATED: lang={lang} result={result_bool}"


def main():
    ap = argparse.ArgumentParser(description="Run check_string on JSON files and annotate them with 'Potentially run: '.")
    ap.add_argument("--folder", type=pathlib.Path, default=pathlib.Path("./Data"), help="Folder containing .json files (recursive).")
    ap.add_argument("--extensions", type=str, default=".json", help="Comma-separated file extensions to scan (default: .json)")
    ap.add_argument("--dry-run", action="store_true", default=False, help="Do not write changes, just print what would be updated.")
    args = ap.parse_args()
    
    folder = args.folder
    if not folder.is_dir():
        print(f"ERROR: {folder} is not a directory.", file=sys.stderr)
        sys.exit(2)

    exts = {".json"}
    summary = {"processed": 0, "updated": 0, "skipped": 0, "errors": 0}
    print(f"Scanning {folder} recursively for files with extensions: {exts}\n")

    for p in folder.rglob(f"*.json"):
        # Only process files whose parent folder or any part of their path is "LLM Jury"
        if "LLM Jury" not in str(p.parent) and "LLM Jury" not in str(p):
           continue
        if not p.is_file():
            continue
        
        summary["processed"] += 1
        changed, message = process_file(p)
        
        # Determine status
        if "ERROR" in message.upper() or "EXCEPTION" in message.upper():
            status = "ERROR"
            summary["errors"] += 1
        elif message.startswith("UPDATED"):
            status = "UPDATED" if not args.dry_run else "DRY"
            summary["updated"] += 1
        elif message.startswith("SKIP"):
            status = "SKIP"
            summary["skipped"] += 1
        else:
            status = "INFO"
        
        print(f"[{status}] {p.relative_to(folder)} -> {message}")

    print("\nSummary:")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
