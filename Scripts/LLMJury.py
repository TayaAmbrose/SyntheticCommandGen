"""
This script performs semantic validation (LLM jury evaluation) on synthetic command-line 
samples for the MITRE ATT&CK technique T1612 ("Build Image on Host") using OpenAI's Assistant API.

Key features:
- Iterates through all .json sample files in a specified input directory.
- Builds a structured evaluation prompt for each sample, referencing the MITRE technique 
  description and asking the LLM to rate it across five criteria:
    1. Category fit
    2. Attack realism
    3. Maliciousness
    4. Technical plausibility
    5. Privilege relevance
- Sends the prompt to GPT-4 Turbo (via Assistant API) and retrieves a strictly JSON-formatted response.
- Calculates a weighted average score and maps it to a final verdict 
  ("likely_match", "uncertain", or "likely_mismatch").
- Appends the evaluation results to the sample’s JSON under the 'validation' field and saves 
  the updated file to a designated output folder.

Main purpose:
This script acts as the second-stage validation pipeline in the research project, 
providing automated, explainable semantic judgments on the quality and alignment 
of synthetic adversarial commands relative to their intended ATT&CK technique.
"""

import os
import json
import time
import re
import openai
from datetime import datetime

# === CONFIGURATION ===
openai.api_key = "api key here"
assistant_id = "assistant id here"

input_folder = "data/samples/T1612"
output_folder = os.path.join(input_folder, "llm_jury_verdict")
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
        f"You are a cybersecurity evaluator with access to the MITRE ATT&CK technique database loaded as JSON.\n"
        f"Refer explicitly to the JSON record for technique {data['technique_id']} as your sole source of truth for category fit evaluation.\n\n"
        f"MITRE ATT&CK Technique ID: {data['technique_id']}\n"
        f"Technique Description (from JSON): {mitre_description}\n\n"
        f"Evaluate the following sample:\n"
        f"Command: {data['command']}\n"
        f"Explanation: {data['explanation']}\n"
        f"Platform: {data.get('platform')}\n"
        f"Privilege: {data.get('privilege')}\n"
        f"Shell: {data.get('shell')}\n\n"
        f"For each metric below, assign a numeric score between 0 (not at all) and 1 (perfect fit), only numeric values, no words:\n"
        f"- category_fit\n"
        f"- attack_realism\n"
        f"- maliciousness\n"
        f"- technical_plausibility\n"
        f"- privilege_relevance\n\n"
        f"Finally, provide a brief one-sentence explanation of your reasoning.\n\n"
        f"Output strictly as JSON like:\n"
        f'{{"category_fit": 0.9, "attack_realism": 0.85, "maliciousness": 0.8, "technical_plausibility": 0.9, "privilege_relevance": 0.85, "explanation": "Example reason here."}}'
    )

# === VERDICT CALCULATOR ===
def compute_final_score(scores):
    weights = {
        "category_fit": 0.3,
        "attack_realism": 0.2,
        "maliciousness": 0.2,
        "technical_plausibility": 0.2,
        "privilege_relevance": 0.1
    }
    total = sum(scores[k] * weights[k] for k in weights)
    return round(total, 3)

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

    # Create thread and run assistant
    thread = openai.beta.threads.create()
    openai.beta.threads.messages.create(thread_id=thread.id, role="user", content=prompt)
    run = openai.beta.threads.runs.create(thread_id=thread.id, assistant_id=assistant_id)

    while True:
        run_status = openai.beta.threads.runs.retrieve(thread_id=thread.id, run_id=run.id)
        if run_status.status == "completed":
            break
        elif run_status.status == "failed":
            print(f"[!] Run failed for: {fname}")
            continue
        time.sleep(2)

    # Get and clean LLM response
    messages = openai.beta.threads.messages.list(thread_id=thread.id)
    assistant_reply = ""
    for msg in messages.data:
        if msg.role == "assistant":
            assistant_reply += msg.content[0].text.value

    cleaned_reply = clean_llm_response(assistant_reply)
    try:
        eval_result = json.loads(cleaned_reply)
    except json.JSONDecodeError:
        print(f"[!] JSON parse error in {fname}")
        continue

    # Compute final weighted score and verdict
    final_score = compute_final_score(eval_result)
    verdict = get_verdict(final_score)

    # Build judgment entry
    llm_judgment = {
        "model": "gpt-4-turbo",
        "score": final_score,
        "category_fit": eval_result.get("category_fit"),
        "attack_realism": eval_result.get("attack_realism"),
        "maliciousness": eval_result.get("maliciousness"),
        "technical_plausibility": eval_result.get("technical_plausibility"),
        "privilege_relevance": eval_result.get("privilege_relevance"),
        "reason": eval_result.get("explanation"),
        "timestamp": now()
    }

    # Update file with verdict
    data.setdefault("validation", {})
    data["validation"].setdefault("llm_judgments", [])
    data["validation"]["llm_judgments"].append(llm_judgment)
    data["validation"]["llm_average_score"] = final_score
    data["validation"]["llm_verdict"] = verdict

    with open(os.path.join(output_folder, fname), "w") as out:
        json.dump(data, out, indent=2)

    print(f"[✓] {fname} → final_score: {final_score}, verdict: {verdict}")

































# import os
# import json
# import time
# import openai
# from datetime import datetime
# import re

# # === CONFIGURATION ===
# openai.api_key = "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"
# assistant_id = "asst_V7Y4yzlKCiQu13PgPNcW2az6"

# input_folder = "data/samples/T1612"
# output_folder = os.path.join(input_folder, "llm_jury_verdict")
# os.makedirs(output_folder, exist_ok=True)

# # === TIME ===
# def now():
#     return datetime.utcnow().isoformat() + "Z"

# # === PROMPT BUILDER ===
# def build_prompt(data):
#     return (
#         f"Evaluate whether the following command aligns with MITRE ATT&CK Technique {data['technique_id']}.\n\n"
#         f"Command: {data['command']}\n\n"
#         f"Explanation: {data['explanation']}\n\n"
#         f"Give a confidence score from 0 (no match) to 1 (perfect match) and explain your reasoning briefly in one or two sentences. "
#         f"Do not use markdown or formatting characters like **. Output only the score and reasoning."
#     )

# # === RESPONSE PARSER ===
# def parse_response(response):
#     # Extract score
#     score_match = re.search(r"([0-1](?:\.\d+)?)", response)
#     score = float(score_match.group(1)) if score_match else None

#     # Remove score from beginning of response
#     reason = response.strip()
#     if score_match:
#         score_str = score_match.group(1)
#         reason = re.sub(rf"^{re.escape(score_str)}\s*[\:\-–]*\s*", "", reason, count=1)

#     # Remove markdown artifacts
#     reason = re.sub(r"\*\*|^-", "", reason).strip()

#     return score, reason

# # === VERDICT ===
# def get_verdict(score):
#     if score is None:
#         return "unknown"
#     elif score >= 0.85:
#         return "likely_match"
#     elif score >= 0.65:
#         return "uncertain"
#     else:
#         return "likely_mismatch"

# # === MAIN LOOP ===
# for fname in os.listdir(input_folder):
#     if not fname.endswith(".json"):
#         continue

#     filepath = os.path.join(input_folder, fname)
#     with open(filepath, "r") as f:
#         data = json.load(f)

#     prompt = build_prompt(data)

#     # Create a thread and send prompt
#     thread = openai.beta.threads.create()
#     openai.beta.threads.messages.create(
#         thread_id=thread.id,
#         role="user",
#         content=prompt
#     )
#     run = openai.beta.threads.runs.create(
#         thread_id=thread.id,
#         assistant_id=assistant_id
#     )

#     # Wait for run to complete
#     while True:
#         run_status = openai.beta.threads.runs.retrieve(thread_id=thread.id, run_id=run.id)
#         if run_status.status == "completed":
#             break
#         elif run_status.status == "failed":
#             print(f"[!] Run failed for: {fname}")
#             break
#         time.sleep(1)

#     # Retrieve reply
#     messages = openai.beta.threads.messages.list(thread_id=thread.id)
#     for msg in messages.data:
#         if msg.role == "assistant":
#             raw_response = msg.content[0].text.value.strip()
#             score, reason = parse_response(raw_response)

#             timestamp = now()
#             judgment = {
#                 "model": "gpt-4-turbo",
#                 "score": score,
#                 "reason": reason,
#                 "timestamp": timestamp
#             }

#             # Inject judgment into data
#             data.setdefault("validation", {})
#             data["validation"]["llm_judgments"] = [judgment]
#             data["validation"]["llm_average_score"] = score
#             data["validation"]["llm_verdict"] = get_verdict(score)

#             # Save new file
#             with open(os.path.join(output_folder, fname), "w") as out:
#                 json.dump(data, out, indent=2)

#             print(f"Processed {fname} → verdict: {data['validation']['llm_verdict']}")













# import os
# import json
# import time
# import openai
# from datetime import datetime

# # === CONFIGURATION ===
# openai.api_key = "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"
# assistant_id = "asst_V7Y4yzlKCiQu13PgPNcW2az6"

# input_folder = "data/samples/T1611"
# output_folder = os.path.join(input_folder, "llm_judged_verdicts")
# os.makedirs(output_folder, exist_ok=True)

# # === TIME ===
# def now():
#     return datetime.utcnow().isoformat() + "Z"

# # === PROMPT BUILDER ===
# def build_prompt(data):
#     return (
#         f"Evaluate whether the following command aligns with MITRE ATT&CK Technique {data['technique_id']}.\n\n"
#         f"Command: {data['command']}\n\n"
#         f"Explanation: {data['explanation']}\n\n"
#         f"Give a confidence score from 0 (no match) to 1 (perfect match) and explain your reasoning."
#     )

# # === PARSE SCORE FROM TEXT ===
# def parse_llm_response(text):
#     try:
#         score_line = next(l for l in text.splitlines() if "score" in l.lower())
#         score = float([t for t in score_line.split() if t.replace(".", "").isdigit()][0])
#     except Exception:
#         score = None
#     return score

# # === VERDICT FROM SCORE ===
# def get_verdict(score):
#     if score is None:
#         return "unknown"
#     elif score >= 0.85:
#         return "likely_match"
#     elif score >= 0.65:
#         return "uncertain"
#     else:
#         return "likely_mismatch"

# # === MAIN LOOP ===
# for fname in os.listdir(input_folder):
#     if not fname.endswith(".json"):
#         continue

#     filepath = os.path.join(input_folder, fname)
#     with open(filepath, "r") as f:
#         data = json.load(f)

#     prompt = build_prompt(data)

#     # Create a new thread
#     thread = openai.beta.threads.create()
#     openai.beta.threads.messages.create(
#         thread_id=thread.id,
#         role="user",
#         content=prompt
#     )

#     run = openai.beta.threads.runs.create(
#         thread_id=thread.id,
#         assistant_id=assistant_id
#     )

#     # Wait for assistant to finish
#     while True:
#         run_status = openai.beta.threads.runs.retrieve(thread_id=thread.id, run_id=run.id)
#         if run_status.status == "completed":
#             break
#         elif run_status.status == "failed":
#             print(f"[!] Run failed for: {fname}")
#             break
#         time.sleep(1)

#     # Get the assistant's reply
#     messages = openai.beta.threads.messages.list(thread_id=thread.id)
#     reply_text = ""
#     for msg in messages.data:
#         if msg.role == "assistant":
#             reply_text = msg.content[0].text.value.strip()

#     score = parse_llm_response(reply_text)
#     verdict = get_verdict(score)

#     judgment = {
#         "model": "gpt-4-turbo",
#         "score": score,
#         "reason": reply_text,
#         "timestamp": now()
#     }

#     # Output new verdict file
#     output = {
#         "id": data.get("id", fname.replace(".json", "")),
#         "technique_id": data["technique_id"],
#         "llm_judgments": [judgment],
#         "llm_average_score": score,
#         "llm_verdict": verdict
#     }

#     with open(os.path.join(output_folder, fname), "w") as out:
#         json.dump(output, out, indent=2)

#     print(f"Processed {fname} → Verdict: {verdict}")













# # This file serves as an LLM jury to assess how accurate the samles are and how closely they fit into the desired MITRE Technique.

# import os
# import json
# import openai
# from datetime import datetime
# from anthropic import Anthropic, HUMAN_PROMPT, AI_PROMPT

# # add in keys here
# openai.api_key = os.getenv("OPENAI_API_KEY")
# anthropic = Anthropic(api_key=os.getenv("CLAUDE_API_KEY"))

# input_folder = "data/samples/T1611"
# output_folder = "data/samples/T1611/llm_judged_samples"
# os.makedirs(output_folder, exist_ok=True)

# # prompt
# def build_prompt(data):
#     return (
#         f"Evaluate whether the following command aligns with MITRE ATT&CK Technique {data['technique_id']}.\n\n"
#         f"Command: {data['command']}\n\n"
#         f"Explanation: {data['explanation']}\n\n"
#         f"Give a confidence score from 0 (no match) to 1 (perfect match) and explain your reasoning."
#     )

# # GPT-4 Turbo
# def ask_gpt(prompt):
#     try:
#         res = openai.ChatCompletion.create(
#             model="gpt-4-turbo",
#             messages=[
#                 {"role": "system", "content": "You are a cybersecurity expert helping validate ATT&CK alignment."},
#                 {"role": "user", "content": prompt}
#             ],
#             max_tokens=500,
#             temperature=0,
#         )
#         return parse_llm_response(res.choices[0].message.content, "gpt-4-turbo")
#     except Exception as e:
#         return {"model": "gpt-4-turbo", "score": None, "reason": str(e), "timestamp": now()}

# # Claude 3 Opus
# def ask_claude(prompt):
#     try:
#         res = anthropic.completions.create(
#             model="claude-3-opus-20240229",
#             max_tokens_to_sample=500,
#             prompt=f"{HUMAN_PROMPT} {prompt}{AI_PROMPT}",
#             stop_sequences=[HUMAN_PROMPT],
#             temperature=0
#         )
#         return parse_llm_response(res.completion, "claude-3-opus")
#     except Exception as e:
#         return {"model": "claude-3-opus", "score": None, "reason": str(e), "timestamp": now()}

# # Parse LLM response
# def parse_llm_response(text, model):
#     try:
#         score_line = next(l for l in text.splitlines() if "score" in l.lower())
#         score = float([t for t in score_line.split() if t.replace(".", "").isdigit()][0])
#     except Exception as e:
#         score = None
#     return {
#         "model": model,
#         "score": score,
#         "reason": text.strip(),
#         "timestamp": now()
#     }

# # UTC now
# def now():
#     return datetime.utcnow().isoformat() + "Z"

# # 🏁 Final verdict
# def get_verdict(avg):
#     if avg is None:
#         return "unknown"
#     if avg >= 0.85:
#         return "likely_match"
#     elif avg >= 0.65:
#         return "uncertain"
#     else:
#         return "likely_mismatch"

# # 📂 Main loop
# for fname in os.listdir(input_folder):
#     if not fname.endswith(".json"):
#         continue
#     with open(os.path.join(input_folder, fname)) as f:
#         data = json.load(f)

#     prompt = build_prompt(data)

#     gpt_judgment = ask_gpt(prompt)
#     claude_judgment = ask_claude(prompt)

#     scores = [j["score"] for j in [gpt_judgment, claude_judgment] if j["score"] is not None]
#     avg_score = round(sum(scores)/len(scores), 3) if scores else None

#     data.setdefault("validation", {})
#     data["validation"]["llm_judgments"] = [gpt_judgment, claude_judgment]
#     data["validation"]["llm_average_score"] = avg_score
#     data["validation"]["llm_verdict"] = get_verdict(avg_score)

#     with open(os.path.join(output_folder, fname), "w") as out:
#         json.dump(data, out, indent=2)

#     print(f"Processed: {fname} → verdict: {data['validation']['llm_verdict']}")




# {
#   "id": "SYN-POWERSHELL-T1611-6e0532b0-62145a26",
#   "technique_id": "T1611",
#   "platform": "windows",
#   "shell": "powershell",
#   "command": "Invoke-Item -Path C:\\HostSystem\\maintenance\\scheduledtask.ps1",
#   "explanation": "Executes a PowerShell script located in the host system from within the container.",
#   "rationale_steps": [
#     "Identify a useful script on the host system.",
#     "Execute the script directly using PowerShell's Invoke-Item, affecting the host's scheduled tasks."
#   ],
#   "source_prompt_hash": "6e0532b0",
#   "obfuscation_level": "none",
#   "validation": {
#     "syntax_ok": true,
#     "llm_judgments": [
#         {
#         "model": "gpt-4-turbo",
#         "score": 0.90,
#         "reason": "This command is strongly aligned with T1611 because it escapes a container using namespace manipulation...",
#         "timestamp": "2025-07-07T18:22:00Z"
#         }
#     ],
#     "llm_average_score": 0.9,
#     "llm_verdict": "likely_match"
#     },
#   "timestamp_utc": "2025-07-07T00:32:32.674952Z"
# }
