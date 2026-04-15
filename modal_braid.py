"""
modal_braid.py — Braid engine on Modal

Architecture:
  - Each model in the PER phase runs in its own Modal container (true parallel GPU inference)
  - Audit log persisted to a Modal Volume (survives restarts, queryable cross-session)
  - Session state (sealed plan, per-model verdicts) in Modal Dict (shared mid-run)
  - verify_claim and audit_log exposed as web endpoints (replaces TS plugin tools)
  - Compliance validation (tool-validator rules) runs in Python before any output re-enters context

Usage:
  modal run modal_braid.py --question "..." [--models m1,m2] [--refine]
  modal deploy modal_braid.py   # expose web endpoints permanently
"""

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import modal

# ── Modal primitives ───────────────────────────────────────────────────────

app = modal.App("braid-engine")

audit_volume = modal.Volume.from_name("braid-audit", create_if_missing=True)
AUDIT_MOUNT = "/audit"
AUDIT_FILE = f"{AUDIT_MOUNT}/verifier-audit.jsonl"

# Per-session shared state: sealed plan, per-model outputs, verdicts
session_dict = modal.Dict.from_name("braid-session", create_if_missing=True)

# ── Container image ────────────────────────────────────────────────────────

ollama_image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("curl", "zstd")
    .run_commands(
        "curl -fsSL https://ollama.ai/install.sh | sh",
    )
    .pip_install("httpx")
)

base_image = modal.Image.debian_slim(python_version="3.11").pip_install("httpx", "fastapi[standard]")

# ── Compliance validator (Python port of tool-validator.ts) ────────────────

@dataclass
class Finding:
    rule: str
    verdict: str  # "pass" | "flag" | "blocked"
    reason: str


VERDICT_RANK = {"pass": 0, "flag": 1, "blocked": 2}


def _worst(findings: list[Finding]) -> str:
    return max((f.verdict for f in findings), key=lambda v: VERDICT_RANK[v], default="pass")


def validate_output(tool: str, output: str, args: dict) -> dict:
    """Python port of validateToolOutput from tool-validator.ts"""
    findings: list[Finding] = []
    out = output or ""

    # error-not-diagnosed
    lower = out.lower()
    if any(k in lower for k in ("error:", "exception:", "traceback", "exitcode: 1", "exit code 1")):
        findings.append(Finding("error-not-diagnosed", "flag",
                                "Tool returned an error signal — diagnose root cause before retrying"))

    # empty-output
    if not out.strip():
        findings.append(Finding("empty-output", "flag",
                                "Tool returned empty output — confirm action executed"))

    # large-output-truncation
    if len(out) > 8000:
        findings.append(Finding("large-output-truncation", "flag",
                                f"Output is {len(out)} chars — likely truncated"))

    # bash-destructive
    if tool == "bash":
        cmd = args.get("command", "")
        for pattern, label in [
            (r"\brm\s+-rf\b", "rm -rf"),
            (r"\bdrop\s+table\b", "DROP TABLE"),
            (r"\btruncate\b", "TRUNCATE"),
            (r"\bmkfs\b", "mkfs"),
        ]:
            if re.search(pattern, cmd, re.IGNORECASE):
                findings.append(Finding("bash-destructive", "flag",
                                        f"Destructive bash pattern: {label}"))

    # pii-exposure (FCRA §607, GLBA §501, HIPAA §164.502)
    pii_patterns = [
        (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern"),
        (r"\b(?:\d{4}[- ]){3}\d{4}\b", "credit card pattern"),
        (r"\b\d{3}-\d{3}-\d{4}\b", "phone number (GLBA NPI)"),
        (r"\b[A-Z]{2}\d{6,9}\b", "passport/ID pattern"),
        (r"\baccount[\s_-]?(?:number|num|#|no)?[\s:]+\d{8,17}\b", "account number (NPI)"),
        (r"\b[A-TV-Z][0-9][0-9A-Z]\.[0-9A-Z]{1,4}\b", "ICD-10 code (PHI)"),
    ]
    for pattern, label in pii_patterns:
        if re.search(pattern, out, re.IGNORECASE):
            findings.append(Finding("pii-exposure", "blocked",
                                    f"Sensitive data: {label} (FCRA §607, GLBA §501, HIPAA §164.502)"))
            break

    # fcra-adverse-action (FCRA §615a)
    if re.search(r"\b(?:adverse action|denied|declined|rejected)\b", out, re.IGNORECASE):
        has_notice = bool(re.search(r"right to (?:a free copy|dispute|obtain)|consumer reporting agency|FCRA", out, re.IGNORECASE))
        if not has_notice:
            findings.append(Finding("fcra-adverse-action", "blocked",
                                    "Adverse action without FCRA §615(a) notices (CRA name, right-to-copy, right-to-dispute)"))

    # durable-write-gate (FCRA Retention + ISO 27001 A.8.3)
    durable_tools = {"write_file", "edit_file", "create_file", "database_write",
                     "db_insert", "db_update", "record_update"}
    is_durable = tool in durable_tools
    write_via_shell = False
    if tool == "bash":
        cmd = args.get("command", "")
        write_via_shell = bool(re.search(r"\btee\b|>>|>\s*\w|INSERT\s+INTO|UPDATE\s+\w|CREATE\s+TABLE", cmd, re.IGNORECASE))
        is_durable = write_via_shell

    if is_durable:
        justification = args.get("justification", "")
        reg_basis = args.get("regulatory_basis", "")
        if len(justification) >= 20 and len(reg_basis) >= 5:
            findings.append(Finding("durable-write-gate", "flag",
                                    f'Durable write allowed: "{justification[:80]}" [basis: {reg_basis}]'))
        else:
            findings.append(Finding("durable-write-gate", "blocked",
                                    "Durable write blocked: no regulatory justification. "
                                    "Supply args.justification (>=20 chars) + args.regulatory_basis."))

    # deprecated-crypto (ISO 27001 A.8.24)
    for pattern, name in [
        (r"\bMD5\b", "MD5"), (r"\bSHA-?1\b", "SHA-1"), (r"\b3?DES\b", "DES/3DES"),
        (r"\bRC4\b", "RC4"), (r"\bSSLv[23]\b", "SSLv2/3"), (r"\bTLS\s*1\.[01]\b", "TLS 1.0/1.1"),
    ]:
        if re.search(pattern, out):
            findings.append(Finding("deprecated-crypto", "blocked",
                                    f"Deprecated crypto: {name} (ISO 27001 A.8.24)"))
            break

    # hardcoded-credentials (ISO 27001 A.8.28)
    cred_patterns = [
        (r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?\S{4,}", "hardcoded password"),
        (r"(?:api_?key|apikey|secret_?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}", "hardcoded API key"),
        (r"AKIA[0-9A-Z]{16}", "AWS key ID"),
        (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "private key"),
    ]
    for pattern, label in cred_patterns:
        if re.search(pattern, out, re.IGNORECASE):
            findings.append(Finding("hardcoded-credentials", "blocked",
                                    f"{label} in output (ISO 27001 A.8.28 / OWASP A02)"))
            break

    # soc-change-event (SOC 2 CC8.1)
    if re.search(r"\b(?:modif(?:y|ied)|replac(?:e|ed)|delet(?:e|ed)|drop(?:ped)?|migrat(?:e|ed)|refactor(?:ed)?)\b", out, re.IGNORECASE):
        if not re.search(r"\b(?:blast radius|impact|affect|downstream|rollback|revert)\b", out, re.IGNORECASE):
            findings.append(Finding("soc-change-event", "flag",
                                    "Change event without impact analysis (SOC 2 CC8.1)"))

    # soc-incident-pattern (SOC 2 CC7.2)
    error_count = len(re.findall(r"\b(?:error|exception|failed|failure|traceback)\b", lower))
    if error_count >= 2:
        findings.append(Finding("soc-incident-pattern", "flag",
                                f"{error_count} error signals in output — potential incident (SOC 2 CC7.2)"))

    if not findings:
        return {"verdict": "pass", "findings": []}

    verdict = _worst(findings)
    blocked = [f for f in findings if f.verdict == "blocked"]
    flags = [f for f in findings if f.verdict == "flag"]

    parts = []
    if blocked:
        parts.append(f"[VERIFIER:BLOCKED] {len(blocked)} rule(s):\n" +
                     "\n".join(f"  • [{f.rule}] {f.reason}" for f in blocked))
    if flags:
        parts.append(f"[VERIFIER:FLAG] {len(flags)} finding(s):\n" +
                     "\n".join(f"  • [{f.rule}] {f.reason}" for f in flags))

    return {
        "verdict": verdict,
        "annotation": "\n\n".join(parts),
        "findings": [{"rule": f.rule, "verdict": f.verdict, "reason": f.reason} for f in findings],
    }


# ── Audit helpers ─────────────────────────────────────────────────────────

def _write_audit(entry: dict):
    """Append a JSONL entry to the audit volume. Only call from inside a Modal container."""
    import os
    os.makedirs(AUDIT_MOUNT, exist_ok=True)
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    audit_volume.commit()


@app.function(
    image=base_image,
    volumes={AUDIT_MOUNT: audit_volume},
)
def write_audit_entry(entry: dict):
    """Write a single audit entry to the persistent volume. Call via .remote() from local context."""
    _write_audit(entry)


# ── Model inference container ──────────────────────────────────────────────

@app.function(
    image=ollama_image,
    gpu="T4",
    timeout=300,
    volumes={AUDIT_MOUNT: audit_volume},
    secrets=[],
)
def run_model(model: str, prompt: str, session_id: str, phase: str = "per") -> dict:
    """
    Run a single model inference in its own GPU container.
    Validates output before returning. Writes audit entry.
    """
    import subprocess
    import httpx

    start = time.monotonic()

    # Start Ollama server in background
    proc = subprocess.Popen(
        ["ollama", "serve"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(3)  # wait for server

    # Pull model if not present
    try:
        subprocess.run(["ollama", "pull", model], timeout=120, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        return {"model": model, "error": f"pull failed: {e}", "text": "",
                "fault_verdict": "fault", "latency_ms": 0}

    # Inference via Ollama REST
    try:
        resp = httpx.post(
            "http://localhost:11434/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            },
            timeout=240,
        )
        resp.raise_for_status()
        data = resp.json()
        text = data.get("message", {}).get("content", "")
        latency_ms = int((time.monotonic() - start) * 1000)
    except Exception as e:
        return {"model": model, "error": str(e), "text": "",
                "fault_verdict": "fault", "latency_ms": int((time.monotonic() - start) * 1000)}
    finally:
        proc.terminate()

    # Compliance validation
    validation = validate_output("llm_output", text, {})

    entry = {
        "type": "tool_intercepted",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sessionID": session_id,
        "tool": f"model:{model}",
        "callID": str(uuid.uuid4()),
        "phase": phase,
        "verdict": validation["verdict"],
        "findings": validation.get("findings", []),
        "outputPreview": text[:200],
    }
    _write_audit(entry)

    return {
        "model": model,
        "text": text,
        "error": None,
        "fault_verdict": validation["verdict"],
        "latency_ms": latency_ms,
        "findings": validation.get("findings", []),
        "annotation": validation.get("annotation"),
    }


# ── Synthesizer (same container, larger context) ───────────────────────────

@app.function(
    image=ollama_image,
    gpu="T4",
    timeout=300,
    volumes={AUDIT_MOUNT: audit_volume},
)
def run_synthesizer(model: str, prompt: str, session_id: str, phase: str = "post") -> dict:
    """Synthesis and verification — same infra as run_model but labeled separately."""
    return run_model.local(model, prompt, session_id, phase)


# ── Web endpoints: verify_claim and audit_log ──────────────────────────────

@app.function(
    image=base_image,
    volumes={AUDIT_MOUNT: audit_volume},
)
@modal.fastapi_endpoint(method="POST")
def verify_claim(body: dict) -> dict:
    """
    POST {"session_id": "...", "claim": "...", "evidence": "..."}
    Returns {"verdict": "verified"|"unverified", "reason": "..."}
    Writes to audit volume.
    """
    claim = body.get("claim", "")
    evidence = body.get("evidence", "")
    session_id = body.get("session_id", "unknown")

    has_evidence = len(evidence.strip()) > 20
    verdict = "verified" if has_evidence else "unverified"
    reason = (
        f'Evidence accepted: "{evidence[:120]}"'
        if has_evidence
        else "No substantive evidence cited. Cannot confirm claim."
    )

    entry = {
        "type": "verify_called",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sessionID": session_id,
        "claim": claim,
        "verdict": verdict,
        "reason": reason,
    }
    _write_audit(entry)

    return {
        "verdict": verdict,
        "reason": reason,
        "claim": claim,
        "message": (
            f"VERIFIED: {claim}" if verdict == "verified"
            else f"UNVERIFIED: {claim}\n{reason}"
        ),
    }


@app.function(
    image=base_image,
    volumes={AUDIT_MOUNT: audit_volume},
)
@modal.fastapi_endpoint(method="GET")
def audit_log(last_n: int = 10) -> dict:
    """
    GET /audit_log?last_n=20
    Returns last N audit entries from the persistent volume.
    """
    audit_volume.reload()
    try:
        with open(AUDIT_FILE) as f:
            lines = [l.strip() for l in f if l.strip()]
        entries = [json.loads(l) for l in lines[-last_n:]]
        return {"count": len(entries), "entries": entries}
    except FileNotFoundError:
        return {"count": 0, "entries": []}


# ── Braid orchestrator (the main entrypoint) ───────────────────────────────

@app.local_entrypoint()
def main(
    question: str,
    models: str = "qwen2.5:latest,llama3.2:latest,mistral:latest",
    synthesizer: str = "granite3-dense:8b",
    refine: bool = False,
):
    model_list = [m.strip() for m in models.split(",")]
    session_id = str(uuid.uuid4())[:8]
    width = 72

    print(f"\n{'═'*width}")
    print(f"  BRAID SESSION {session_id}  |  {len(model_list)} models  |  Modal GPU")
    print(f"{'═'*width}")

    # ── PHASE 0: PRE ──────────────────────────────────────────────────────
    print(f"\n── PHASE 0: PRE (sealing plan via {synthesizer}) " + "─"*(width-48-len(synthesizer)))

    pre_prompt = (
        f"INSTRUCTION: Respond with plain text only. Do not call any tools.\n\n"
        f"You are about to coordinate a multi-model query. The user's question is: \"{question}\"\n\n"
        f"The following models will each independently answer it: {', '.join(model_list)}.\n\n"
        f"Before they run, state in 2-3 sentences: "
        f"(1) what a good answer looks like, "
        f"(2) what disagreements you expect between models, "
        f"(3) what verification criterion you will use — be explicit about what would cause FAIL. "
        f"This is your sealed plan (Γ) — you cannot revise it later."
    )

    pre_result = run_model.remote(synthesizer, pre_prompt, session_id, "pre")
    sealed_plan = pre_result.get("text", "(no plan)")
    print(f"\nΓ (sealed plan):\n{sealed_plan}\n")

    # Store sealed plan in shared Dict
    session_dict[f"{session_id}:sealed_plan"] = sealed_plan

    # ── PHASE 1: PER (parallel model inference) ────────────────────────────
    print(f"\n── PHASE 1: PER ({len(model_list)} models in parallel on Modal GPU) " + "─"*(width-52-len(model_list)*2))

    per_prompt = (
        f"SEALED PLAN (Γ): {sealed_plan}\n\n"
        f"Question: {question}\n\n"
        f"Answer concisely and accurately. The synthesizer will check your response against Γ."
    )

    # True parallel dispatch — each model gets its own container
    per_futures = [
        run_model.spawn(model, per_prompt, session_id, "per")
        for model in model_list
    ]
    responses = [f.get() for f in per_futures]

    for r in responses:
        model_name = r["model"]
        latency = r.get("latency_ms", 0)
        verdict = r.get("fault_verdict", "pass")
        text_preview = (r.get("text") or "")[:120]
        print(f"\n[{model_name}] ({latency}ms) verdict={verdict}")
        if r.get("findings"):
            for finding in r["findings"]:
                print(f"  ⚠ [{finding['rule']}] {finding['verdict']}: {finding['reason'][:80]}")
        print(f"  {text_preview}{'...' if len(r.get('text',''))>120 else ''}")
        session_dict[f"{session_id}:per:{model_name}"] = r.get("text", "")

    # ── PHASE 2: POST (synthesis + verification) ──────────────────────────
    print(f"\n── PHASE 2: POST (synthesis via {synthesizer}) " + "─"*(width-43-len(synthesizer)))

    valid_responses = [r for r in responses if r.get("text") and not r.get("error")]
    if not valid_responses:
        print("All models failed — cannot synthesize.", flush=True)
        return

    response_block = "\n\n".join(
        f"[{r['model']}]: {(r['text'] or '')[:400]}"
        for r in valid_responses
    )

    post_prompt = (
        f"SEALED PLAN (Γ): {sealed_plan}\n\n"
        f"QUESTION: {question}\n\n"
        f"MODEL RESPONSES:\n{response_block}\n\n"
        f"Your task:\n"
        f"## Synthesized Answer\n[Combine the best elements of the responses]\n\n"
        f"## Contradictions\n[Note any genuine disagreements between models]\n\n"
        f"## Verification\n[PASS or FAIL with reason, judged against Γ]"
    )

    post_result = run_synthesizer.remote(synthesizer, post_prompt, session_id, "post")
    synthesis = post_result.get("text", "")

    print(f"\n{'═'*width}")
    print(synthesis)
    print(f"{'═'*width}\n")

    # Extract verification verdict
    verdict_match = re.search(r"## Verification\s*\n(.+?)(?:\n##|$)", synthesis, re.DOTALL)
    verdict_body = verdict_match.group(1).strip()[:400] if verdict_match else ""
    is_fail = "fail" in verdict_body.lower()

    # Write final session entry to audit (via Modal container — Volume is read-only locally)
    final_entry = {
        "type": "session_complete",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sessionID": session_id,
        "question": question[:100],
        "models": model_list,
        "verdict": "FAIL" if is_fail else "PASS",
        "verdict_body": verdict_body[:200],
    }
    write_audit_entry.remote(final_entry)

    # ── Phase 0 refinement on FAIL ─────────────────────────────────────────
    if refine and is_fail:
        print(f"\n── PHASE 0 REFINEMENT (FAIL detected, re-sealing Γ) " + "─"*(width-51))
        refine_prompt = (
            f"INSTRUCTION: Respond with plain text only.\n\n"
            f"A previous braid run on this question produced Verification: FAIL.\n"
            f"Failure reason: {verdict_body}\n\n"
            f"Re-seal a stricter plan (Γ) that explicitly forbids the observed failure modes.\n"
            f"Question: {question}"
        )
        refine_result = run_model.remote(synthesizer, refine_prompt, session_id, "refine")
        print(f"\nRefined Γ:\n{refine_result.get('text','(failed)')}\n")

    print(f"Audit log: modal volume ls braid-audit")
    print(f"Session ID: {session_id}")
