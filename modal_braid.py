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
  modal deploy modal_braid.py   # expose web endpoints + UI permanently

Endpoints (after deploy):
  GET  /              → streaming UI
  POST /braid/stream  → SSE stream (phases emitted as they complete)
  POST /verify_claim  → claim verification
  GET  /audit_log     → audit history

Roles (product-of-experts, engineered independence):
  advocate  — argue for the most correct answer, cite reasoning
  adversary — find every flaw, edge case, and wrong assumption
  auditor   — check compliance, legality, and constraint satisfaction
  synthesis — reconcile all roles against the sealed plan (POST only)
"""

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import modal

# ── Role definitions (product-of-experts axis separation) ─────────────────
# Each role gets a decorrelated prompt frame. Same model, orthogonal tasks.
# This enforces ρ ≈ 0 between nodes structurally, not by assumption.

ROLES: dict[str, dict] = {
    "advocate": {
        "label": "Advocate",
        "symbol": "⊕",
        "description": "Argue for the most correct, well-supported answer",
        "frame": (
            "You are the ADVOCATE. Your role is to construct the strongest, "
            "most well-reasoned answer to the question. Cite your reasoning. "
            "Do not hedge unnecessarily — commit to a position and defend it."
        ),
    },
    "adversary": {
        "label": "Adversary",
        "symbol": "⊖",
        "description": "Find every flaw, edge case, and wrong assumption",
        "frame": (
            "You are the ADVERSARY. Your role is to find every flaw, "
            "counterexample, hidden assumption, and failure mode in any proposed answer. "
            "Do not propose a solution — only attack. Be specific and technical."
        ),
    },
    "auditor": {
        "label": "Auditor",
        "symbol": "⊗",
        "description": "Check compliance, legal constraints, and regulatory correctness",
        "frame": (
            "You are the AUDITOR. Your role is to check the answer for compliance violations, "
            "regulatory issues (FCRA, GLBA, HIPAA, ISO 27001, SOC 2), PII exposure, "
            "deprecated practices, and hardcoded secrets. "
            "Flag every violation. Ignore elegance — correctness is the only metric."
        ),
    },
}

DEFAULT_ROLE_SEQUENCE = ["advocate", "adversary", "auditor"]


def _assign_roles(model_list: list[str]) -> list[dict]:
    """Assign roles to models. If more models than roles, cycle roles."""
    assignments = []
    for i, model in enumerate(model_list):
        role_key = DEFAULT_ROLE_SEQUENCE[i % len(DEFAULT_ROLE_SEQUENCE)]
        role = ROLES[role_key]
        assignments.append({
            "model": model,
            "role": role_key,
            "label": role["label"],
            "symbol": role["symbol"],
            "frame": role["frame"],
        })
    return assignments


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


# ── SSE helper ───────────────────────────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ── Static UI ─────────────────────────────────────────────────────────────

UI_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Braid Engine</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d0d0d; color: #e0e0e0; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 13px; min-height: 100vh; }
  header { padding: 18px 24px; border-bottom: 1px solid #222; display: flex; align-items: center; gap: 16px; }
  header h1 { font-size: 15px; letter-spacing: 0.08em; color: #fff; font-weight: 600; }
  header span { color: #555; font-size: 11px; }
  .container { max-width: 1100px; margin: 0 auto; padding: 24px; }
  .input-row { display: flex; gap: 10px; margin-bottom: 28px; }
  input[type=text] { flex: 1; background: #161616; border: 1px solid #2a2a2a; border-radius: 6px; color: #e0e0e0; padding: 10px 14px; font-family: inherit; font-size: 13px; outline: none; transition: border 0.15s; }
  input[type=text]:focus { border-color: #444; }
  button { background: #1a1a1a; border: 1px solid #333; border-radius: 6px; color: #ccc; padding: 10px 20px; font-family: inherit; font-size: 13px; cursor: pointer; transition: all 0.15s; white-space: nowrap; }
  button:hover { background: #222; border-color: #555; color: #fff; }
  button:disabled { opacity: 0.4; cursor: not-allowed; }
  .phase { margin-bottom: 20px; }
  .phase-header { font-size: 11px; letter-spacing: 0.12em; color: #555; text-transform: uppercase; margin-bottom: 10px; padding-bottom: 6px; border-bottom: 1px solid #1a1a1a; }
  .sealed-plan { background: #111; border: 1px solid #1e1e1e; border-left: 3px solid #3a3a3a; border-radius: 4px; padding: 14px 16px; white-space: pre-wrap; line-height: 1.6; color: #aaa; }
  .roles { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; }
  .role-card { background: #111; border: 1px solid #1e1e1e; border-radius: 6px; overflow: hidden; }
  .role-card.advocate { border-top: 2px solid #2d6a4f; }
  .role-card.adversary { border-top: 2px solid #6a2d2d; }
  .role-card.auditor   { border-top: 2px solid #2d4a6a; }
  .role-label { padding: 8px 14px; font-size: 11px; letter-spacing: 0.1em; display: flex; justify-content: space-between; align-items: center; }
  .role-label .symbol { font-size: 15px; }
  .role-label .meta { color: #444; font-size: 10px; }
  .role-body { padding: 12px 14px; color: #bbb; white-space: pre-wrap; line-height: 1.6; min-height: 60px; }
  .verdict-pass { color: #4ade80; font-size: 10px; font-weight: 700; letter-spacing: 0.1em; }
  .verdict-flag { color: #facc15; font-size: 10px; font-weight: 700; }
  .verdict-blocked { color: #f87171; font-size: 10px; font-weight: 700; }
  .findings { margin-top: 8px; padding-top: 8px; border-top: 1px solid #1a1a1a; }
  .finding { color: #facc15; font-size: 11px; margin-bottom: 3px; }
  .synthesis { background: #0f1a0f; border: 1px solid #1e2e1e; border-radius: 6px; padding: 18px; white-space: pre-wrap; line-height: 1.7; color: #ccc; }
  .synthesis h2 { color: #4ade80; font-size: 12px; letter-spacing: 0.08em; margin-bottom: 8px; margin-top: 16px; }
  .synthesis h2:first-child { margin-top: 0; }
  .verdict-banner { text-align: center; padding: 14px; border-radius: 6px; font-size: 14px; font-weight: 700; letter-spacing: 0.15em; margin-top: 18px; }
  .verdict-banner.pass { background: #0f2a1a; color: #4ade80; border: 1px solid #1a4a2a; }
  .verdict-banner.fail { background: #2a0f0f; color: #f87171; border: 1px solid #4a1a1a; }
  .status { font-size: 11px; color: #555; margin-bottom: 16px; min-height: 18px; }
  .spinner { display: inline-block; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .audit-link { font-size: 11px; color: #444; margin-top: 12px; }
  .audit-link a { color: #666; text-decoration: none; }
  .audit-link a:hover { color: #aaa; }
  .placeholder { color: #333; font-style: italic; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>&#9135; Braid Engine</h1>
  <span>Advocate &oplus; &nbsp; Adversary &ominus; &nbsp; Auditor &otimes;</span>
</header>
<div class="container">
  <div class="input-row">
    <input type="text" id="question" placeholder="Ask a question..." />
    <button id="run-btn" onclick="runBraid()">Run Braid</button>
  </div>
  <div class="status" id="status"></div>

  <div class="phase" id="phase-pre" style="display:none">
    <div class="phase-header">&Gamma; Sealed Plan</div>
    <div class="sealed-plan" id="sealed-plan-text"></div>
  </div>

  <div class="phase" id="phase-per" style="display:none">
    <div class="phase-header">Phase 1 &mdash; Roles (parallel)</div>
    <div class="roles" id="roles-grid"></div>
  </div>

  <div class="phase" id="phase-post" style="display:none">
    <div class="phase-header">Phase 2 &mdash; Synthesis</div>
    <div class="synthesis" id="synthesis-text"></div>
    <div id="verdict-banner"></div>
  </div>

  <div class="audit-link" id="audit-link"></div>
</div>
<script>
const ROLE_CLASSES = { advocate: 'advocate', adversary: 'adversary', auditor: 'auditor' };
const ROLE_LABELS  = { advocate: '\u2295 Advocate', adversary: '\u2296 Adversary', auditor: '\u2297 Auditor' };

function setStatus(msg, spin=false) {
  document.getElementById('status').innerHTML =
    (spin ? '<span class="spinner">&#8635;</span> ' : '') + msg;
}

function show(id) { document.getElementById(id).style.display = ''; }

function renderMarkdown(text) {
  return text
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
}

function addRoleCard(data) {
  const grid = document.getElementById('roles-grid');
  const role = data.role || 'advocate';
  const verdict = data.verdict || 'pass';
  const latency = data.latency_ms ? (data.latency_ms/1000).toFixed(1)+'s' : '';
  const findings = (data.findings || []).map(f =>
    `<div class="finding">&bull; [${f.rule}] ${f.reason}</div>`
  ).join('');
  const card = document.createElement('div');
  card.className = `role-card ${ROLE_CLASSES[role] || ''}`;
  card.id = `role-${role}`;
  card.innerHTML = `
    <div class="role-label">
      <span>${ROLE_LABELS[role] || role} <span style="color:#444">[${data.model || ''}]</span></span>
      <span class="meta">${latency} &nbsp; <span class="verdict-${verdict}">${verdict.toUpperCase()}</span></span>
    </div>
    <div class="role-body">${(data.text || '').slice(0,600)}${(data.text||'').length>600?'...':''}
      ${findings ? '<div class="findings">'+findings+'</div>' : ''}
    </div>`;
  grid.appendChild(card);
}

async function runBraid() {
  const question = document.getElementById('question').value.trim();
  if (!question) return;
  document.getElementById('run-btn').disabled = true;
  document.getElementById('roles-grid').innerHTML = '';
  document.getElementById('synthesis-text').innerHTML = '<span class="placeholder">Waiting...</span>';
  document.getElementById('verdict-banner').innerHTML = '';
  document.getElementById('audit-link').innerHTML = '';
  ['phase-pre','phase-per','phase-post'].forEach(id => document.getElementById(id).style.display='none');

  let _startTs = Date.now();
  let _timerInterval = setInterval(() => {
    const el = document.getElementById('status');
    if (el && el.dataset.spinning === '1') {
      const s = Math.floor((Date.now() - _startTs) / 1000);
      el.innerHTML = '<span class="spinner">&#8635;</span> ' + el.dataset.msg + ' (' + s + 's)';
    }
  }, 1000);

  function setStatusTimed(msg) {
    const el = document.getElementById('status');
    el.dataset.spinning = '1';
    el.dataset.msg = msg;
    el.innerHTML = '<span class="spinner">&#8635;</span> ' + msg + ' (0s)';
  }

  function clearTimer() {
    clearInterval(_timerInterval);
    document.getElementById('status').dataset.spinning = '0';
  }

  setStatusTimed('Sealing plan...');

  const es = new EventSource('/braid/stream?question=' + encodeURIComponent(question));

  es.addEventListener('pre_done', e => {
    const d = JSON.parse(e.data);
    document.getElementById('sealed-plan-text').textContent = d.sealed_plan || '';
    show('phase-pre');
    _startTs = Date.now();
    setStatusTimed('Running ' + (d.n_roles||3) + ' roles in parallel...');
  });

  es.addEventListener('per_model_done', e => {
    const d = JSON.parse(e.data);
    show('phase-per');
    addRoleCard(d);
  });

  es.addEventListener('post_done', e => {
    const d = JSON.parse(e.data);
    const text = d.synthesis || '';
    document.getElementById('synthesis-text').innerHTML = renderMarkdown(text);
    const isPass = text.toLowerCase().includes('pass') && !text.toLowerCase().includes('fail');
    const banner = document.getElementById('verdict-banner');
    banner.className = 'verdict-banner ' + (isPass ? 'pass' : 'fail');
    banner.textContent = isPass ? 'VERIFICATION: PASS' : 'VERIFICATION: FAIL';
    show('phase-post');
    clearTimer();
    setStatus('Synthesis complete.');
  });

  es.addEventListener('session_complete', e => {
    const d = JSON.parse(e.data);
    document.getElementById('audit-link').innerHTML =
      `Session <code>${d.session_id}</code> &mdash; <a href="/audit_log?last_n=5">View audit log</a>`;
    clearTimer();
    document.getElementById('run-btn').disabled = false;
    es.close();
    setStatus('');
  });

  es.onerror = () => {
    clearTimer();
    setStatus('Stream error or complete.');
    document.getElementById('run-btn').disabled = false;
    es.close();
  };
}

document.getElementById('question').addEventListener('keydown', e => {
  if (e.key === 'Enter') runBraid();
});
</script>
</body>
</html>
"""


# ── Single ASGI app — all routes share one URL base ──────────────────────────
# GET  /               → UI
# GET  /braid/stream   → SSE stream
# POST /verify_claim   → claim verification
# GET  /audit_log      → audit history

@app.function(
    image=base_image,
    volumes={AUDIT_MOUNT: audit_volume},
    timeout=600,
)
@modal.asgi_app()
def web():
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

    api = FastAPI()

    @api.get("/")
    def serve_ui():
        return HTMLResponse(UI_HTML)

    @api.get("/braid/stream")
    def stream(
        question: str,
        models: str = "qwen2.5:latest,llama3.2:latest,mistral:latest",
        synthesizer: str = "qwen2.5:latest",
    ):
        model_list = [m.strip() for m in models.split(",")]
        assignments = _assign_roles(model_list)
        session_id = str(uuid.uuid4())[:8]

        def generate():
            # Heartbeat thread — keeps SSE alive during GPU cold start
            import threading
            _stop = threading.Event()
            _queue: list[str] = []

            def _heartbeat():
                while not _stop.is_set():
                    _stop.wait(15)
                    if not _stop.is_set():
                        _queue.append(": ping\n\n")

            hb = threading.Thread(target=_heartbeat, daemon=True)
            hb.start()

            def _flush_heartbeats():
                while _queue:
                    yield _queue.pop(0)

            # PRE
            role_descriptions = "\n".join(
                f"  {a['symbol']} {a['label']} ({a['model']}): {ROLES[a['role']]['description']}"
                for a in assignments
            )
            pre_prompt = (
                f"INSTRUCTION: Respond with plain text only. Do not call any tools.\n\n"
                f"You are about to coordinate a structured multi-role query. "
                f"The user's question is: \"{question}\"\n\n"
                f"Roles:\n{role_descriptions}\n\n"
                f"State in 2-3 sentences: (1) what a correct answer looks like, "
                f"(2) what tensions you expect between roles, "
                f"(3) what would cause FAIL. This is your sealed plan (Γ)."
            )
            pre_result = run_model.remote(synthesizer, pre_prompt, session_id, "pre")
            sealed_plan = pre_result.get("text", "(no plan)")
            session_dict[f"{session_id}:sealed_plan"] = sealed_plan
            _stop.set()  # stop heartbeat once PRE returns
            yield from _flush_heartbeats()
            yield _sse("pre_done", {
                "sealed_plan": sealed_plan,
                "session_id": session_id,
                "n_roles": len(assignments),
                "latency_ms": pre_result.get("latency_ms", 0),
            })

            # PER — spawn all, collect in order
            per_futures = [
                run_model.spawn(
                    a["model"],
                    f"{a['frame']}\n\nSEALED PLAN (Γ): {sealed_plan}\n\nQuestion: {question}\n\nRespond as the {a['label']}.",
                    session_id,
                    f"per:{a['role']}",
                )
                for a in assignments
            ]
            per_results = {}
            for future, a in zip(per_futures, assignments):
                r = future.get()
                per_results[a["role"]] = r.get("text", "")
                session_dict[f"{session_id}:per:{a['role']}"] = per_results[a["role"]]
                yield _sse("per_model_done", {
                    "role": a["role"],
                    "role_label": a["label"],
                    "symbol": a["symbol"],
                    "model": a["model"],
                    "text": (r.get("text") or "")[:800],
                    "verdict": r.get("fault_verdict", "pass"),
                    "findings": r.get("findings", []),
                    "latency_ms": r.get("latency_ms", 0),
                })

            # POST
            response_block = "\n\n".join(
                f"[{a['symbol']}{a['label']} / {a['model']}]:\n{per_results.get(a['role'], '')[:400]}"
                for a in assignments
            )
            post_prompt = (
                f"SEALED PLAN (Γ): {sealed_plan}\n\nQUESTION: {question}\n\n"
                f"ROLE RESPONSES:\n{response_block}\n\n"
                f"## Synthesized Answer\n[Reconcile Advocate, Adversary, Auditor]\n\n"
                f"## Role Tensions\n[Sharpest disagreements]\n\n"
                f"## Audit Flags\n[Compliance violations found]\n\n"
                f"## Verification\n[PASS or FAIL against Γ]"
            )
            post_result = run_synthesizer.remote(synthesizer, post_prompt, session_id, "post")
            synthesis = post_result.get("text", "")
            verdict_match = re.search(r"## Verification\s*\n(.+?)(?:\n##|$)", synthesis, re.DOTALL)
            verdict_body = verdict_match.group(1).strip()[:400] if verdict_match else ""
            is_fail = "fail" in verdict_body.lower()
            yield _sse("post_done", {
                "synthesis": synthesis,
                "verdict": "FAIL" if is_fail else "PASS",
                "latency_ms": post_result.get("latency_ms", 0),
            })

            write_audit_entry.remote({
                "type": "session_complete",
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "sessionID": session_id,
                "question": question[:100],
                "roles": [{"model": a["model"], "role": a["role"]} for a in assignments],
                "verdict": "FAIL" if is_fail else "PASS",
                "source": "stream",
            })
            yield _sse("session_complete", {
                "session_id": session_id,
                "verdict": "FAIL" if is_fail else "PASS",
            })

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @api.post("/verify_claim")
    def verify_claim(body: dict):
        claim = body.get("claim", "")
        evidence = body.get("evidence", "")
        session_id = body.get("session_id", "unknown")
        has_evidence = len(evidence.strip()) > 20
        verdict = "verified" if has_evidence else "unverified"
        reason = (
            f'Evidence accepted: "{evidence[:120]}"'
            if has_evidence
            else "No substantive evidence cited."
        )
        _write_audit({
            "type": "verify_called",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sessionID": session_id, "claim": claim,
            "verdict": verdict, "reason": reason,
        })
        return {"verdict": verdict, "reason": reason, "claim": claim}

    @api.get("/audit_log")
    def audit_log_route(last_n: int = 10):
        audit_volume.reload()
        try:
            with open(AUDIT_FILE) as f:
                lines = [l.strip() for l in f if l.strip()]
            entries = [json.loads(l) for l in lines[-last_n:]]
            return {"count": len(entries), "entries": entries}
        except FileNotFoundError:
            return {"count": 0, "entries": []}

    return api


# ── Braid orchestrator (the main entrypoint) ───────────────────────────────

@app.local_entrypoint()
def main(
    question: str,
    models: str = "qwen2.5:latest,llama3.2:latest,mistral:latest",
    synthesizer: str = "granite3-dense:8b",
    refine: bool = False,
):
    model_list = [m.strip() for m in models.split(",")]
    assignments = _assign_roles(model_list)
    session_id = str(uuid.uuid4())[:8]
    width = 72

    role_summary = "  ".join(f"{a['symbol']}{a['label']}[{a['model']}]" for a in assignments)

    print(f"\n{'═'*width}")
    print(f"  BRAID SESSION {session_id}  |  Modal GPU")
    print(f"  {role_summary}")
    print(f"{'═'*width}")

    # ── PHASE 0: PRE ──────────────────────────────────────────────────────
    print(f"\n── PHASE 0: PRE (sealing plan via {synthesizer}) " + "─"*(width-48-len(synthesizer)))

    role_descriptions = "\n".join(
        f"  {a['symbol']} {a['label']} ({a['model']}): {ROLES[a['role']]['description']}"
        for a in assignments
    )

    pre_prompt = (
        f"INSTRUCTION: Respond with plain text only. Do not call any tools.\n\n"
        f"You are about to coordinate a structured multi-role query. "
        f"The user's question is: \"{question}\"\n\n"
        f"The following roles will each independently address it:\n{role_descriptions}\n\n"
        f"Before they run, state in 2-3 sentences: "
        f"(1) what a correct answer looks like, "
        f"(2) what tensions you expect between roles (Advocate vs Adversary vs Auditor), "
        f"(3) what verification criterion you will use — be explicit about what would cause FAIL. "
        f"This is your sealed plan (Γ) — you cannot revise it later."
    )

    pre_result = run_model.remote(synthesizer, pre_prompt, session_id, "pre")
    sealed_plan = pre_result.get("text", "(no plan)")
    print(f"\nΓ (sealed plan):\n{sealed_plan}\n")

    # Store sealed plan and role assignments in shared Dict
    session_dict[f"{session_id}:sealed_plan"] = sealed_plan
    session_dict[f"{session_id}:roles"] = json.dumps([
        {"model": a["model"], "role": a["role"], "label": a["label"]} for a in assignments
    ])

    # ── PHASE 1: PER (parallel role inference) ────────────────────────────
    print(f"\n── PHASE 1: PER ({len(assignments)} roles in parallel on Modal GPU) " + "─"*(width-52-len(assignments)*2))

    # Each role gets its own decorrelated axis prompt — product-of-experts
    per_futures = [
        run_model.spawn(
            a["model"],
            (
                f"{a['frame']}\n\n"
                f"SEALED PLAN (Γ): {sealed_plan}\n\n"
                f"Question: {question}\n\n"
                f"Respond in character as the {a['label']}. Be specific."
            ),
            session_id,
            f"per:{a['role']}",
        )
        for a in assignments
    ]
    responses = [f.get() for f in per_futures]

    # Tag each response with its role
    for r, a in zip(responses, assignments):
        r["role"] = a["role"]
        r["role_label"] = a["label"]
        r["symbol"] = a["symbol"]

    for r in responses:
        latency = r.get("latency_ms", 0)
        verdict = r.get("fault_verdict", "pass")
        text_preview = (r.get("text") or "")[:120]
        tag = f"{r['symbol']}{r['role_label']}[{r['model']}]"
        print(f"\n{tag} ({latency}ms) verdict={verdict}")
        if r.get("findings"):
            for finding in r["findings"]:
                print(f"  ⚠ [{finding['rule']}] {finding['verdict']}: {finding['reason'][:80]}")
        print(f"  {text_preview}{'...' if len(r.get('text',''))>120 else ''}")
        session_dict[f"{session_id}:per:{r['role']}"] = r.get("text", "")

    # ── PHASE 2: POST (synthesis + verification) ──────────────────────────
    print(f"\n── PHASE 2: POST (synthesis via {synthesizer}) " + "─"*(width-43-len(synthesizer)))

    valid_responses = [r for r in responses if r.get("text") and not r.get("error")]
    if not valid_responses:
        print("All models failed — cannot synthesize.", flush=True)
        return

    response_block = "\n\n".join(
        f"[{r['symbol']}{r['role_label']} / {r['model']}]:\n{(r['text'] or '')[:400]}"
        for r in valid_responses
    )

    post_prompt = (
        f"SEALED PLAN (Γ): {sealed_plan}\n\n"
        f"QUESTION: {question}\n\n"
        f"ROLE RESPONSES (each model operated under a different axis):\n{response_block}\n\n"
        f"Your task as Synthesis:\n"
        f"## Synthesized Answer\n"
        f"[Reconcile the Advocate's best argument, the Adversary's strongest objection, "
        f"and the Auditor's compliance findings into a single correct answer]\n\n"
        f"## Role Tensions\n[What did the Advocate and Adversary most sharply disagree on?]\n\n"
        f"## Audit Flags\n[List any compliance or constraint violations the Auditor found]\n\n"
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
        "roles": [{"model": a["model"], "role": a["role"]} for a in assignments],
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
