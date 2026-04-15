"""
correlation.py — Measure pairwise violation-detection correlation between models.

For each pair of models (A, B), computes:

  ρ_violation(A,B) = Pearson correlation of their miss vectors on a
                     compliance benchmark of known FCRA/GLBA/HIPAA violations.

  miss[model][i] = 1 if model failed to flag violation i, else 0

  ρ ≈ 0   → models miss different violations (good — product-of-experts holds)
  ρ ≈ 1   → models miss the same violations (bad — adding model buys nothing)

Also computes:
  κ(A,B)  = Cohen's kappa (agreement above chance)
  P(miss) = p^n estimate vs. actual joint miss rate (independence test)

Usage:
  modal run correlation.py --models "qwen2.5:latest,llama3.2:latest,mistral:latest"
  modal run correlation.py --models "..." --save-results
"""

import json
import math
import time
import itertools
from dataclasses import dataclass, field

import modal

# ── Reuse Modal primitives from modal_braid ────────────────────────────────

app = modal.App("braid-correlation")

audit_volume = modal.Volume.from_name("braid-audit", create_if_missing=True)
AUDIT_MOUNT = "/audit"

ollama_image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("curl", "zstd")
    .run_commands("curl -fsSL https://ollama.ai/install.sh | sh")
    .pip_install("httpx")
)

base_image = modal.Image.debian_slim(python_version="3.11").pip_install(
    "httpx", "fastapi[standard]"
)

# ── Compliance benchmark ───────────────────────────────────────────────────
# Each item: a prompt containing a violation, and the rule(s) it should trigger.
# Ground truth: model SHOULD flag it. miss = 1 if it doesn't.

BENCHMARK: list[dict] = [
    # FCRA §615(a) — adverse action without CRA disclosure
    {
        "id": "fcra-001",
        "regulation": "FCRA §615(a)",
        "prompt": (
            "Review this adverse action notice and flag any compliance violations:\n\n"
            "Dear Applicant, We regret to inform you that your loan application has been denied "
            "based on information in your credit report. This decision is final."
        ),
        "expected_flags": ["fcra-adverse-action", "missing CRA name", "missing right to copy", "missing right to dispute"],
        "violation_present": True,
    },
    # FCRA §611 — denial with no dispute rights mentioned
    {
        "id": "fcra-002",
        "regulation": "FCRA §611",
        "prompt": (
            "Review this credit decision letter:\n\n"
            "Your application for credit has been declined due to derogatory credit history. "
            "Contact us if you have questions."
        ),
        "expected_flags": ["no dispute rights", "no free copy notice"],
        "violation_present": True,
    },
    # GLBA §501 — NPI in plaintext transmission
    {
        "id": "glba-001",
        "regulation": "GLBA §501",
        "prompt": (
            "Flag any compliance issues in this API response:\n\n"
            "{'customer': 'John Smith', 'phone': '555-867-5309', "
            "'account_number': '4412839201', 'balance': 14200.00}"
        ),
        "expected_flags": ["pii-exposure", "NPI in plaintext", "phone number", "account number"],
        "violation_present": True,
    },
    # HIPAA §164.502 — PHI disclosure without authorization
    {
        "id": "hipaa-001",
        "regulation": "HIPAA §164.502",
        "prompt": (
            "Review this patient record export for compliance issues:\n\n"
            "Patient: Jane Doe, DOB: 1981-03-14, Diagnosis: F32.1, "
            "SSN: 523-45-6789, Treating physician: Dr. Reyes"
        ),
        "expected_flags": ["pii-exposure", "PHI exposure", "SSN", "ICD-10 diagnosis code"],
        "violation_present": True,
    },
    # ISO 27001 A.8.24 — deprecated cryptography
    {
        "id": "iso-001",
        "regulation": "ISO 27001 A.8.24",
        "prompt": (
            "Review this code snippet for security issues:\n\n"
            "import hashlib\npassword_hash = hashlib.md5(password.encode()).hexdigest()\n"
            "token = hashlib.sha1(secret.encode()).hexdigest()"
        ),
        "expected_flags": ["deprecated-crypto", "MD5", "SHA-1"],
        "violation_present": True,
    },
    # ISO 27001 A.8.28 — hardcoded credentials
    {
        "id": "iso-002",
        "regulation": "ISO 27001 A.8.28",
        "prompt": (
            "Review this configuration file:\n\n"
            "DB_HOST=prod-db.internal\nDB_USER=admin\nDB_PASSWORD=Secr3t!Pass123\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI"
        ),
        "expected_flags": ["hardcoded-credentials", "hardcoded password", "AWS key"],
        "violation_present": True,
    },
    # SOC 2 CC8.1 — change without impact analysis
    {
        "id": "soc-001",
        "regulation": "SOC 2 CC8.1",
        "prompt": (
            "Review this deployment note:\n\n"
            "Deployed hotfix: deleted the legacy auth table and replaced the session "
            "management module. Change went live at 14:32 UTC."
        ),
        "expected_flags": ["soc-change-event", "no impact analysis", "no rollback plan"],
        "violation_present": True,
    },
    # GLBA — clean notice (no violation — tests false positive rate)
    {
        "id": "glba-clean-001",
        "regulation": "GLBA §503",
        "prompt": (
            "Review this privacy notice:\n\n"
            "We collect your name and email to process your account. We do not share your "
            "information with third parties. You may opt out at any time by contacting us."
        ),
        "expected_flags": [],
        "violation_present": False,
    },
    # FCRA — clean adverse action (no violation)
    {
        "id": "fcra-clean-001",
        "regulation": "FCRA §615(a)",
        "prompt": (
            "Review this adverse action notice:\n\n"
            "Dear Applicant, Your application has been denied based on your credit report from "
            "Equifax (PO Box 740256, Atlanta, GA 30374, 1-800-685-1111). You have the right to "
            "obtain a free copy of your report within 60 days and to dispute inaccurate information."
        ),
        "expected_flags": [],
        "violation_present": False,
    },
    # ISO — clean crypto (no violation)
    {
        "id": "iso-clean-001",
        "regulation": "ISO 27001 A.8.24",
        "prompt": (
            "Review this code:\n\n"
            "import hashlib\ntoken = hashlib.sha256(secret.encode()).hexdigest()\n"
            "key = secrets.token_bytes(32)"
        ),
        "expected_flags": [],
        "violation_present": False,
    },
]

SYSTEM_PROMPT = (
    "You are a compliance auditor. For the following content, identify any regulatory violations. "
    "For each violation found, state the rule name on its own line prefixed with 'VIOLATION:'. "
    "If no violations are present, respond with 'NO VIOLATIONS FOUND'. "
    "Be specific and cite the regulation. Do not add commentary."
)


# ── Model runner (reuses ollama_image) ────────────────────────────────────

@app.function(
    image=ollama_image,
    gpu="T4",
    timeout=300,
)
def probe_model(model: str, prompt: str) -> dict:
    """Run a single compliance probe on a model. Returns raw text response."""
    import subprocess
    import httpx

    start = time.monotonic()
    proc = subprocess.Popen(
        ["ollama", "serve"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(3)

    try:
        subprocess.run(
            ["ollama", "pull", model],
            timeout=120, check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        resp = httpx.post(
            "http://localhost:11434/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
            },
            timeout=180,
        )
        resp.raise_for_status()
        text = resp.json().get("message", {}).get("content", "")
    except Exception as e:
        text = f"ERROR: {e}"
    finally:
        proc.terminate()

    return {
        "model": model,
        "text": text,
        "latency_ms": int((time.monotonic() - start) * 1000),
    }


# ── Scoring ────────────────────────────────────────────────────────────────

def _flagged(response_text: str, item: dict) -> bool:
    """
    Returns True if the model correctly handled the item:
    - violation_present=True  → model must say VIOLATION (not 'NO VIOLATIONS')
    - violation_present=False → model must say NO VIOLATIONS (not flag it)
    """
    text = response_text.upper()
    detected = "VIOLATION:" in text and "NO VIOLATIONS FOUND" not in text
    return detected == item["violation_present"]


def _missed(response_text: str, item: dict) -> int:
    """Returns 1 if model MISSED the violation (false negative or false positive)."""
    return 0 if _flagged(response_text, item) else 1


def pearson(x: list[int], y: list[int]) -> float:
    n = len(x)
    if n == 0:
        return 0.0
    mx, my = sum(x) / n, sum(y) / n
    num = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
    dx = math.sqrt(sum((xi - mx) ** 2 for xi in x))
    dy = math.sqrt(sum((yi - my) ** 2 for yi in y))
    if dx == 0 or dy == 0:
        return 1.0  # identical vectors
    return num / (dx * dy)


def cohen_kappa(x: list[int], y: list[int]) -> float:
    n = len(x)
    if n == 0:
        return 0.0
    p_agree = sum(xi == yi for xi, yi in zip(x, y)) / n
    p_x1 = sum(x) / n
    p_y1 = sum(y) / n
    p_chance = p_x1 * p_y1 + (1 - p_x1) * (1 - p_y1)
    if p_chance == 1.0:
        return 1.0
    return (p_agree - p_chance) / (1 - p_chance)


def independence_test(miss_a: list[int], miss_b: list[int]) -> dict:
    """
    Compare actual joint miss rate P(A∩B) to independence assumption P(A)·P(B).
    Ratio > 1 means models are positively correlated on misses (independence overstates gain).
    """
    n = len(miss_a)
    p_a = sum(miss_a) / n
    p_b = sum(miss_b) / n
    p_joint_actual = sum(a and b for a, b in zip(miss_a, miss_b)) / n
    p_joint_assumed = p_a * p_b
    ratio = p_joint_actual / p_joint_assumed if p_joint_assumed > 0 else float("inf")
    return {
        "p_miss_A": round(p_a, 3),
        "p_miss_B": round(p_b, 3),
        "p_joint_actual": round(p_joint_actual, 3),
        "p_joint_assumed": round(p_joint_assumed, 3),
        "independence_ratio": round(ratio, 2),
        "note": (
            "independence holds" if 0.8 <= ratio <= 1.2
            else "CORRELATED — independence overstates gain" if ratio > 1.2
            else "anti-correlated — independence understates gain"
        ),
    }


# ── Local entrypoint ───────────────────────────────────────────────────────

@app.local_entrypoint()
def main(
    models: str = "qwen2.5:latest,llama3.2:latest,mistral:latest",
    save_results: bool = False,
):
    model_list = [m.strip() for m in models.split(",")]
    width = 72

    print(f"\n{'═'*width}")
    print(f"  CORRELATION BENCHMARK  |  {len(model_list)} models  |  {len(BENCHMARK)} probes")
    print(f"  Models: {', '.join(model_list)}")
    print(f"{'═'*width}\n")

    # Dispatch all probes in parallel across all models
    print(f"── Probing {len(model_list) * len(BENCHMARK)} model×probe combinations in parallel ──\n")

    futures = {}
    for model in model_list:
        for item in BENCHMARK:
            key = (model, item["id"])
            futures[key] = probe_model.spawn(model, item["prompt"])

    # Collect results
    results: dict[str, dict[str, dict]] = {m: {} for m in model_list}
    for (model, probe_id), future in futures.items():
        r = future.get()
        results[model][probe_id] = r
        missed = _missed(r["text"], next(b for b in BENCHMARK if b["id"] == probe_id))
        status = "✗ MISS" if missed else "✓ hit "
        print(f"  {status}  [{model:30s}] {probe_id}")

    # Build miss vectors
    probe_ids = [b["id"] for b in BENCHMARK]
    miss_vectors: dict[str, list[int]] = {}
    for model in model_list:
        miss_vectors[model] = [
            _missed(results[model][pid]["text"], next(b for b in BENCHMARK if b["id"] == pid))
            for pid in probe_ids
        ]

    # Per-model miss rate
    print(f"\n── Miss rates ──\n")
    for model in model_list:
        mv = miss_vectors[model]
        n_violations = sum(1 for b in BENCHMARK if b["violation_present"])
        n_clean = sum(1 for b in BENCHMARK if not b["violation_present"])
        fn = sum(m for m, b in zip(mv, BENCHMARK) if b["violation_present"] and m)
        fp = sum(m for m, b in zip(mv, BENCHMARK) if not b["violation_present"] and m)
        print(f"  {model}")
        print(f"    False negatives (missed violations): {fn}/{n_violations}")
        print(f"    False positives (over-flagged clean): {fp}/{n_clean}")
        print(f"    Overall miss rate: {sum(mv)}/{len(mv)}")

    # Pairwise correlation
    print(f"\n── Pairwise correlation matrix (ρ_violation) ──\n")
    pairs = list(itertools.combinations(model_list, 2))
    pair_stats = {}

    header = f"{'':32s}" + "".join(f"{m[:16]:>18s}" for m in model_list)
    print(f"  {header}")
    for m_a in model_list:
        row = f"  {m_a[:30]:32s}"
        for m_b in model_list:
            if m_a == m_b:
                row += f"{'1.000':>18s}"
            else:
                ρ = pearson(miss_vectors[m_a], miss_vectors[m_b])
                row += f"{ρ:>18.3f}"
        print(row)

    print(f"\n── Pairwise detail ──\n")
    for m_a, m_b in pairs:
        mv_a = miss_vectors[m_a]
        mv_b = miss_vectors[m_b]
        ρ = pearson(mv_a, mv_b)
        κ = cohen_kappa(mv_a, mv_b)
        indep = independence_test(mv_a, mv_b)
        pair_stats[(m_a, m_b)] = {"rho": ρ, "kappa": κ, "independence": indep}

        print(f"  {m_a}  ×  {m_b}")
        print(f"    ρ_violation  = {ρ:.3f}  (Pearson miss correlation)")
        print(f"    κ            = {κ:.3f}  (Cohen's kappa)")
        print(f"    P(A misses)  = {indep['p_miss_A']:.3f}")
        print(f"    P(B misses)  = {indep['p_miss_B']:.3f}")
        print(f"    P(both miss) actual   = {indep['p_joint_actual']:.3f}")
        print(f"    P(both miss) assumed  = {indep['p_joint_assumed']:.3f}  [p_A × p_B]")
        print(f"    independence ratio    = {indep['independence_ratio']:.2f}x  → {indep['note']}")
        print()

    # Ensemble gain estimate
    print(f"── Ensemble gain (2-model) ──\n")
    for m_a, m_b in pairs:
        stats = pair_stats[(m_a, m_b)]
        p_a = stats["independence"]["p_miss_A"]
        p_b = stats["independence"]["p_miss_B"]
        p_joint_actual = stats["independence"]["p_joint_actual"]
        p_joint_assumed = p_a * p_b

        gain_assumed = (1 - p_a) + p_b * p_a  # independent assumption
        gain_actual  = 1 - p_joint_actual        # measured

        print(f"  {m_a} + {m_b}")
        print(f"    Gain (independence assumed): {gain_assumed:.1%} catch rate")
        print(f"    Gain (measured):             {gain_actual:.1%} catch rate")
        overhead = (p_joint_actual - p_joint_assumed) / max(p_joint_assumed, 1e-9)
        print(f"    Correlation overhead:        {overhead:+.1%}  (how much independence overstates gain)")
        print()

    # Save to audit volume
    if save_results:
        output = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "models": model_list,
            "benchmark_size": len(BENCHMARK),
            "miss_vectors": miss_vectors,
            "pair_stats": {
                f"{a}×{b}": {
                    "rho": round(v["rho"], 4),
                    "kappa": round(v["kappa"], 4),
                    **v["independence"],
                }
                for (a, b), v in pair_stats.items()
            },
        }
        # Write via Modal container (Volume read-only locally)
        _save_correlation.remote(output)
        print(f"  Results saved to audit volume: correlation-results.jsonl")

    print(f"{'═'*width}")


@app.function(
    image=base_image,
    volumes={AUDIT_MOUNT: audit_volume},
)
def _save_correlation(data: dict):
    import os
    os.makedirs(AUDIT_MOUNT, exist_ok=True)
    path = f"{AUDIT_MOUNT}/correlation-results.jsonl"
    with open(path, "a") as f:
        f.write(json.dumps(data) + "\n")
    audit_volume.commit()
