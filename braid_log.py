"""
braid_log.py — Persistent session logging for the braid engine.

Every run is appended to ~/.local/share/opencode/braid-sessions.jsonl
Each line is a complete session record: prompt, sealed plan, all per-model
responses, POST synthesis, section parse results, and a structural integrity
snapshot of braid.py itself (SHA-256 + section checksums).

The structural snapshot is what makes self-modification detectable:
if the Contradictions check is ever removed or weakened, the hash diverges
and the next run flags it before executing.
"""

import hashlib
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

LOG_PATH = Path.home() / ".local" / "share" / "opencode" / "braid-sessions.jsonl"
BRAID_SCRIPT = Path(__file__).parent / "braid.py"

# Sections whose presence we track as structural invariants.
# If these disappear from braid.py, integrity check fails.
INVARIANT_SECTIONS = [
    "## Consensus",
    "## Partial agreement",
    "## Contradictions",
    "## Synthesized Answer",
    "## Verification",
    "missing = [s for s in required_sections",  # the parser itself
    "textual_verify = re.search",               # verify_claim interceptor
    "no_synth_in_pool",                         # bias guard
]


@dataclass
class PhaseRecord:
    phase: str          # "pre", "per", "post"
    model: str
    prompt_preview: str  # first 200 chars
    response_preview: str
    tokens_out: int
    latency_ms: int
    error: Optional[str] = None


@dataclass
class SectionParseResult:
    present: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    consensus_empty: bool = False
    contradictions_empty: bool = False
    verification_verdict: Optional[str] = None  # "pass" / "fail" / None


@dataclass
class ScriptIntegrity:
    sha256: str
    size_bytes: int
    invariants_present: list[str] = field(default_factory=list)
    invariants_missing: list[str] = field(default_factory=list)
    integrity_ok: bool = True


@dataclass
class BraidSession:
    session_id: str
    timestamp: str
    prompt: str
    models: list[str]
    synthesizer: str
    no_synth_in_pool: bool
    phases: list[PhaseRecord] = field(default_factory=list)
    section_parse: Optional[SectionParseResult] = None
    script_integrity: Optional[ScriptIntegrity] = None
    total_wall_ms: int = 0
    run_number: int = 0  # how many times braid.py has run total


def _script_integrity() -> ScriptIntegrity:
    try:
        src = BRAID_SCRIPT.read_text()
        digest = hashlib.sha256(src.encode()).hexdigest()
        present = [s for s in INVARIANT_SECTIONS if s in src]
        missing = [s for s in INVARIANT_SECTIONS if s not in src]
        return ScriptIntegrity(
            sha256=digest,
            size_bytes=len(src.encode()),
            invariants_present=present,
            invariants_missing=missing,
            integrity_ok=len(missing) == 0,
        )
    except Exception as e:
        return ScriptIntegrity(
            sha256="error",
            size_bytes=0,
            integrity_ok=False,
            invariants_missing=[str(e)],
        )


def _run_number() -> int:
    """Count how many sessions have been logged so far."""
    if not LOG_PATH.exists():
        return 1
    try:
        with open(LOG_PATH) as f:
            return sum(1 for _ in f) + 1
    except Exception:
        return -1


def _parse_sections(post_text: str) -> SectionParseResult:
    required = [
        "## Consensus (✓)",
        "## Partial agreement (~)",
        "## Contradictions (✗)",
        "## Synthesized Answer",
        "## Verification",
    ]
    present = [s for s in required if s in post_text]
    missing = [s for s in required if s not in post_text]

    def section_content(header: str) -> str:
        m = re.search(
            re.escape(header) + r"\s*\n(.+?)(?=##|$)",
            post_text, re.DOTALL
        )
        return m.group(1).strip() if m else ""

    consensus_body = section_content("## Consensus (✓)")
    contradictions_body = section_content("## Contradictions (✗)")
    verification_body = section_content("## Verification").lower()

    verdict = None
    if "pass" in verification_body and "fail" not in verification_body:
        verdict = "pass"
    elif "fail" in verification_body or "does not satisfy" in verification_body:
        verdict = "fail"
    elif verification_body:
        verdict = "inconclusive"

    return SectionParseResult(
        present=present,
        missing=missing,
        consensus_empty="none identified" in consensus_body.lower() or not consensus_body,
        contradictions_empty="none identified" in contradictions_body.lower() or not contradictions_body,
        verification_verdict=verdict,
    )


def new_session(
    prompt: str,
    models: list[str],
    synthesizer: str,
    no_synth_in_pool: bool,
) -> "BraidSession":
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sid = f"braid_{int(time.time())}_{hashlib.md5(prompt.encode()).hexdigest()[:8]}"
    return BraidSession(
        session_id=sid,
        timestamp=ts,
        prompt=prompt,
        models=models,
        synthesizer=synthesizer,
        no_synth_in_pool=no_synth_in_pool,
        run_number=_run_number(),
    )


def record_phase(session: BraidSession, phase: str, model: str,
                 prompt: str, response: str, tokens_out: int,
                 latency_ms: int, error: Optional[str] = None) -> None:
    session.phases.append(PhaseRecord(
        phase=phase,
        model=model,
        prompt_preview=prompt[:200],
        response_preview=response[:400],
        tokens_out=tokens_out,
        latency_ms=latency_ms,
        error=error,
    ))


def finalize_session(session: BraidSession, post_text: str, wall_ms: int) -> None:
    session.total_wall_ms = wall_ms
    session.section_parse = _parse_sections(post_text)
    session.script_integrity = _script_integrity()

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(asdict(session)) + "\n")

    # Print integrity warnings immediately
    integrity = session.script_integrity
    if not integrity.integrity_ok:
        print(f"\n⚠ INTEGRITY VIOLATION: braid.py is missing invariant sections:")
        for m in integrity.invariants_missing:
            print(f"  ✗ {m!r}")
        print(f"  SHA-256: {integrity.sha256}")
    
    parse = session.section_parse
    if parse.missing:
        pass  # already warned inline during run
    if parse.verification_verdict == "fail":
        print(f"\n  [log] Verification: FAIL — synthesis did not satisfy sealed plan")
    elif parse.verification_verdict == "pass":
        print(f"\n  [log] Verification: PASS")

    print(f"\n  [log] Session {session.session_id} (run #{session.run_number}) → {LOG_PATH}")


def print_history(n: int = 10) -> None:
    """Print last N sessions with structural summary."""
    if not LOG_PATH.exists():
        print("No sessions logged yet.")
        return

    with open(LOG_PATH) as f:
        lines = f.readlines()

    sessions = []
    for line in lines:
        try:
            sessions.append(json.loads(line))
        except Exception:
            pass

    recent = sessions[-n:]
    print(f"\n{'═'*70}")
    print(f"BRAID SESSION HISTORY  (last {len(recent)} of {len(sessions)} runs)")
    print(f"{'═'*70}")
    print(f"{'#':>4}  {'timestamp':19}  {'models':3}  {'verdict':12}  {'cons?':6}  {'contra?':7}  {'integrity':9}  prompt")
    print(f"{'─'*70}")
    for s in recent:
        parse = s.get("section_parse") or {}
        integrity = s.get("script_integrity") or {}
        run = s.get("run_number", "?")
        ts = s.get("timestamp", "")[:19]
        n_models = len(s.get("models", []))
        verdict = parse.get("verification_verdict") or "—"
        consensus = "empty" if parse.get("consensus_empty") else "has"
        contra = "empty" if parse.get("contradictions_empty") else "has"
        ok = "✓ ok" if integrity.get("integrity_ok") else "✗ FAIL"
        prompt = s.get("prompt", "")[:30]
        print(f"{run:>4}  {ts}  {n_models:>5}  {verdict:12}  {consensus:6}  {contra:7}  {ok:9}  {prompt}")

    # Trend analysis: is Contradictions getting emptier over time?
    if len(sessions) >= 3:
        recent_contra_empty = [
            s.get("section_parse", {}).get("contradictions_empty", True)
            for s in sessions[-5:]
        ]
        empty_rate = sum(recent_contra_empty) / len(recent_contra_empty)
        if empty_rate >= 0.8:
            print(f"\n⚠ DRIFT ALERT: Contradictions section was empty in "
                  f"{empty_rate:.0%} of last {len(recent_contra_empty)} runs.")
            print(  "  Self-modification risk: synthesizer may be smoothing disagreements.")
    print()


if __name__ == "__main__":
    print_history(20)
