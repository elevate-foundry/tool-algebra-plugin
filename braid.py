#!/usr/bin/env python3
"""
braid.py — Multi-model consensus engine routed through opencode.

Every call goes through `opencode run --format json` so the verifier plugin
fires on each one: system prompt injection, tool output interception, audit log.

Three phases per braid:

  PHASE 0 — PRE (1 call, synthesizer model)
    Seals the plan: declares intent, expected output shape, which models will run.
    This is Γ in Tool Algebra — the immutable plan before execution begins.

  PHASE 1 — PER (N parallel calls, one per model)
    Each model gets the same prompt through opencode. Plugin constraints active.
    Responses streamed, text extracted from JSON event stream.

  PHASE 2 — POST (1 call, synthesizer model)
    Sees all N responses. Produces braided output: ✓ consensus, ~ partial, ✗ contradiction.
    Instructed to call verify_claim before signing off.

Usage:
    python3 braid.py "what is the most important property of a tool algebra?"
    python3 braid.py --models qwen2.5:latest llama3.2:latest gemma3:4b
    python3 braid.py --synthesizer deepseek-r1:latest --verbose "explain Rule 110"
"""

import argparse
import ast
import asyncio
import json
import os
import re
import subprocess
import sys
import time
from braid_log import (
    new_session, record_phase, finalize_session, print_history, BraidSession,
    LOG_PATH,
)
from dataclasses import dataclass, field
from typing import Optional

DEFAULT_MODELS = [
    "ollama/qwen2.5:latest",
    "ollama/llama3.2:latest",
    "ollama/gemma3:4b",
]
DEFAULT_SYNTHESIZER = "ollama/qwen2.5:latest"

# Directory opencode reads config from (where opencode.jsonc + plugin are registered)
OPENCODE_CWD = os.path.expanduser("~")


@dataclass
class ModelResponse:
    model: str
    text: str
    latency_ms: int = 0
    tokens_out: int = 0
    error: Optional[str] = None
    events: list[dict] = field(default_factory=list)


def _run_opencode_sync(model: str, prompt: str, timeout: int = 120, pure: bool = False) -> ModelResponse:
    """
    Runs: opencode run "<prompt>" --model <model> --format json
    from OPENCODE_CWD so the plugin and config are loaded.
    pure=True adds --pure to suppress MCP tools (prevents tool-spiral on simple queries).
    Extracts text from the JSON event stream.
    """
    start = time.monotonic()
    cmd = [
        "opencode", "run", prompt,
        "--model", model,
        "--format", "json",
    ]
    if pure:
        cmd.append("--pure")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=OPENCODE_CWD,
        )
        raw = result.stdout.strip()
        if not raw:
            stderr_snippet = result.stderr[-300:] if result.stderr else "(no stderr)"
            return ModelResponse(model=model, text="", error=f"no output. stderr: {stderr_snippet}")

        events = []
        text_parts = []
        tokens_out = 0

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                events.append(ev)
                t = ev.get("type", "")
                # text event: part.text
                if t == "text":
                    part = ev.get("part", {})
                    text_parts.append(part.get("text", ""))
                # step_finish carries token counts
                elif t == "step_finish":
                    part = ev.get("part", {})
                    tokens_out += part.get("tokens", {}).get("output", 0)
                elif t == "error":
                    err = ev.get("error", {})
                    return ModelResponse(
                        model=model,
                        text="",
                        error=f"{err.get('name','error')}: {err.get('data',{}).get('message', str(err))}",
                        events=events,
                    )
            except json.JSONDecodeError:
                pass

        text = "".join(text_parts).strip()
        if not text:
            return ModelResponse(model=model, text="", error="no text in event stream", events=events)

        return ModelResponse(
            model=model,
            text=text,
            latency_ms=int((time.monotonic() - start) * 1000),
            tokens_out=tokens_out,
            events=events,
        )

    except subprocess.TimeoutExpired:
        return ModelResponse(model=model, text="", error=f"timeout after {timeout}s")
    except FileNotFoundError:
        return ModelResponse(model=model, text="", error="opencode not found in PATH")
    except Exception as e:
        return ModelResponse(model=model, text="", error=str(e))


async def run_opencode(model: str, prompt: str, timeout: int = 120, pure: bool = False) -> ModelResponse:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _run_opencode_sync, model, prompt, timeout, pure)


def _print_response(r: ModelResponse, label: str = "") -> None:
    tag = label or r.model
    if r.error:
        print(f"\n✗ {tag}: {r.error}", file=sys.stderr)
        return
    print(f"\n┌─ {tag}  ({r.latency_ms}ms, {r.tokens_out} tok)")
    for line in r.text.splitlines():
        print(f"│  {line}")
    print(f"└{'─'*58}")


def _extract_ts_exports(path: str) -> str:
    """Extract exported function/const names and their signatures from a .ts file."""
    try:
        src = open(path).read()
        exports = []
        for m in re.finditer(
            r'^export\s+(async\s+)?(?:function|const|class|type|interface)\s+(\w+)([^{;\n]*)',
            src, re.MULTILINE
        ):
            exports.append(f"  {m.group(0).rstrip()}")
        return "\n".join(exports) if exports else "  (no exports found)"
    except Exception as e:
        return f"  (could not read: {e})"


def _build_context() -> str:
    """
    Reads the real source files and returns a concise architectural context block.
    Injected into every phase prompt so models operate on ground truth, not hallucination.
    """
    repo = os.path.dirname(os.path.abspath(__file__))
    sections = []

    # ── 1. File tree — exact paths, no invention possible ──────────────────────
    tree_lines = [
        "data/braid-sessions.jsonl   ← LFS session log (append-only)",
        "braid.py                    ← engine (this file)",
        "braid_log.py                ← integrity guard + session persistence",
        "src/",
        "  index.ts                  ← plugin entry: system prompt injection, tool hooks",
        "  constraints.ts            ← CONSTRAINT_SETS, DEFAULT_ACTIVE, getActiveConstraints()",
        "  tool-validator.ts         ← validateToolOutput(toolName, output) → ValidationResult",
        "  audit.ts                  ← writeAudit(entry), AUDIT_PATH",
        "  ollama-provider.ts        ← ollamaProviderHook: registers local Ollama models",
        "  tests/                    ← vitest test suite",
    ]
    sections.append("### Repository file tree (exact — do not invent paths not listed here)\n"
                    + "\n".join(tree_lines))

    # ── 2. braid.py — AST-parsed function signatures ───────────────────────────
    try:
        src = open(os.path.join(repo, "braid.py")).read()
        tree = ast.parse(src)
        sigs = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = [a.arg for a in node.args.args]
                doc = ast.get_docstring(node) or ""
                prefix = "async " if isinstance(node, ast.AsyncFunctionDef) else ""
                sigs.append(f"  {prefix}def {node.name}({', '.join(args)})"
                            + (f"  # {doc[:80]}" if doc else ""))
        sections.append("### braid.py — function signatures\n" + "\n".join(sigs))
    except Exception as e:
        sections.append(f"### braid.py — could not parse: {e}")

    # ── 3. braid_log.py — invariants (what the integrity guard protects) ───────
    try:
        log_src = open(os.path.join(repo, "braid_log.py")).read()
        m = re.search(r'INVARIANT_SECTIONS = \[(.+?)\]', log_src, re.DOTALL)
        if m:
            sections.append("### braid_log.py — INVARIANT_SECTIONS (must never disappear from braid.py)\n"
                            + m.group(0))
    except Exception:
        pass

    # ── 4. TypeScript export map — exact exported symbols per file ─────────────
    ts_files = {
        "src/index.ts":          os.path.join(repo, "src", "index.ts"),
        "src/constraints.ts":    os.path.join(repo, "src", "constraints.ts"),
        "src/tool-validator.ts": os.path.join(repo, "src", "tool-validator.ts"),
        "src/audit.ts":          os.path.join(repo, "src", "audit.ts"),
        "src/ollama-provider.ts":os.path.join(repo, "src", "ollama-provider.ts"),
    }
    export_lines = []
    for fname, fpath in ts_files.items():
        export_lines.append(f"\n{fname}:")
        export_lines.append(_extract_ts_exports(fpath))
    sections.append("### TypeScript exports — exact symbols (use only these, not invented names)\n"
                    + "\n".join(export_lines))

    # ── 5. src/index.ts — full plugin entry (hooks are small) ──────────────────
    try:
        plugin_src = open(os.path.join(repo, "src", "index.ts")).read()
        sections.append("### src/index.ts — full source\n" + plugin_src)
    except Exception:
        pass

    return (
        "## Braid Engine — Architectural Context\n"
        "You are running inside this system. The following is the REAL source code.\n"
        "Do not invent function names, file paths, or data structures not listed here.\n\n"
        + "\n\n".join(sections)
    )


async def braid(
    prompt: str,
    models: list[str],
    synthesizer: str,
    verbose: bool = False,
    no_synth_in_pool: bool = False,
) -> None:
    width = 60
    wall_start = time.monotonic()
    session = new_session(prompt, models, synthesizer, no_synth_in_pool)

    print(f"\n{'='*width}")
    print(f"BRAID  |  pre → {len(models)}×parallel → post  [run #{session.run_number}]")
    print(f"Models: {', '.join(models)}")
    print(f"Synth:  {synthesizer}")
    print(f"Prompt: {prompt[:width-8]}{'...' if len(prompt)>width-8 else ''}")
    print(f"{'='*width}\n")

    # ── PHASE 0: PRE ──────────────────────────────────────────────────────────
    # Seal the plan. The synthesizer declares what it's about to do before any
    # model queries run. This is Γ — the immutable intent record.
    print("── PHASE 0: PRE (sealing plan) " + "─"*(width-31))
    arch_context = _build_context()
    pre_prompt = (
        f"INSTRUCTION: Respond with plain text only. Do not call any tools. Do not use browser or filesystem tools.\n\n"
        f"{arch_context}\n\n"
        f"You are about to coordinate a multi-model query on this system. "
        f"The user's question is: \"{prompt}\"\n\n"
        f"The following models will each independently answer it: {', '.join(models)}.\n\n"
        f"Before they run, state in 2-3 sentences: "
        f"(1) what a good answer to this question looks like given the actual codebase above, "
        f"(2) what disagreements you expect between models, "
        f"(3) what you will use as the verification criterion for the final synthesis. "
        f"Be specific. This is your sealed plan (Γ) — you cannot revise it later. "
        f"Reply with plain text only."
    )
    pre = await run_opencode(synthesizer, pre_prompt)
    _print_response(pre, label=f"PRE [{synthesizer}]")
    record_phase(session, "pre", synthesizer, pre_prompt, pre.text or "",
                 pre.tokens_out, pre.latency_ms, pre.error)
    if pre.error:
        print("Pre-phase failed — continuing without sealed plan.", file=sys.stderr)
        sealed_plan = "(no plan)"
    else:
        sealed_plan = pre.text

    # ── PHASE 1: PER (parallel) ───────────────────────────────────────────────
    # Prepend no-tool instruction so models answer directly without spiraling into MCP tools
    per_prompt = f"INSTRUCTION: Answer with plain text only. Do not call any tools.\n\n{arch_context}\n\n{prompt}"
    pool = [m for m in models if m != synthesizer] if no_synth_in_pool else models
    if no_synth_in_pool and synthesizer in models:
        print(f"  [bias guard] excluded {synthesizer} from pool — it synthesizes but doesn't vote")
    print(f"\n── PHASE 1: PER ({len(pool)} models in parallel) " + "─"*(width-38-len(str(len(pool)))))
    tasks = [run_opencode(m, per_prompt, timeout=180) for m in pool]
    responses: list[ModelResponse] = await asyncio.gather(*tasks)

    successful = [r for r in responses if not r.error]
    failed = [r for r in responses if r.error]

    for r in responses:
        _print_response(r)
        record_phase(session, "per", r.model, per_prompt, r.text or "",
                     r.tokens_out, r.latency_ms, r.error)

    if not successful:
        print("\nAll models failed — cannot synthesize.", file=sys.stderr)
        return

    # ── PHASE 2: POST (synthesis) ─────────────────────────────────────────────
    print(f"\n── PHASE 2: POST (synthesis via {synthesizer}) " + "─"*(width-43-len(synthesizer)))

    # Trim each response to 400 chars so the synthesis prompt doesn't exhaust
    # the model's output budget before reaching Synthesized Answer / Verification
    MAX_RESPONSE_CHARS = 400
    responses_block = "\n\n".join(
        f"### {r.model}\n{r.text[:MAX_RESPONSE_CHARS]}"
        + ("..." if len(r.text) > MAX_RESPONSE_CHARS else "")
        for r in successful
    )
    failed_note = (
        f"\nNote: {len(failed)} model(s) failed to respond: {[r.model for r in failed]}."
        if failed else ""
    )

    post_prompt = (
        f"INSTRUCTION: Respond with plain text only. Do not call browser or filesystem tools.\n"
        f"You MUST reproduce each section header EXACTLY as written below, then fill in the content.\n\n"
        f"You are the synthesis agent for a multi-model braid.\n\n"
        f"Sealed plan (Γ): {sealed_plan}\n\n"
        f"Original question: {prompt}\n{failed_note}\n\n"
        f"Model responses:\n\n{responses_block}\n\n"
        f"Fill in each section below. Do not skip any section. Do not rename headers.\n\n"
        f"## Consensus (✓)\n"
        f"List every claim ALL models agreed on. If none, write 'None identified.'\n\n"
        f"## Partial agreement (~)\n"
        f"List claims present in SOME responses only. Name which model(s) made each claim.\n\n"
        f"## Contradictions (✗)\n"
        f"List direct disagreements. Quote both sides with model name. If none, write 'None identified.'\n\n"
        f"## Synthesized Answer\n"
        f"Your best unified answer to the original question, citing which models supported each claim.\n\n"
        f"## Verification\n"
        f"State whether your synthesis satisfies the sealed plan's verification criterion. "
        f"Be explicit: quote the criterion, then judge pass or fail with one sentence of evidence."
    )

    post = await run_opencode(synthesizer, post_prompt)
    _print_response(post, label=f"POST [{synthesizer}]")
    record_phase(session, "post", synthesizer, post_prompt, post.text or "",
                 post.tokens_out, post.latency_ms, post.error)

    if post.error:
        finalize_session(session, "", int((time.monotonic()-wall_start)*1000))
    else:
        # ── Parse and validate braided structure ─────────────────────────────
        required_sections = [
            "## Consensus (✓)",
            "## Partial agreement (~)",
            "## Contradictions (✗)",
            "## Synthesized Answer",
            "## Verification",
        ]
        missing = [s for s in required_sections if s not in post.text]
        if missing:
            print(f"\n⚠ POST missing sections: {missing}", file=sys.stderr)

        # ── Detect textual verify_claim and route a real verification call ───
        # Some models write [verification_claim] or verify_claim(...) as prose
        # instead of making a real tool call. Intercept and make the call properly.
        textual_verify = re.search(
            r'\[verification[_\s]?claim\]|verify_claim\s*[:(]',
            post.text, re.IGNORECASE
        )
        if textual_verify:
            print(f"\n  [braid] detected textual verify_claim — routing real verification call...")
            # Extract the Synthesized Answer section as the claim to verify
            synth_match = re.search(
                r'##\s*Synthesized Answer\s*\n(.+?)(?=##|$)',
                post.text, re.DOTALL
            )
            claim_text = synth_match.group(1).strip()[:300] if synth_match else post.text[:300]

            verify_prompt = (
                f"INSTRUCTION: Call the verify_claim tool with the following arguments.\n"
                f"Do not answer in prose. Use the verify_claim tool.\n\n"
                f"claim: The following synthesis correctly answers '{prompt}': "
                f"{claim_text[:200]}\n"
                f"evidence: The synthesis is drawn from {len(successful)} model responses and "
                f"satisfies the sealed plan criterion: {sealed_plan[:200]}"
            )
            verify_result = await run_opencode(synthesizer, verify_prompt)
            if not verify_result.error:
                print(f"\n  [verify_claim result]")
                for line in verify_result.text.splitlines():
                    print(f"  │  {line}")
            else:
                print(f"  [verify_claim failed] {verify_result.error}", file=sys.stderr)

        print(f"\n{'═'*width}")
        print("BRAIDED OUTPUT")
        print(f"{'═'*width}")
        print(post.text)
        print(f"{'═'*width}\n")

        finalize_session(session, post.text, int((time.monotonic()-wall_start)*1000))

    if verbose:
        print(f"Total model responses: {len(successful)}/{len(models)}")
        print(f"Session log: {LOG_PATH}  (git LFS tracked)")
        # show last few audit entries
        audit_path = os.path.expanduser("~/.local/share/opencode/verifier-audit.jsonl")
        if os.path.exists(audit_path):
            with open(audit_path) as f:
                lines = f.readlines()
            recent = lines[-min(6, len(lines)):]
            print(f"\nLast {len(recent)} audit entries:")
            for line in recent:
                try:
                    e = json.loads(line)
                    print(f"  {e.get('ts','')[:19]}  {e.get('type'):25s}  {e.get('verdict','') or e.get('claim','')[:40]}")
                except Exception:
                    pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Three-phase braid engine through opencode")
    parser.add_argument("prompt", nargs="*", help="Prompt to braid")
    parser.add_argument("--models", "-m", nargs="+", default=DEFAULT_MODELS)
    parser.add_argument("--synthesizer", "-s", default=DEFAULT_SYNTHESIZER)
    parser.add_argument("--no-synth-in-pool", action="store_true",
                        help="Exclude synthesizer from Phase 1 pool to eliminate self-confirmation bias")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--history", action="store_true",
                        help="Print session history and drift analysis, then exit")
    args = parser.parse_args()

    if args.history:
        print_history(20)
        return

    prompt = " ".join(args.prompt) if args.prompt else None
    if not prompt:
        print('Usage: python3 braid.py "your question here"')
        print('       python3 braid.py --history   # view session log + drift analysis')
        sys.exit(1)

    asyncio.run(braid(
        prompt=prompt,
        models=args.models,
        synthesizer=args.synthesizer,
        verbose=args.verbose,
        no_synth_in_pool=args.no_synth_in_pool,
    ))


if __name__ == "__main__":
    main()
