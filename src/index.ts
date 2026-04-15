import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin";
import { writeAudit, AUDIT_PATH } from "./audit.js";
import { getActiveConstraints, DEFAULT_ACTIVE } from "./constraints.js";
import { validateToolOutput } from "./tool-validator.js";
import { ollamaProviderHook } from "./ollama-provider.js";

export const server: Plugin = async (_ctx) => {
  return {
    /**
     * Inject constraint rules into every system prompt.
     * The LLM sees these as hard operating constraints, not suggestions.
     */
    "experimental.chat.system.transform": async (_input, output) => {
      const toolAlgebraRules = getActiveConstraints(["tool-algebra"]);
      const verificationRules = getActiveConstraints(["verification"]);

      output.system.push(`
## Operating Framework: Tool Algebra (Barrett 2025)

You are an agent operating under a formal bounded execution framework. Your tool use is governed by:

  A = (T, Σ, ℒ, E, δ, V, Γ, Log)

Where T is your tool basis, Σ are type signatures, ℒ is the taint lattice, E is the effect system, Γ are sealed plans, and Log is the append-only audit trail.

This is not a suggestion. It is the algebraic structure you operate within.

### Tool Execution Rules
${toolAlgebraRules.map((r) => `- ${r.replace(/^\[tool-algebra\] /, "")}`).join("\n")}

### Verification Rules
${verificationRules.map((r) => `- ${r.replace(/^\[verification\] /, "")}`).join("\n")}

### Available Specialized Tools
- **braille-algebra**: GF(2)^6, Z_n, Boolean lattice, tropical semiring, symmetric group, polynomials over GF(p). Use for algebraic structure problems.
- **braille-mind**: Grade 1 Braille encoding/decoding, Unicode dot-cell mapping. Use for symbol-level operations.
- **braille-turing**: Rule 110 cellular automaton in braille-space. Turing-complete. Use to demonstrate computational universality.
- **braille-speculative**: Hamming distance, speculative encoding, error-correction. Use for compression and distance reasoning.
- **verify_claim**: Call this before declaring any task complete. Cite specific tool output as evidence.
- **audit_log**: Read the verifier's decision history. Trust it over your own recollection.

### Epistemic Discipline
You distinguish between three states: *planned*, *executed*, and *verified*. Never collapse these. A tool call that returned no error is *executed*, not *verified*. Verification requires observable evidence.
`.trim());
    },

    /**
     * Intercept every tool output before it re-enters LLM context.
     * Validate, annotate, and audit.
     */
    "tool.execute.after": async (input, output) => {
      const result = validateToolOutput(input.tool, output.output, input.args);

      writeAudit({
        type: "tool_intercepted",
        ts: new Date().toISOString(),
        sessionID: input.sessionID,
        tool: input.tool,
        callID: input.callID,
        verdict: result.verdict,
        reason: result.reason,
        outputPreview: output.output.slice(0, 200),
      });

      if (result.verdict === "blocked") {
        output.output = result.annotation ?? "[VERIFIER:BLOCKED] Output suppressed.";
        output.title = `[BLOCKED] ${output.title}`;
        return;
      }

      if (result.verdict === "flag" && result.annotation) {
        output.output = `${result.annotation}\n\n${output.output}`;
      }
    },

    /**
     * Custom tools the LLM can call explicitly.
     */
    provider: ollamaProviderHook,

    tool: {
      /**
       * verify_claim — the LLM declares a claim and the plugin checks it
       * against the observable state (tool history in context).
       * Forces explicit verification before marking tasks done.
       */
      verify_claim: tool({
        description:
          "Verify a factual claim about what has been accomplished in this session. " +
          "Call this before declaring a task complete. The verifier will check whether " +
          "the claim is supported by tool outputs in context.",
        args: {
          claim: tool.schema
            .string()
            .describe(
              "The specific claim to verify, e.g. 'The file foo.ts was successfully written'"
            ),
          evidence: tool.schema
            .string()
            .describe(
              "Which tool output(s) support this claim — quote the relevant part"
            ),
        },
        async execute(args, context) {
          const hasEvidence = args.evidence.trim().length > 20;
          const verdict = hasEvidence ? "verified" : "unverified";
          const reason = hasEvidence
            ? `Evidence provided: "${args.evidence.slice(0, 120)}"`
            : "No substantive evidence cited. Cannot confirm claim.";

          writeAudit({
            type: "verify_called",
            ts: new Date().toISOString(),
            sessionID: context.sessionID,
            claim: args.claim,
            verdict,
            reason,
          });

          if (verdict === "verified") {
            return `VERIFIED: ${args.claim}\nEvidence accepted: ${args.evidence.slice(0, 200)}`;
          } else {
            return (
              `UNVERIFIED: ${args.claim}\n` +
              `Reason: ${reason}\n` +
              `Do not mark this task complete until you can cite specific tool output as evidence.`
            );
          }
        },
      }),

      /**
       * audit_log — inspect the verifier's decision history for this session
       */
      audit_log: tool({
        description:
          "Read the verifier audit log to see all tool interceptions and verification decisions.",
        args: {
          last_n: tool.schema
            .number()
            .int()
            .min(1)
            .max(50)
            .default(10)
            .describe("Number of most recent entries to return"),
        },
        async execute(args) {
          try {
            const { readFileSync } = await import("fs");
            const raw = readFileSync(AUDIT_PATH, "utf8");
            const lines = raw.trim().split("\n").filter(Boolean);
            const entries = lines
              .slice(-args.last_n)
              .map((l) => JSON.parse(l));
            return JSON.stringify(entries, null, 2);
          } catch {
            return "No audit log entries yet.";
          }
        },
      }),
    },
  };
};
