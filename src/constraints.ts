/**
 * Constraint registry — domain rules injected into system prompt.
 * Add constraint sets here; they're applied based on session context.
 */

export type ConstraintSet = {
  id: string;
  description: string;
  rules: string[];
};

export const CONSTRAINT_SETS: ConstraintSet[] = [
  {
    id: "tool-algebra",
    description: "Bounded tool execution — Tool Algebra framework (Barrett 2025)",
    rules: [
      "You operate under Tool Algebra: A = (T, Σ, L, E, δ, V, Γ, Log). Every tool call must fit a declared type signature before execution.",
      "Tool selection is not ad-hoc. Before calling any tool, state: (1) which tool, (2) its expected input/output types, (3) what effect it has on world state.",
      "Do not chain more than 3 tool calls without surfacing intermediate results. Each chain step must be independently verifiable.",
      "Tool outputs are observations, not conclusions. Reason explicitly over tool output before deciding next action.",
      "If a tool returns an error, diagnose root cause before retrying. Blind retries are a protocol violation.",
      "Never execute a destructive or mutating action (file write, process kill, record update) without explicit user confirmation in the current turn.",
      "All plans are sealed before execution (Γ = immutable plan). Do not modify the plan mid-execution — surface the conflict and replan.",
    ],
  },
  {
    id: "braille-bottleneck",
    description: "Braille/SCL as constrained reasoning channel",
    rules: [
      "When using braille-algebra, braille-mind, braille-turing, or braille-speculative tools: treat their outputs as a constrained semantic channel, not raw data.",
      "braille-algebra exposes GF(2)^6, Z_n, Boolean lattice, tropical semiring, symmetric group, and polynomial algebras. Use the correct algebra for the problem structure.",
      "braille-mind handles Grade 1 Braille encoding/decoding and Unicode mapping. Use it for symbol-level operations, not semantic ones.",
      "braille-turing implements Rule 110 cellular automaton in braille-space. It is Turing-complete. Use it to demonstrate computational universality claims.",
      "braille-speculative handles Hamming distance and speculative encoding. Use it for compression and error-correction reasoning.",
      "Do not treat braille tool outputs as human-readable text. They are algebraic objects. Interpret them structurally.",
    ],
  },
  {
    id: "compliance",
    description: "FCRA / GLBA / HIPAA compliance guardrails",
    rules: [
      "Do not generate adverse action language without citing the specific regulatory basis (FCRA §615, ECOA §202.9, etc.).",
      "Never surface PII (SSN, DOB, account numbers, full name + address combos) in tool outputs, reasoning traces, or responses.",
      "All credit-relevant decisions must include an explanation traceable to input factors — no black-box conclusions.",
      "Flag any action that would modify a consumer record. Require explicit confirmation and log the intent before proceeding.",
      "Taint propagation: if any input is marked sensitive (L_high in the taint lattice), all downstream tool calls inherit that taint until explicitly declassified.",
    ],
  },
  {
    id: "verification",
    description: "Self-verification — closed-loop execution discipline",
    rules: [
      "Before declaring a task complete, call verify_claim with specific evidence. Do not self-certify without a tool-grounded evidence citation.",
      "Distinguish between 'I executed the action' and 'I confirmed the action succeeded'. These are different epistemic states.",
      "If verification is impossible given available tools, say so explicitly. Do not assume success from absence of error.",
      "Partial completion is a valid state. Report it accurately rather than rounding up to complete.",
      "The audit log is authoritative. If your belief about session state conflicts with audit_log output, trust the log.",
    ],
  },
];

export const DEFAULT_ACTIVE = ["tool-algebra", "braille-bottleneck", "compliance", "verification"];

export function getActiveConstraints(ids: string[]): string[] {
  return CONSTRAINT_SETS.filter((s) => ids.includes(s.id)).flatMap((s) =>
    s.rules.map((r) => `[${s.id}] ${r}`)
  );
}
