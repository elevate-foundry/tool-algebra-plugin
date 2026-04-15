/**
 * Tool output validator.
 * Runs heuristic checks on tool outputs before they re-enter LLM context.
 * Returns a verdict and optional annotation to prepend to the output.
 */

type Verdict = "pass" | "flag" | "blocked";

type ValidationResult = {
  verdict: Verdict;
  reason?: string;
  annotation?: string;
};

type Rule = {
  name: string;
  test: (tool: string, output: string, args: unknown) => ValidationResult | null;
};

const RULES: Rule[] = [
  {
    name: "error-not-diagnosed",
    test: (_tool, output) => {
      const lower = output.toLowerCase();
      const isError =
        lower.includes("error:") ||
        lower.includes("exception:") ||
        lower.includes("traceback") ||
        lower.includes("exitcode: 1") ||
        lower.includes("exit code 1");
      if (!isError) return null;
      return {
        verdict: "flag",
        reason: "Tool returned an error signal",
        annotation:
          "[VERIFIER] This output contains an error. Diagnose the root cause before retrying.",
      };
    },
  },
  {
    name: "pii-exposure",
    test: (_tool, output) => {
      const ssnPattern = /\b\d{3}-\d{2}-\d{4}\b/;
      const creditCardPattern = /\b(?:\d{4}[- ]){3}\d{4}\b/;
      if (ssnPattern.test(output) || creditCardPattern.test(output)) {
        return {
          verdict: "blocked",
          reason: "PII detected in tool output (SSN or credit card pattern)",
          annotation:
            "[VERIFIER:BLOCKED] Output contained PII and has been redacted. Do not proceed with this data.",
        };
      }
      return null;
    },
  },
  {
    name: "empty-output",
    test: (_tool, output) => {
      if (output.trim().length === 0) {
        return {
          verdict: "flag",
          reason: "Tool returned empty output",
          annotation:
            "[VERIFIER] Tool returned no output. Confirm the action actually executed before proceeding.",
        };
      }
      return null;
    },
  },
  {
    name: "large-output-truncation",
    test: (_tool, output) => {
      if (output.length > 8000) {
        return {
          verdict: "flag",
          reason: `Output is ${output.length} chars — likely truncated`,
          annotation: `[VERIFIER] Output is large (${output.length} chars). You may be seeing a truncated view. Verify completeness before acting.`,
        };
      }
      return null;
    },
  },
  {
    name: "bash-destructive",
    test: (tool, _output, args) => {
      if (tool !== "bash") return null;
      const cmd =
        typeof args === "object" &&
        args !== null &&
        "command" in args &&
        typeof (args as Record<string, unknown>).command === "string"
          ? ((args as Record<string, string>).command as string)
          : "";
      const destructive = [
        /\brm\s+-rf\b/,
        /\bdrop\s+table\b/i,
        /\btruncate\b/i,
        /\bformat\b/,
        /\bmkfs\b/,
      ];
      for (const pattern of destructive) {
        if (pattern.test(cmd)) {
          return {
            verdict: "flag",
            reason: `Destructive bash pattern detected: ${pattern}`,
            annotation:
              "[VERIFIER] This command has destructive potential. Confirm user intent before treating output as authoritative.",
          };
        }
      }
      return null;
    },
  },
];

export function validateToolOutput(
  tool: string,
  output: string | null | undefined,
  args: unknown
): ValidationResult {
  const safeOutput = output ?? "";
  for (const rule of RULES) {
    const result = rule.test(tool, safeOutput, args);
    if (result) return result;
  }
  return { verdict: "pass" };
}
