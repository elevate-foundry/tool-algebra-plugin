/**
 * Tool output validator.
 * Runs ALL rules and accumulates findings — worst verdict wins.
 * Compliance rules (FCRA, GLBA, HIPAA, ISO 27001, SOC) are mechanical blocks,
 * not advisory. A model CAN proceed past a durable-write block by supplying
 * a justification field in args citing the regulatory basis. If it can't, blocked.
 */

type Verdict = "pass" | "flag" | "blocked";

type ValidationResult = {
  verdict: Verdict;
  reason?: string;
  annotation?: string;
  findings?: Finding[];
};

type Finding = {
  rule: string;
  verdict: Verdict;
  reason: string;
};

type Rule = {
  name: string;
  test: (tool: string, output: string, args: unknown) => Finding | null;
};

// ── helpers ────────────────────────────────────────────────────────────────

function getArg(args: unknown, key: string): string {
  if (typeof args === "object" && args !== null && key in args) {
    const v = (args as Record<string, unknown>)[key];
    return typeof v === "string" ? v : "";
  }
  return "";
}

const VERDICT_RANK: Record<Verdict, number> = { pass: 0, flag: 1, blocked: 2 };

function worstVerdict(findings: Finding[]): Verdict {
  return findings.reduce<Verdict>(
    (worst, f) => (VERDICT_RANK[f.verdict] > VERDICT_RANK[worst] ? f.verdict : worst),
    "pass"
  );
}

// ── rule definitions ───────────────────────────────────────────────────────

const RULES: Rule[] = [
  // ── existing rules ────────────────────────────────────────────────────
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
        rule: "error-not-diagnosed",
        verdict: "flag",
        reason: "Tool returned an error signal — diagnose root cause before retrying",
      };
    },
  },
  {
    name: "empty-output",
    test: (_tool, output) => {
      if (output.trim().length > 0) return null;
      return {
        rule: "empty-output",
        verdict: "flag",
        reason: "Tool returned empty output — confirm action executed",
      };
    },
  },
  {
    name: "large-output-truncation",
    test: (_tool, output) => {
      if (output.length <= 8000) return null;
      return {
        rule: "large-output-truncation",
        verdict: "flag",
        reason: `Output is ${output.length} chars — likely truncated`,
      };
    },
  },
  {
    name: "bash-destructive",
    test: (tool, _output, args) => {
      if (tool !== "bash") return null;
      const cmd = getArg(args, "command");
      const patterns = [/\brm\s+-rf\b/, /\bdrop\s+table\b/i, /\btruncate\b/i, /\bformat\b/, /\bmkfs\b/];
      for (const p of patterns) {
        if (p.test(cmd)) {
          return {
            rule: "bash-destructive",
            verdict: "flag",
            reason: `Destructive bash pattern: ${p}`,
          };
        }
      }
      return null;
    },
  },

  // ── FCRA + GLBA + HIPAA: expanded PII/PHI/NPI detection (blocked) ─────
  {
    name: "pii-exposure",
    test: (_tool, output) => {
      const patterns: [RegExp, string][] = [
        [/\b\d{3}-\d{2}-\d{4}\b/, "SSN pattern"],
        [/\b(?:\d{4}[- ]){3}\d{4}\b/, "credit card pattern"],
        [/\b\d{3}-\d{3}-\d{4}\b/, "phone number pattern"],
        [/\b[A-Z]{2}\d{6,9}\b/, "passport/ID pattern"],
        // NPI (GLBA): account number heuristic — 8–17 digit string not a phone/SSN
        [/\baccount[\s_-]?(?:number|num|#|no)?[\s:]+\d{8,17}\b/i, "account number (NPI)"],
        // PHI (HIPAA): diagnosis codes
        [/\b[A-TV-Z][0-9][0-9A-Z]\.[0-9A-Z]{1,4}\b/, "ICD-10 diagnosis code (PHI)"],
        // PHI: drug/treatment context with name
        [/\b(?:prescribed|diagnosis|treatment|medication)\b.{0,60}\b[A-Z][a-z]{2,}\s[A-Z][a-z]{2,}\b/, "PHI — name + clinical context"],
      ];
      for (const [pattern, label] of patterns) {
        if (pattern.test(output)) {
          return {
            rule: "pii-exposure",
            verdict: "blocked",
            reason: `Sensitive data pattern detected: ${label} — output redacted (FCRA §607, GLBA §501, HIPAA §164.502)`,
          };
        }
      }
      return null;
    },
  },

  // ── FCRA §615(a): adverse action missing required notices (blocked) ───
  {
    name: "fcra-adverse-action",
    test: (_tool, output) => {
      const adverseKeywords = /\b(?:adverse action|denied|declined|rejected)\b/i;
      if (!adverseKeywords.test(output)) return null;
      const hasNotice =
        /right to (?:a free copy|dispute|obtain)/i.test(output) ||
        /consumer reporting agency/i.test(output) ||
        /FCRA/i.test(output);
      if (hasNotice) return null;
      return {
        rule: "fcra-adverse-action",
        verdict: "blocked",
        reason:
          "Adverse action language detected without required FCRA §615(a) notices " +
          "(CRA name/address, right-to-copy, right-to-dispute). Refusing to surface.",
      };
    },
  },

  // ── FCRA Retention + ISO 27001 A.8.3: durable write without justification (blocked) ──
  {
    name: "durable-write-gate",
    test: (tool, output, args) => {
      // Tools that write to durable stores
      const durableWriteTools = [
        "write_file", "edit_file", "create_file",
        "database_write", "db_insert", "db_update", "record_update",
        "bash",  // catches: tee, >, >>, dd, cp to sensitive paths
      ];
      const isDurableWrite = durableWriteTools.includes(tool);

      // Also catch bash commands that write
      let writeViaShell = false;
      if (tool === "bash") {
        const cmd = getArg(args, "command");
        writeViaShell = /\btee\b|>>|>\s*\w|INSERT\s+INTO|UPDATE\s+\w|CREATE\s+TABLE/i.test(cmd);
        if (!writeViaShell) return null;  // bash but not a write — skip
      } else if (!isDurableWrite) {
        return null;
      }

      // Model gets to pass by supplying justification in args
      const justification = getArg(args, "justification");
      const regulatoryBasis = getArg(args, "regulatory_basis");

      if (justification.length >= 20 && regulatoryBasis.length >= 5) {
        // Justification provided — log as flag, allow through
        return {
          rule: "durable-write-gate",
          verdict: "flag",
          reason: `Durable write allowed with justification: "${justification.slice(0, 80)}" [basis: ${regulatoryBasis}]`,
        };
      }

      return {
        rule: "durable-write-gate",
        verdict: "blocked",
        reason:
          "Durable write blocked: no regulatory justification provided. " +
          "To proceed, supply args.justification (≥20 chars) and args.regulatory_basis " +
          "citing the applicable exemption (FCRA Retention, ISO 27001 A.8.3, etc.).",
      };
    },
  },

  // ── ISO 27001 A.8.24: deprecated cryptography (blocked) ──────────────
  {
    name: "deprecated-crypto",
    test: (_tool, output) => {
      const deprecated = [
        [/\bMD5\b/, "MD5"],
        [/\bSHA-?1\b/, "SHA-1"],
        [/\b3?DES\b/, "DES/3DES"],
        [/\bRC4\b/, "RC4"],
        [/\bSSLv[23]\b/i, "SSLv2/3"],
        [/\bTLS\s*1\.[01]\b/, "TLS 1.0/1.1"],
      ] as [RegExp, string][];
      for (const [pattern, name] of deprecated) {
        if (pattern.test(output)) {
          return {
            rule: "deprecated-crypto",
            verdict: "blocked",
            reason: `Deprecated cryptographic algorithm detected: ${name} (ISO 27001 A.8.24). Refusing to propagate.`,
          };
        }
      }
      return null;
    },
  },

  // ── SOC 2 CC8.1: change event without impact analysis (flag) ─────────
  {
    name: "soc-change-event",
    test: (_tool, output) => {
      const changeKeywords = /\b(?:modif(?:y|ied|ication)|replac(?:e|ed)|delet(?:e|ed)|drop(?:ped)?|migrat(?:e|ed)|upgrad(?:e|ed)|refactor(?:ed)?)\b/i;
      if (!changeKeywords.test(output)) return null;
      const hasImpact =
        /\b(?:blast radius|impact|affect(?:s|ed)?|downstream|dependent|rollback|revert)\b/i.test(output);
      if (hasImpact) return null;
      return {
        rule: "soc-change-event",
        verdict: "flag",
        reason:
          "Change event detected without impact analysis (SOC 2 CC8.1). " +
          "Surface blast radius and rollback plan before proceeding.",
      };
    },
  },

  // ── SOC 2 CC7.2: consecutive tool failures = incident (flag) ─────────
  {
    name: "soc-incident-pattern",
    test: (_tool, output) => {
      const lower = output.toLowerCase();
      // Two or more error signals in one output = escalate
      const errorCount = (lower.match(/\b(?:error|exception|failed|failure|traceback)\b/g) || []).length;
      if (errorCount < 2) return null;
      return {
        rule: "soc-incident-pattern",
        verdict: "flag",
        reason: `Multiple error signals (${errorCount}) in single output — potential incident (SOC 2 CC7.2). Escalate rather than retry.`,
      };
    },
  },

  // ── ISO 27001 A.8.28 / OWASP: hardcoded credentials (blocked) ────────
  {
    name: "hardcoded-credentials",
    test: (_tool, output) => {
      const patterns: [RegExp, string][] = [
        [/(?:password|passwd|pwd)\s*[:=]\s*['"]?\S{4,}/i, "hardcoded password"],
        [/(?:api_?key|apikey|secret_?key)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}/i, "hardcoded API key"],
        [/(?:aws_?access_?key_?id)\s*[:=]\s*['"]?[A-Z0-9]{16,}/i, "AWS access key"],
        [/AKIA[0-9A-Z]{16}/, "AWS key ID pattern"],
        [/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, "private key in output"],
      ];
      for (const [pattern, label] of patterns) {
        if (pattern.test(output)) {
          return {
            rule: "hardcoded-credentials",
            verdict: "blocked",
            reason: `${label} detected in output (ISO 27001 A.8.28, OWASP A02). Refusing to propagate.`,
          };
        }
      }
      return null;
    },
  },
];

// ── main export ────────────────────────────────────────────────────────────

export function validateToolOutput(
  tool: string,
  output: string | null | undefined,
  args: unknown
): ValidationResult {
  const safeOutput = output ?? "";
  const findings: Finding[] = [];

  for (const rule of RULES) {
    const result = rule.test(tool, safeOutput, args);
    if (result) findings.push(result);
  }

  if (findings.length === 0) return { verdict: "pass" };

  const verdict = worstVerdict(findings);
  const blocked = findings.filter((f) => f.verdict === "blocked");
  const flags = findings.filter((f) => f.verdict === "flag");

  const annotationParts: string[] = [];
  if (blocked.length > 0) {
    annotationParts.push(
      `[VERIFIER:BLOCKED] ${blocked.length} rule(s) blocked this output:\n` +
        blocked.map((f) => `  • [${f.rule}] ${f.reason}`).join("\n")
    );
  }
  if (flags.length > 0) {
    annotationParts.push(
      `[VERIFIER:FLAG] ${flags.length} finding(s) require attention:\n` +
        flags.map((f) => `  • [${f.rule}] ${f.reason}`).join("\n")
    );
  }

  return {
    verdict,
    reason: findings.map((f) => f.reason).join("; "),
    annotation: annotationParts.join("\n\n"),
    findings,
  };
}
