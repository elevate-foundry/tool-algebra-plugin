import { describe, it, expect } from "vitest";
import { getActiveConstraints, DEFAULT_ACTIVE, CONSTRAINT_SETS } from "../constraints.js";

/**
 * Tests for the system prompt injection — validates the rendered output
 * that actually lands in the LLM context window.
 */

function buildSystemPrompt(ids: string[]): string {
  const toolAlgebraRules = getActiveConstraints(["tool-algebra"]);
  const verificationRules = getActiveConstraints(["verification"]);
  const brailleRules = getActiveConstraints(["braille-bottleneck"]);
  const regulatoryIds = ["fcra", "glba", "hipaa", "iso27001", "soc"];
  const regulatoryRules = getActiveConstraints(regulatoryIds.filter((id) => ids.includes(id)));

  const sections: string[] = [
    "## Operating Framework: Tool Algebra (Barrett 2025)",
    "",
    "You are an agent operating under a formal bounded execution framework. Your tool use is governed by:",
    "",
    "  A = (T, Σ, ℒ, E, δ, V, Γ, Log)",
    "",
    "### Tool Execution Rules",
    ...toolAlgebraRules.map((r) => `- ${r.replace(/^\[tool-algebra\] /, "")}`),
    "",
    "### Verification Rules",
    ...verificationRules.map((r) => `- ${r.replace(/^\[verification\] /, "")}`),
  ];

  if (ids.includes("braille-bottleneck")) {
    sections.push("", "### Braille Tool Discipline");
    sections.push(...brailleRules.map((r) => `- ${r.replace(/^\[braille-bottleneck\] /, "")}`));
  }

  if (regulatoryRules.length > 0) {
    sections.push("", "### Regulatory Constraints");
    sections.push(...regulatoryRules.map((r) => `- ${r}`));
  }

  return sections.join("\n").trim();
}

describe("system prompt structure", () => {
  it("contains the Tool Algebra header", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    expect(prompt).toContain("Tool Algebra (Barrett 2025)");
  });

  it("contains the formal algebra definition", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    expect(prompt).toContain("A = (T, Σ, ℒ, E, δ, V, Γ, Log)");
  });

  it("contains Tool Execution Rules section", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    expect(prompt).toContain("### Tool Execution Rules");
  });

  it("contains Verification Rules section", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    expect(prompt).toContain("### Verification Rules");
  });

  it("includes braille section when braille-bottleneck active", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    expect(prompt).toContain("### Braille Tool Discipline");
  });

  it("includes regulatory section when fcra/glba/hipaa/iso27001/soc active", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    expect(prompt).toContain("### Regulatory Constraints");
  });

  it("does NOT include braille section when not in active set", () => {
    const prompt = buildSystemPrompt(["tool-algebra", "verification"]);
    expect(prompt).not.toContain("### Braille Tool Discipline");
  });

  it("does NOT include regulatory section when not in active set", () => {
    const prompt = buildSystemPrompt(["tool-algebra", "verification"]);
    expect(prompt).not.toContain("### Regulatory Constraints");
  });
});

describe("system prompt token budget", () => {
  it("full prompt fits within 24000 characters with all sets active", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    // 52 rules across 8 sets; ~3000 tokens — fits all model context windows
    expect(prompt.length).toBeLessThan(24000);
  });

  it("full prompt is non-trivially long (at least 500 chars)", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    expect(prompt.length).toBeGreaterThan(500);
  });
});

describe("system prompt content coverage", () => {
  it("mentions Γ (sealed plans)", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    expect(prompt).toContain("Γ");
  });

  it("mentions verify_claim tool explicitly", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    expect(prompt).toContain("verify_claim");
  });

  it("mentions audit_log tool explicitly", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    expect(prompt).toContain("audit_log");
  });

  it("mentions NPI or PHI guardrail from regulatory constraints", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    expect(prompt).toMatch(/NPI|PHI|PII|nonpublic personal/i);
  });

  it("contains Rule 110 reference in braille section", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    expect(prompt).toContain("Rule 110");
  });

  it("contains GF(2) reference in braille section", () => {
    const prompt = buildSystemPrompt(DEFAULT_ACTIVE);
    expect(prompt).toContain("GF(2)");
  });

  it("total rule count matches CONSTRAINT_SETS", () => {
    const totalRules = CONSTRAINT_SETS.reduce((sum, s) => sum + s.rules.length, 0);
    const allExtracted = getActiveConstraints(DEFAULT_ACTIVE);
    expect(allExtracted.length).toBe(totalRules);
  });
});
