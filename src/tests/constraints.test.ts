import { describe, it, expect } from "vitest";
import {
  CONSTRAINT_SETS,
  DEFAULT_ACTIVE,
  getActiveConstraints,
} from "../constraints.js";

describe("CONSTRAINT_SETS", () => {
  it("contains all four expected sets", () => {
    const ids = CONSTRAINT_SETS.map((s) => s.id);
    expect(ids).toContain("tool-algebra");
    expect(ids).toContain("braille-bottleneck");
    expect(ids).toContain("compliance");
    expect(ids).toContain("verification");
  });

  it("every set has at least one rule", () => {
    for (const set of CONSTRAINT_SETS) {
      expect(set.rules.length).toBeGreaterThan(0);
    }
  });

  it("no rule is empty or whitespace-only", () => {
    for (const set of CONSTRAINT_SETS) {
      for (const rule of set.rules) {
        expect(rule.trim().length).toBeGreaterThan(0);
      }
    }
  });
});

describe("DEFAULT_ACTIVE", () => {
  it("includes all four constraint sets", () => {
    expect(DEFAULT_ACTIVE).toContain("tool-algebra");
    expect(DEFAULT_ACTIVE).toContain("braille-bottleneck");
    expect(DEFAULT_ACTIVE).toContain("compliance");
    expect(DEFAULT_ACTIVE).toContain("verification");
  });

  it("references only valid set IDs", () => {
    const validIds = CONSTRAINT_SETS.map((s) => s.id);
    for (const id of DEFAULT_ACTIVE) {
      expect(validIds).toContain(id);
    }
  });
});

describe("getActiveConstraints", () => {
  it("returns empty array for empty input", () => {
    expect(getActiveConstraints([])).toEqual([]);
  });

  it("returns empty array for unknown IDs", () => {
    expect(getActiveConstraints(["nonexistent"])).toEqual([]);
  });

  it("prefixes each rule with its set ID", () => {
    const rules = getActiveConstraints(["tool-algebra"]);
    for (const rule of rules) {
      expect(rule.startsWith("[tool-algebra]")).toBe(true);
    }
  });

  it("returns correct count for single set", () => {
    const set = CONSTRAINT_SETS.find((s) => s.id === "tool-algebra")!;
    const rules = getActiveConstraints(["tool-algebra"]);
    expect(rules.length).toBe(set.rules.length);
  });

  it("returns combined rules for multiple sets", () => {
    const ids = ["tool-algebra", "verification"];
    const expected = ids.reduce((sum, id) => {
      const set = CONSTRAINT_SETS.find((s) => s.id === id)!;
      return sum + set.rules.length;
    }, 0);
    expect(getActiveConstraints(ids).length).toBe(expected);
  });

  it("ALL active constraints returns rules for all four sets", () => {
    const all = getActiveConstraints(DEFAULT_ACTIVE);
    const total = CONSTRAINT_SETS.reduce((sum, s) => sum + s.rules.length, 0);
    expect(all.length).toBe(total);
  });

  it("braille-bottleneck rules mention specific tool names", () => {
    const rules = getActiveConstraints(["braille-bottleneck"]);
    const joined = rules.join(" ");
    expect(joined).toContain("braille-algebra");
    expect(joined).toContain("braille-turing");
    expect(joined).toContain("braille-speculative");
  });

  it("compliance rules cite regulatory references", () => {
    const rules = getActiveConstraints(["compliance"]);
    const joined = rules.join(" ");
    expect(joined).toMatch(/FCRA|GLBA|HIPAA/);
  });

  it("verification rules reference verify_claim and audit_log", () => {
    const rules = getActiveConstraints(["verification"]);
    const joined = rules.join(" ");
    expect(joined).toContain("verify_claim");
    expect(joined).toContain("audit_log");
  });
});
