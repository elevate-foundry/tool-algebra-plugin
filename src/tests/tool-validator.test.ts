import { describe, it, expect } from "vitest";
import { validateToolOutput } from "../tool-validator.js";

describe("validateToolOutput — pass cases", () => {
  it("passes clean output", () => {
    const r = validateToolOutput("bash", "file written successfully", {});
    expect(r.verdict).toBe("pass");
  });

  it("passes on null output without throwing", () => {
    const r = validateToolOutput("bash", null, {});
    expect(r.verdict).toBe("flag"); // empty-output rule fires
    expect(r.reason).toMatch(/empty/i);
  });

  it("passes on undefined output without throwing", () => {
    const r = validateToolOutput("bash", undefined, {});
    expect(r.verdict).toBe("flag");
  });
});

describe("validateToolOutput — error-not-diagnosed", () => {
  it("flags output containing 'Error:'", () => {
    const r = validateToolOutput("bash", "Error: command not found", {});
    expect(r.verdict).toBe("flag");
    expect(r.reason).toMatch(/error/i);
    expect(r.annotation).toContain("[VERIFIER:FLAG]");
  });

  it("flags output containing 'Traceback'", () => {
    const r = validateToolOutput("python", "Traceback (most recent call last):", {});
    expect(r.verdict).toBe("flag");
  });

  it("flags output containing 'exitcode: 1'", () => {
    const r = validateToolOutput("bash", "exitcode: 1\nsome output", {});
    expect(r.verdict).toBe("flag");
  });

  it("does not flag 'Error' as part of a legitimate word", () => {
    const r = validateToolOutput("read_file", "No errors found in analysis.", {});
    expect(r.verdict).toBe("pass");
  });
});

describe("validateToolOutput — pii-exposure", () => {
  it("blocks SSN pattern", () => {
    const r = validateToolOutput("read_file", "SSN: 123-45-6789", {});
    expect(r.verdict).toBe("blocked");
    expect(r.reason).toMatch(/sensitive data|SSN/i);
    expect(r.annotation).toContain("[VERIFIER:BLOCKED]");
  });

  it("blocks credit card pattern", () => {
    const r = validateToolOutput("read_file", "Card: 4111 1111 1111 1111", {});
    expect(r.verdict).toBe("blocked");
  });

  it("blocks phone numbers (GLBA NPI expansion)", () => {
    // Phone numbers are now blocked under GLBA §501 NPI taint expansion
    const r = validateToolOutput("read_file", "Call: 555-867-5309", {});
    expect(r.verdict).toBe("blocked");
  });
});

describe("validateToolOutput — empty-output", () => {
  it("flags empty string", () => {
    const r = validateToolOutput("bash", "", {});
    expect(r.verdict).toBe("flag");
    expect(r.reason).toMatch(/empty/i);
  });

  it("flags whitespace-only output", () => {
    const r = validateToolOutput("bash", "   \n\t  ", {});
    expect(r.verdict).toBe("flag");
  });

  it("does not flag single character output", () => {
    const r = validateToolOutput("bash", "0", {});
    expect(r.verdict).toBe("pass");
  });
});

describe("validateToolOutput — large-output-truncation", () => {
  it("flags output over 8000 chars", () => {
    const big = "a".repeat(8001);
    const r = validateToolOutput("read_file", big, {});
    expect(r.verdict).toBe("flag");
    expect(r.reason).toMatch(/truncat/i);
  });

  it("passes output exactly at 8000 chars", () => {
    const edge = "a".repeat(8000);
    const r = validateToolOutput("read_file", edge, {});
    expect(r.verdict).toBe("pass");
  });
});

describe("validateToolOutput — bash-destructive", () => {
  it("flags rm -rf", () => {
    const r = validateToolOutput("bash", "done", { command: "rm -rf /tmp/test" });
    expect(r.verdict).toBe("flag");
    expect(r.reason).toMatch(/destructive/i);
  });

  it("flags DROP TABLE", () => {
    const r = validateToolOutput("bash", "done", { command: "DROP TABLE users;" });
    expect(r.verdict).toBe("flag");
  });

  it("does not flag non-bash tools for destructive commands", () => {
    const r = validateToolOutput("read_file", "done", { command: "rm -rf /tmp" });
    expect(r.verdict).toBe("pass");
  });

  it("does not flag safe bash commands", () => {
    const r = validateToolOutput("bash", "hello", { command: "echo hello" });
    expect(r.verdict).toBe("pass");
  });
});

describe("validateToolOutput — verdict priority", () => {
  it("blocked takes priority over flag (PII in large output)", () => {
    const big = "SSN: 123-45-6789 " + "a".repeat(8001);
    const r = validateToolOutput("read_file", big, {});
    expect(r.verdict).toBe("blocked");
  });

  it("accumulates multiple findings", () => {
    const r = validateToolOutput("read_file", "SSN: 123-45-6789 " + "a".repeat(8001), {});
    expect(r.findings?.length).toBeGreaterThanOrEqual(2);
  });
});

describe("validateToolOutput — durable-write-gate", () => {
  it("blocks write_file without justification", () => {
    const r = validateToolOutput("write_file", "ok", {});
    expect(r.verdict).toBe("blocked");
    expect(r.reason).toMatch(/justification/i);
  });

  it("allows write_file with valid justification and regulatory_basis", () => {
    const r = validateToolOutput("write_file", "ok", {
      justification: "Logging session data for audit trail per SOC 2 PI1.1",
      regulatory_basis: "SOC2-PI1.1",
    });
    expect(r.verdict).toBe("flag"); // allowed but logged
    expect(r.reason).toMatch(/justification/i);
  });

  it("blocks bash with redirect without justification", () => {
    const r = validateToolOutput("bash", "ok", { command: "echo data >> log.txt" });
    expect(r.verdict).toBe("blocked");
  });

  it("passes safe bash (no write)", () => {
    const r = validateToolOutput("bash", "hello", { command: "echo hello" });
    expect(r.verdict).toBe("pass");
  });
});

describe("validateToolOutput — deprecated-crypto", () => {
  it("blocks MD5 reference", () => {
    const r = validateToolOutput("bash", "hash = MD5(data)", {});
    expect(r.verdict).toBe("blocked");
    expect(r.reason).toMatch(/MD5/i);
  });

  it("blocks SHA-1 reference", () => {
    const r = validateToolOutput("bash", "using SHA1 for signing", {});
    expect(r.verdict).toBe("blocked");
  });

  it("passes SHA-256", () => {
    const r = validateToolOutput("bash", "using SHA-256 for integrity", {});
    expect(r.verdict).toBe("pass");
  });
});

describe("validateToolOutput — hardcoded-credentials", () => {
  it("blocks hardcoded password", () => {
    const r = validateToolOutput("read_file", "password = 'hunter2'", {});
    expect(r.verdict).toBe("blocked");
    expect(r.reason).toMatch(/password/i);
  });

  it("blocks AWS key ID pattern", () => {
    const r = validateToolOutput("bash", "AKIAIOSFODNN7EXAMPLE", {});
    expect(r.verdict).toBe("blocked");
  });

  it("passes output without credentials", () => {
    const r = validateToolOutput("bash", "Build succeeded in 2.3s", {});
    expect(r.verdict).toBe("pass");
  });
});
