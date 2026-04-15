/**
 * Audit log — append-only JSONL, one entry per intercepted event.
 * Written to ~/.local/share/opencode/verifier-audit.jsonl
 */
import { appendFileSync, mkdirSync } from "fs";
import { homedir } from "os";
import { join } from "path";

const AUDIT_DIR = join(homedir(), ".local", "share", "opencode");
const AUDIT_PATH = join(AUDIT_DIR, "verifier-audit.jsonl");

export type AuditEntry =
  | {
      type: "tool_intercepted";
      ts: string;
      sessionID: string;
      tool: string;
      callID: string;
      verdict: "pass" | "flag" | "blocked";
      reason?: string;
      findings?: { rule: string; verdict: string; reason: string }[];
      outputPreview: string;
    }
  | {
      type: "system_injected";
      ts: string;
      sessionID: string;
      constraints: string[];
    }
  | {
      type: "verify_called";
      ts: string;
      sessionID: string;
      claim: string;
      verdict: "verified" | "unverified" | "contradicted";
      reason: string;
    };

export function writeAudit(entry: AuditEntry): void {
  try {
    mkdirSync(AUDIT_DIR, { recursive: true });
    appendFileSync(AUDIT_PATH, JSON.stringify(entry) + "\n", "utf8");
  } catch {
    // never crash the plugin on audit failure
  }
}

export { AUDIT_PATH };
