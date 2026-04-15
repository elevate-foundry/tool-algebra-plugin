# opencode-verifier-plugin

An [opencode](https://opencode.ai) plugin implementing the **Tool Algebra** framework (Barrett 2025).

## What it does

- **System prompt injection** — every session gets a structured operating framework based on `A = (T, Σ, ℒ, E, δ, V, Γ, Log)`
- **Tool output interception** — validates all tool outputs before they re-enter LLM context (error detection, PII blocking, truncation warnings, destructive command flagging)
- **Audit log** — append-only JSONL at `~/.local/share/opencode/verifier-audit.jsonl`
- **`verify_claim` tool** — forces the LLM to cite observable evidence before declaring tasks complete
- **`audit_log` tool** — LLM can read its own decision history
- **Local ollama model discovery** — auto-registers all locally running ollama models via the provider hook

## Constraint sets

| ID | Description |
|---|---|
| `tool-algebra` | Bounded execution, type-signature discipline, sealed plans |
| `braille-bottleneck` | Braille/SCL MCP servers as constrained algebraic channel |
| `compliance` | FCRA / GLBA / HIPAA guardrails, PII taint propagation |
| `verification` | Closed-loop execution: planned → executed → verified |

## Install

```jsonc
// opencode.jsonc
{
  "plugin": ["/path/to/opencode-verifier-plugin/dist/index.js"],
  "provider": {
    "ollama": {
      "options": {
        "baseURL": "http://localhost:11434/v1",
        "apiKey": "ollama"
      }
    }
  }
}
```

## Dev

```bash
npm install
npm run build
npm test         # 62 tests
npm run test:watch
```

## Architecture

```
src/
  index.ts          — plugin entry, wires all hooks
  constraints.ts    — constraint registry + DEFAULT_ACTIVE
  tool-validator.ts — heuristic validation rules
  ollama-provider.ts — dynamic ollama model registration
  audit.ts          — append-only JSONL audit writer
  tests/
    constraints.test.ts
    tool-validator.test.ts
    ollama-provider.test.ts
    system-prompt.test.ts
```
