# Known opencode Bugs

## 1. `opencode run` default formatter hangs on local model text responses

**Severity:** High  
**Affected:** `opencode run` headless mode with local (ollama) models  
**Version:** 1.4.3

### Symptom
`opencode run "message" --model ollama/qwen2.5:latest` hangs with no output when
the model produces a plain text response (no tool calls).

### Root cause
The default formatter in opencode's `run` subcommand waits for a TUI session-end
event that local models don't reliably emit in the same way hosted APIs do.
The model does respond correctly — events are emitted internally — but the formatter
never flushes them to stdout.

### Evidence
Running with `--format json` shows the response arrives correctly:
```
{"type":"text","text":"The answer to 2+2 is 4.",...}
{"type":"step_finish","reason":"stop",...}
```

### Workaround
Use `--format json` and parse the event stream:
```bash
opencode run "message" --model ollama/qwen2.5:latest --format json | \
  python3 -c "
import sys, json
for line in sys.stdin:
    ev = json.loads(line.strip())
    if ev.get('type') == 'text':
        print(ev['part']['text'])
  "
```

### Fix location (for fork)
The formatter is in the opencode binary's `run` command output handler.
Look for the session-end/completion signal logic in the `run` subcommand.
The fix is to flush and exit when `step_finish` with `reason: "stop"` is received,
regardless of whether a subsequent session-level done signal arrives.

---

## 2. Tool count limit (OpenAI: 128 tools max)

**Severity:** Medium  
**Affected:** Any session routing through OpenAI or OpenAI-compatible providers  

### Symptom
```
Error: [OpenAI] Invalid 'tools': array too long. Expected max 128, got 179.
```

### Root cause
opencode loads all MCP server tools into every request unconditionally.
With 12 MCP servers active, total tool count exceeds OpenAI's 128-tool limit.

### Workaround
Use `"enabled": false` on high-tool-count MCP servers in `opencode.jsonc`.

### Fix location (for fork)
Tool injection logic before the LLM call. The fix is dynamic tool selection:
at session start, select ≤N tools relevant to the declared task context rather
than injecting all tools unconditionally.
