import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ollamaProviderHook } from "../ollama-provider.js";

const MOCK_MODELS = [
  { id: "qwen2.5:latest" },
  { id: "llama3.2:latest" },
  { id: "braille-fast:latest" },
];

function mockFetch(models: typeof MOCK_MODELS | null, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status === 200,
    status,
    json: async () => ({ data: models ?? [] }),
  });
}

describe("ollamaProviderHook", () => {
  it("has id 'ollama'", () => {
    expect(ollamaProviderHook.id).toBe("ollama");
  });

  it("has a models function", () => {
    expect(typeof ollamaProviderHook.models).toBe("function");
  });
});

describe("ollamaProviderHook.models", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetch(MOCK_MODELS));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns a record keyed by model id", async () => {
    const result = await ollamaProviderHook.models!({} as any, {} as any);
    expect(Object.keys(result)).toEqual(MOCK_MODELS.map((m) => m.id));
  });

  it("each model has providerID 'ollama'", async () => {
    const result = await ollamaProviderHook.models!({} as any, {} as any);
    for (const model of Object.values(result)) {
      expect(model.providerID).toBe("ollama");
    }
  });

  it("each model uses @ai-sdk/openai-compatible npm", async () => {
    const result = await ollamaProviderHook.models!({} as any, {} as any);
    for (const model of Object.values(result)) {
      expect(model.api.npm).toBe("@ai-sdk/openai-compatible");
    }
  });

  it("each model has toolcall capability enabled", async () => {
    const result = await ollamaProviderHook.models!({} as any, {} as any);
    for (const model of Object.values(result)) {
      expect(model.capabilities.toolcall).toBe(true);
    }
  });

  it("each model has zero cost", async () => {
    const result = await ollamaProviderHook.models!({} as any, {} as any);
    for (const model of Object.values(result)) {
      expect(model.cost.input).toBe(0);
      expect(model.cost.output).toBe(0);
    }
  });

  it("each model has status 'active'", async () => {
    const result = await ollamaProviderHook.models!({} as any, {} as any);
    for (const model of Object.values(result)) {
      expect(model.status).toBe("active");
    }
  });

  it("returns empty record when ollama is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("connection refused"))
    );
    const result = await ollamaProviderHook.models!({} as any, {} as any);
    expect(Object.keys(result)).toHaveLength(0);
  });

  it("returns empty record when response is not ok", async () => {
    vi.stubGlobal("fetch", mockFetch(null, 500));
    const result = await ollamaProviderHook.models!({} as any, {} as any);
    expect(Object.keys(result)).toHaveLength(0);
  });

  it("model id matches the key", async () => {
    const result = await ollamaProviderHook.models!({} as any, {} as any);
    for (const [key, model] of Object.entries(result)) {
      expect(model.id).toBe(key);
    }
  });
});
