/**
 * Ollama provider — dynamically registers all locally available ollama models
 * into opencode by querying the OpenAI-compat /v1/models endpoint.
 */
import type { ProviderHook } from "@opencode-ai/plugin";
import type { Model } from "@opencode-ai/sdk/v2";

const OLLAMA_BASE = "http://localhost:11434/v1";

type OllamaModelEntry = { id: string };

async function fetchOllamaModels(): Promise<OllamaModelEntry[]> {
  try {
    const res = await fetch(`${OLLAMA_BASE}/models`, {
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) return [];
    const json = (await res.json()) as { data: OllamaModelEntry[] };
    return json.data ?? [];
  } catch {
    return [];
  }
}

function makeModel(id: string): Model {
  return {
    id,
    providerID: "ollama",
    api: {
      id: id,
      url: OLLAMA_BASE,
      npm: "@ai-sdk/openai-compatible",
    },
    name: id,
    capabilities: {
      temperature: true,
      reasoning: false,
      attachment: false,
      toolcall: true,
      input: { text: true, audio: false, image: false, video: false, pdf: false },
      output: { text: true, audio: false, image: false, video: false, pdf: false },
      interleaved: false,
    },
    cost: {
      input: 0,
      output: 0,
      cache: { read: 0, write: 0 },
    },
    limit: {
      context: 32768,
      output: 4096,
    },
    status: "active",
    options: {},
    headers: {},
    release_date: "2024-01-01",
  };
}

export const ollamaProviderHook: ProviderHook = {
  id: "ollama",
  models: async () => {
    const entries = await fetchOllamaModels();
    const result: Record<string, Model> = {};
    for (const entry of entries) {
      result[entry.id] = makeModel(entry.id);
    }
    return result;
  },
};
