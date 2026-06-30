import { track } from "@vercel/analytics";

const STORAGE_KEY = "latte:tool-usage:v1";

function readUsage() {
  if (typeof window === "undefined") {
    return { total: 0, byTool: {} };
  }

  try {
    const stored = JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "{}");
    return {
      total: Number(stored.total) || 0,
      byTool:
        stored.byTool && typeof stored.byTool === "object" ? stored.byTool : {},
    };
  } catch {
    return { total: 0, byTool: {} };
  }
}

export function getLocalUsage() {
  return readUsage();
}

export function recordToolUsage(toolId, action) {
  const current = readUsage();
  const next = {
    total: current.total + 1,
    byTool: {
      ...current.byTool,
      [toolId]: (Number(current.byTool[toolId]) || 0) + 1,
    },
  };

  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));

  track("tool_used", {
    tool: toolId,
    action,
  });

  if (import.meta.env.PROD) {
    void fetch("/api/usage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool: toolId, action }),
      keepalive: true,
    }).catch(() => {});
  }

  return next;
}
