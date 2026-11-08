import type { Inventory } from "./types";

export function parseInventory(raw: string): Inventory {
  const data: unknown = JSON.parse(raw);
  if (!isInventory(data)) {
    throw new Error(
      "File is JSON but not a shadowmcp inventory. Re-export with: shadowmcp scan --json --out inventory.json",
    );
  }
  return data;
}

function isInventory(value: unknown): value is Inventory {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.schema_version === "string" &&
    typeof v.tool_version === "string" &&
    typeof v.scanned_at === "string" &&
    Array.isArray(v.servers) &&
    Array.isArray(v.errors) &&
    !!v.coverage &&
    typeof v.coverage === "object" &&
    !!v.host &&
    typeof v.host === "object"
  );
}