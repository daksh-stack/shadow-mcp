import { useState } from "react";
import { InventoryView } from "./components/InventoryView";
import { parseInventory } from "./inventory/parse";
import type { Inventory } from "./inventory/types";

export default function App() {
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function onFile(file: File | undefined) {
    setError(null);
    if (!file) return;
    try {
      const text = await file.text();
      setInventory(parseInventory(text));
    } catch (err) {
      setInventory(null);
      setError(err instanceof Error ? err.message : "Could not read that file.");
    }
  }

  return (
    <main>
      <div className="border-b border-stone-800 px-6 py-4">
        <label className="text-sm">
          Open inventory JSON{" "}
          <input
            className="ml-2 text-sm"
            type="file"
            accept="application/json,.json"
            onChange={(e) => void onFile(e.target.files?.[0])}
          />
        </label>
        {error && <p className="mt-2 text-sm text-red-300">{error}</p>}
      </div>
      {!inventory && !error && (
        <p className="px-6 py-10 text-sm text-stone-400">
          Produce a file on the machine you want to inspect:
          <code className="ml-2 text-stone-200">
            shadowmcp scan --json --out inventory.json
          </code>
        </p>
      )}
      {inventory && <InventoryView inventory={inventory} />}
    </main>
  );
}