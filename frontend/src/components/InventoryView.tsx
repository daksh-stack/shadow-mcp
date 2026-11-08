import { useMemo, useState } from "react";
import type { Inventory, ServerRecord, Severity } from "../inventory/types";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function InventoryView({ inventory }: { inventory: Inventory }) {
  const [client, setClient] = useState<string>("all");
  const [severity, setSeverity] = useState<string>("all");
  const [selectedId, setSelectedId] = useState<string | null>(inventory.servers[0]?.id ?? null);

  const clients = useMemo(
    () => [...new Set(inventory.servers.map((s) => s.client))].sort(),
    [inventory.servers],
  );

  const visible = inventory.servers.filter((s) => {
    if (client !== "all" && s.client !== client) return false;
    if (severity === "all") return true;
    return s.risk_flags.some((f) => f.severity === severity);
  });

  const selected = visible.find((s) => s.id === selectedId) ?? visible[0] ?? null;

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <header className="mb-6">
        <p className="text-xs uppercase tracking-widest text-stone-500">shadowmcp inventory</p>
        <h1 className="text-2xl font-semibold">{inventory.host.hostname}</h1>
        <p className="text-sm text-stone-400">
          {inventory.tool_version} · schema {inventory.schema_version} · {inventory.scanned_at} ·{" "}
          {inventory.host.os}
        </p>
      </header>

      <section className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Servers" value={String(inventory.servers.length)} />
        <Stat label="Shown" value={String(visible.length)} />
        <Stat label="Parse errors" value={String(inventory.errors.length)} />
        <Stat
          label="Introspect"
          value={inventory.coverage.introspect_enabled ? "on" : "off"}
        />
      </section>

      <div className="mb-4 flex flex-wrap gap-2">
        <Select
          label="Client"
          value={client}
          onChange={setClient}
          options={["all", ...clients]}
        />
        <Select
          label="Flag"
          value={severity}
          onChange={setSeverity}
          options={["all", ...SEVERITY_ORDER]}
        />
      </div>

      <div className="grid gap-4 md:grid-cols-[320px_1fr]">
        <ul className="space-y-2">
          {visible.length === 0 && (
            <li className="rounded border border-stone-800 p-3 text-sm text-stone-400">
              No servers match these filters.
              {inventory.servers.length === 0 && " This scan found no configured MCP servers."}
            </li>
          )}
          {visible.map((s) => (
            <li key={s.id}>
              <button
                type="button"
                onClick={() => setSelectedId(s.id)}
                className={`w-full rounded border px-3 py-2 text-left ${
                  selected?.id === s.id
                    ? "border-stone-400 bg-stone-900"
                    : "border-stone-800 hover:border-stone-600"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium">{s.name}</span>
                  <span className="text-xs text-stone-500">{s.transport}</span>
                </div>
                <div className="text-xs text-stone-500">{s.client}</div>
              </button>
            </li>
          ))}
        </ul>
        <div>{selected ? <ServerDetail server={selected} /> : null}</div>
      </div>

      {inventory.errors.length > 0 && (
        <section className="mt-8">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-stone-400">
            Scan errors
          </h2>
          <ul className="space-y-1 text-sm">
            {inventory.errors.map((e, i) => (
              <li key={`${e.code}-${i}`} className="text-amber-200">
                {e.code} {e.source ?? ""} — {e.message}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="mt-8">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-stone-400">
          What this scan did not do
        </h2>
        <ul className="list-disc space-y-1 pl-5 text-sm text-stone-400">
          {inventory.coverage.limitations.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
        <p className="mt-3 text-xs text-stone-500">
          Checked {inventory.coverage.config_paths_checked.length} paths, found{" "}
          {inventory.coverage.config_paths_found.length}.
        </p>
      </section>
    </div>
  );
}

function ServerDetail({ server }: { server: ServerRecord }) {
  const cmd = [server.command, ...server.args].filter(Boolean).join(" ");
  return (
    <article className="rounded border border-stone-800 p-4">
      <h2 className="text-lg font-semibold">{server.name}</h2>
      <p className="break-all text-xs text-stone-500">{server.config_path}</p>
      <dl className="mt-4 space-y-2 text-sm">
        <Row k="Client" v={server.client} />
        <Row k="Transport" v={server.transport} />
        <Row k="Command" v={cmd || "—"} />
        <Row k="URL" v={server.url ?? "—"} />
        <Row k="Env keys" v={server.env_keys.join(", ") || "—"} />
        <Row
          k="Listen"
          v={
            server.listen
              ? `${server.listen.listening ? "listening" : "not listening"} ${server.listen.host}:${server.listen.port}`
              : "not checked"
          }
        />
      </dl>

      <h3 className="mt-5 text-xs uppercase tracking-wide text-stone-500">Processes</h3>
      {server.processes.length === 0 ? (
        <p className="text-sm text-stone-400">No correlated process.</p>
      ) : (
        <ul className="mt-2 space-y-2 text-sm">
          {server.processes.map((p) => (
            <li key={p.pid} className="rounded bg-stone-900 p-2">
              <div>
                pid {p.pid} · {p.name} · confidence {p.confidence}
              </div>
              <div className="text-stone-400">{p.reason}</div>
              <div className="break-all text-xs text-stone-500">{p.cmdline.join(" ")}</div>
            </li>
          ))}
        </ul>
      )}

      <h3 className="mt-5 text-xs uppercase tracking-wide text-stone-500">Risk flags</h3>
      {server.risk_flags.length === 0 ? (
        <p className="text-sm text-stone-400">No rules fired. That is not a clean bill of health.</p>
      ) : (
        <ul className="mt-2 space-y-2">
          {server.risk_flags.map((f) => (
            <li key={f.rule_id} className="rounded bg-stone-900 p-2 text-sm">
              <div className="font-medium">
                [{f.severity}] {f.rule_id}
              </div>
              <div>{f.title}</div>
              <div className="text-stone-400">{f.explanation}</div>
            </li>
          ))}
        </ul>
      )}

      {server.capabilities && (
        <>
          <h3 className="mt-5 text-xs uppercase tracking-wide text-stone-500">Declared tools</h3>
          {server.capabilities.ok ? (
            <ul className="mt-2 text-sm">
              {server.capabilities.tools.length === 0 && <li>None declared.</li>}
              {server.capabilities.tools.map((t) => (
                <li key={t.name}>
                  <span className="font-medium">{t.name}</span>
                  {t.description ? ` — ${t.description}` : ""}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-amber-200">{server.capabilities.error}</p>
          )}
        </>
      )}
    </article>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-stone-800 px-3 py-2">
      <div className="text-xs text-stone-500">{label}</div>
      <div className="text-lg">{value}</div>
    </div>
  );
}

function Select({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: string[];
}) {
  return (
    <label className="text-sm text-stone-400">
      {label}{" "}
      <select
        className="ml-1 rounded border border-stone-700 bg-stone-950 px-2 py-1 text-stone-100"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="grid grid-cols-[110px_1fr] gap-2">
      <dt className="text-stone-500">{k}</dt>
      <dd className="break-all">{v}</dd>
    </div>
  );
}