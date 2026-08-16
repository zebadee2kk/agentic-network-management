import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

type Dependency = {
  status: "ok" | "degraded" | "down";
  detail?: string | null;
};

type Readiness = {
  ready: boolean;
  dependencies: Record<string, Dependency>;
};

type Principal = {
  subject: string;
  roles: string[];
  provider: string;
};

function App() {
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      const [readyResponse, principalResponse] = await Promise.all([
        fetch("/health/ready"),
        fetch("/api/v1/whoami"),
      ]);
      const readyBody = (await readyResponse.json()) as Readiness;
      if (!principalResponse.ok) {
        throw new Error(`identity request failed: ${principalResponse.status}`);
      }
      setReadiness(readyBody);
      setPrincipal((await principalResponse.json()) as Principal);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Control plane unavailable");
    }
  }

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 10_000);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <main>
      <header>
        <div>
          <p className="eyebrow">AUTONOMOUS INFRASTRUCTURE OPERATIONS</p>
          <h1>Agentic Network Management</h1>
          <p className="subtitle">
            Discover, observe, investigate and remediate through explicit policy boundaries.
          </p>
        </div>
        <div className={`state ${readiness?.ready ? "ok" : "down"}`}>
          <span className="dot" />
          {readiness?.ready ? "Control plane ready" : "Control plane degraded"}
        </div>
      </header>

      {error && <section className="alert">{error}</section>}

      <section>
        <div className="section-heading">
          <div>
            <p className="eyebrow">FOUNDATION</p>
            <h2>Control-plane health</h2>
          </div>
          <button onClick={() => void refresh()}>Refresh</button>
        </div>
        <div className="grid">
          {readiness ? (
            Object.entries(readiness.dependencies).map(([name, dep]) => (
              <article key={name} className="card">
                <div className="card-title">
                  <h3>{name}</h3>
                  <span className={`pill ${dep.status}`}>{dep.status}</span>
                </div>
                <p>{dep.detail ?? "Healthy and reachable."}</p>
              </article>
            ))
          ) : (
            <article className="card"><p>Loading dependency state…</p></article>
          )}
        </div>
      </section>

      <section className="identity">
        <p className="eyebrow">IDENTITY</p>
        <h2>{principal?.subject ?? "Unknown principal"}</h2>
        <p>
          Provider: <strong>{principal?.provider ?? "—"}</strong> · Roles: {principal?.roles.join(", ") ?? "—"}
        </p>
      </section>

      <footer>
        Phase 1 deliberately contains no managed-network execution path.
      </footer>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
