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

type Asset = {
  id: string;
  display_name: string;
  asset_type: string;
  criticality: string;
  status: string;
  network_zone?: string | null;
  protected_roles: string[];
};

type Candidate = {
  id: string;
  observation_id: string;
  candidate_asset_id?: string | null;
  score: number;
  reasons: string[];
  status: string;
  resolution?: string | null;
};

function App() {
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      const [readyResponse, principalResponse, assetsResponse, candidatesResponse] =
        await Promise.all([
          fetch("/health/ready"),
          fetch("/api/v1/whoami"),
          fetch("/api/v1/assets"),
          fetch("/api/v1/reconciliation/candidates"),
        ]);
      const readyBody = (await readyResponse.json()) as Readiness;
      for (const response of [principalResponse, assetsResponse, candidatesResponse]) {
        if (!response.ok) {
          throw new Error(`control-plane request failed: ${response.status}`);
        }
      }
      setReadiness(readyBody);
      setPrincipal((await principalResponse.json()) as Principal);
      setAssets((await assetsResponse.json()) as Asset[]);
      setCandidates((await candidatesResponse.json()) as Candidate[]);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Control plane unavailable");
    }
  }

  async function resolveCandidate(candidate: Candidate, decision: "attach" | "new_asset" | "reject") {
    try {
      const response = await fetch(`/api/v1/reconciliation/candidates/${candidate.id}/resolve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision }),
      });
      if (!response.ok) {
        const body = (await response.json()) as { detail?: string };
        throw new Error(body.detail ?? `resolution failed: ${response.status}`);
      }
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Resolution failed");
    }
  }

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 10_000);
    return () => window.clearInterval(timer);
  }, []);

  const openCandidates = candidates.filter(
    (candidate) => candidate.status === "pending" || candidate.status === "conflict",
  );

  return (
    <main>
      <header>
        <div>
          <p className="eyebrow">AUTONOMOUS INFRASTRUCTURE OPERATIONS</p>
          <h1>Agentic Network Management</h1>
          <p className="subtitle">
            Discover and reconcile network state before any automation receives write authority.
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

      <section>
        <div className="section-heading">
          <div>
            <p className="eyebrow">CANONICAL INVENTORY</p>
            <h2>{assets.length} reconciled assets</h2>
          </div>
          <span className={`pill ${openCandidates.length > 0 ? "degraded" : "ok"}`}>
            {openCandidates.length} reviews
          </span>
        </div>
        <div className="grid inventory-grid">
          {assets.slice(0, 12).map((asset) => (
            <article key={asset.id} className="card asset-card">
              <div className="card-title">
                <h3>{asset.display_name}</h3>
                <span className="pill ok">{asset.status}</span>
              </div>
              <p>{asset.asset_type} · {asset.criticality}</p>
              <p>Zone: {asset.network_zone ?? "unassigned"}</p>
              {asset.protected_roles.length > 0 && (
                <p className="protected">Protected: {asset.protected_roles.join(", ")}</p>
              )}
            </article>
          ))}
          {assets.length === 0 && <article className="card"><p>No assets discovered yet.</p></article>}
        </div>
      </section>

      <section>
        <div className="section-heading">
          <div>
            <p className="eyebrow">IDENTITY REVIEW</p>
            <h2>Reconciliation conflicts</h2>
          </div>
        </div>
        <div className="review-list">
          {openCandidates.map((candidate) => (
            <article key={candidate.id} className="card review-card">
              <div>
                <div className="card-title">
                  <h3>Observation {candidate.observation_id.slice(0, 8)}</h3>
                  <span className={`pill ${candidate.status === "conflict" ? "down" : "degraded"}`}>
                    {candidate.status}
                  </span>
                </div>
                <p>
                  Candidate {candidate.candidate_asset_id?.slice(0, 8) ?? "new asset"} · score{" "}
                  {candidate.score.toFixed(2)}
                </p>
                <p>{candidate.reasons.join(" · ")}</p>
              </div>
              <div className="actions">
                {candidate.candidate_asset_id && (
                  <button onClick={() => void resolveCandidate(candidate, "attach")}>Attach</button>
                )}
                <button onClick={() => void resolveCandidate(candidate, "new_asset")}>Keep separate</button>
                <button onClick={() => void resolveCandidate(candidate, "reject")}>Reject</button>
              </div>
            </article>
          ))}
          {openCandidates.length === 0 && (
            <article className="card"><p>No identity conflicts require operator review.</p></article>
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
        Phase 2 discovery is read-only. Canonical identity is owned by reconciliation, not by NetBox,
        LibreNMS, IP address, or an AI model.
      </footer>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
