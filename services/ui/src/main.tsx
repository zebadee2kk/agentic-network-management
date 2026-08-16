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

type Incident = {
  id: string;
  title: string;
  state: string;
  severity: number;
  confidence: number;
  summary: string;
  last_activity_at: string;
};

type SecurityEvent = {
  event_id: string;
  occurred_at: string;
  source: { connector: string; instance: string };
  type: string;
  severity: number;
  confidence: number;
  summary: string;
  trust: "untrusted_evidence";
};

type AIStatus = {
  enabled: boolean;
  configured_providers: number;
  architecture: "isolated_worker_via_model_relay";
};

type Investigation = {
  id: string;
  incident_id: string;
  provider_id: string;
  status: string;
  objective: string;
  summary?: string | null;
  confidence?: number | null;
  total_input_tokens: number;
  total_output_tokens: number;
  estimated_cost_usd: number;
  error_category?: string | null;
  created_at: string;
};

type Capability = {
  id: string;
  capability_id: string;
  version: string;
  description: string;
  risk: number;
  write: boolean;
  reversible: boolean;
  lifecycle: string;
  capability_digest: string;
  implementation_digest: string;
};

type ActionProposal = {
  id: string;
  revision: number;
  capability: string;
  capability_version: string;
  capability_digest: string;
  implementation_digest: string;
  target_asset_id: string;
  parameters: Record<string, unknown>;
  reason: string;
  incident_id: string;
  evidence_ids: string[];
  confidence: number;
  proposal_digest: string;
  state: string;
  policy_decision: string;
  policy_reasons: string[];
  required_roles: string[];
  policy_source: string;
  policy_version: string;
  created_at: string;
};

type Approval = {
  id: string;
  proposal_id: string;
  approver_id: string;
  approver_roles: string[];
  decision: string;
  valid: boolean;
  created_at: string;
};

type ApprovalQueueItem = {
  proposal: ActionProposal;
  approvals: Approval[];
};

function App() {
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [aiStatus, setAIStatus] = useState<AIStatus | null>(null);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [approvalQueue, setApprovalQueue] = useState<ApprovalQueueItem[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      const responses = await Promise.all([
        fetch("/health/ready"),
        fetch("/api/v1/whoami"),
        fetch("/api/v1/assets"),
        fetch("/api/v1/reconciliation/candidates"),
        fetch("/api/v1/incidents?limit=12"),
        fetch("/api/v1/events?limit=12"),
        fetch("/api/v1/ai/status"),
        fetch("/api/v1/investigations?limit=12"),
        fetch("/api/v1/capabilities"),
        fetch("/api/v1/action-proposals/approval-queue?limit=50"),
      ]);
      const [
        readyResponse,
        principalResponse,
        assetsResponse,
        candidatesResponse,
        incidentsResponse,
        eventsResponse,
        aiStatusResponse,
        investigationsResponse,
        capabilitiesResponse,
        approvalQueueResponse,
      ] = responses;
      const readyBody = (await readyResponse.json()) as Readiness;
      for (const response of responses.slice(1)) {
        if (!response.ok) {
          throw new Error(`control-plane request failed: ${response.status}`);
        }
      }
      setReadiness(readyBody);
      setPrincipal((await principalResponse.json()) as Principal);
      setAssets((await assetsResponse.json()) as Asset[]);
      setCandidates((await candidatesResponse.json()) as Candidate[]);
      setIncidents((await incidentsResponse.json()) as Incident[]);
      setEvents((await eventsResponse.json()) as SecurityEvent[]);
      setAIStatus((await aiStatusResponse.json()) as AIStatus);
      setInvestigations((await investigationsResponse.json()) as Investigation[]);
      setCapabilities((await capabilitiesResponse.json()) as Capability[]);
      setApprovalQueue((await approvalQueueResponse.json()) as ApprovalQueueItem[]);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Control plane unavailable");
    }
  }

  async function resolveCandidate(
    candidate: Candidate,
    decision: "attach" | "new_asset" | "reject",
  ) {
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

  async function decideProposal(proposal: ActionProposal, decision: "approve" | "reject") {
    try {
      const response = await fetch(`/api/v1/action-proposals/${proposal.id}/approvals`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision }),
      });
      if (!response.ok) {
        const body = (await response.json()) as { detail?: string };
        throw new Error(body.detail ?? `approval decision failed: ${response.status}`);
      }
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Approval decision failed");
    }
  }

  function principalCanApprove(proposal: ActionProposal): boolean {
    const roles = new Set(principal?.roles ?? []);
    return proposal.required_roles.every((requiredRole) => {
      if (requiredRole === "operator_approver") {
        return (
          roles.has("operator_approver") ||
          roles.has("security_approver") ||
          roles.has("platform_approver")
        );
      }
      if (requiredRole === "security_approver") {
        return roles.has("security_approver") || roles.has("platform_approver");
      }
      return roles.has(requiredRole);
    });
  }

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 10_000);
    return () => window.clearInterval(timer);
  }, []);

  const openCandidates = candidates.filter(
    (candidate) => candidate.status === "pending" || candidate.status === "conflict",
  );
  const openIncidents = incidents.filter(
    (incident) => incident.state !== "CLOSED" && incident.state !== "FALSE_POSITIVE",
  );

  return (
    <main>
      <header>
        <div>
          <p className="eyebrow">AUTONOMOUS INFRASTRUCTURE OPERATIONS</p>
          <h1>Agentic Network Management</h1>
          <p className="subtitle">
            Reconcile infrastructure state, normalize security evidence, investigate incidents and
            authorize typed remediation proposals without giving AI execution authority.
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
            <p className="eyebrow">SECURITY OPERATIONS</p>
            <h2>{openIncidents.length} open incidents</h2>
          </div>
          <span className={`pill ${openIncidents.length > 0 ? "degraded" : "ok"}`}>
            deterministic correlation
          </span>
        </div>
        <div className="review-list">
          {incidents.map((incident) => (
            <article key={incident.id} className="card review-card">
              <div>
                <div className="card-title">
                  <h3>{incident.title}</h3>
                  <span
                    className={`pill ${
                      incident.severity >= 8 ? "down" : incident.severity >= 5 ? "degraded" : "ok"
                    }`}
                  >
                    sev {incident.severity}
                  </span>
                </div>
                <p>{incident.state} · confidence {incident.confidence.toFixed(2)}</p>
                <p>{incident.summary}</p>
              </div>
            </article>
          ))}
          {incidents.length === 0 && (
            <article className="card"><p>No correlated incidents yet.</p></article>
          )}
        </div>
      </section>

      <section>
        <div className="section-heading">
          <div>
            <p className="eyebrow">POLICY-GATED AUTHORIZATION</p>
            <h2>{approvalQueue.length} proposals awaiting approval</h2>
          </div>
          <span className="pill degraded">no executor in Phase 5</span>
        </div>
        <div className="review-list">
          {approvalQueue.map(({ proposal, approvals }) => {
            const capability = capabilities.find(
              (item) =>
                item.capability_id === proposal.capability &&
                item.version === proposal.capability_version,
            );
            const mayApprove = principalCanApprove(proposal);
            return (
              <article key={proposal.id} className="card review-card">
                <div>
                  <div className="card-title">
                    <h3>{proposal.capability}</h3>
                    <span
                      className={`pill ${
                        (capability?.risk ?? 5) >= 4
                          ? "down"
                          : (capability?.risk ?? 5) >= 2
                            ? "degraded"
                            : "ok"
                      }`}
                    >
                      risk {capability?.risk ?? "?"}
                    </span>
                  </div>
                  <p>
                    Target {proposal.target_asset_id.slice(0, 8)} · incident{" "}
                    {proposal.incident_id.slice(0, 8)} · revision {proposal.revision}
                  </p>
                  <p>{proposal.reason}</p>
                  <p>
                    Policy: {proposal.policy_reasons.join(" · ")} · requires{" "}
                    {proposal.required_roles.join(", ") || "no human role"}
                  </p>
                  <p>
                    Policy {proposal.policy_version} · proposal {proposal.proposal_digest.slice(0, 12)}…
                    · implementation {proposal.implementation_digest.slice(0, 12)}…
                  </p>
                  <p className="protected">
                    AUTHORIZED means authorization state only. Phase 5 cannot execute this action.
                  </p>
                  {approvals.length > 0 && (
                    <p>{approvals.length} prior decision record(s) retained for audit.</p>
                  )}
                  {!mayApprove && (
                    <p className="protected">
                      Your current roles do not satisfy this proposal&apos;s approval requirement.
                    </p>
                  )}
                </div>
                <div className="actions">
                  <button disabled={!mayApprove} onClick={() => void decideProposal(proposal, "approve")}>
                    Approve
                  </button>
                  <button disabled={!mayApprove} onClick={() => void decideProposal(proposal, "reject")}>
                    Reject
                  </button>
                </div>
              </article>
            );
          })}
          {approvalQueue.length === 0 && (
            <article className="card">
              <p>No policy-gated proposals currently require a human decision.</p>
              <p className="protected">
                The capability catalogue contains {capabilities.length} enabled typed operations;
                none has an execution path in Phase 5.
              </p>
            </article>
          )}
        </div>
      </section>

      <section>
        <div className="section-heading">
          <div>
            <p className="eyebrow">READ-ONLY AI INVESTIGATION</p>
            <h2>{investigations.length} recent investigations</h2>
          </div>
          <span className={`pill ${aiStatus?.enabled ? "ok" : "degraded"}`}>
            {aiStatus?.enabled ? "AI enabled" : "AI disabled"}
          </span>
        </div>
        <div className="grid inventory-grid">
          <article className="card asset-card">
            <div className="card-title">
              <h3>Isolation boundary</h3>
              <span className="pill ok">read only</span>
            </div>
            <p>{aiStatus?.configured_providers ?? 0} configured providers</p>
            <p>Reasoning worker → internal model relay → provider</p>
            <p className="protected">No managed-network or secret access from ai-worker</p>
          </article>
          {investigations.slice(0, 11).map((investigation) => (
            <article key={investigation.id} className="card asset-card">
              <div className="card-title">
                <h3>{investigation.status}</h3>
                <span
                  className={`pill ${
                    investigation.status === "SUCCEEDED"
                      ? "ok"
                      : investigation.status === "FAILED"
                        ? "down"
                        : "degraded"
                  }`}
                >
                  {investigation.confidence == null
                    ? "pending"
                    : `confidence ${investigation.confidence.toFixed(2)}`}
                </span>
              </div>
              <p>Incident {investigation.incident_id.slice(0, 8)}</p>
              <p>{investigation.summary ?? investigation.objective}</p>
              <p>
                {investigation.total_input_tokens + investigation.total_output_tokens} tokens · $ 
                {investigation.estimated_cost_usd.toFixed(4)} configured estimate
              </p>
              {investigation.error_category && (
                <p className="protected">Failure: {investigation.error_category}</p>
              )}
            </article>
          ))}
        </div>
      </section>

      <section>
        <div className="section-heading">
          <div>
            <p className="eyebrow">UNTRUSTED EVIDENCE</p>
            <h2>Recent canonical events</h2>
          </div>
        </div>
        <div className="grid inventory-grid">
          {events.map((event) => (
            <article key={event.event_id} className="card asset-card">
              <div className="card-title">
                <h3>{event.source.connector}</h3>
                <span
                  className={`pill ${
                    event.severity >= 8 ? "down" : event.severity >= 5 ? "degraded" : "ok"
                  }`}
                >
                  sev {event.severity}
                </span>
              </div>
              <p>{event.type} · {event.source.instance}</p>
              <p>{event.summary}</p>
              <p className="protected">{event.trust}</p>
            </article>
          ))}
          {events.length === 0 && (
            <article className="card"><p>No security telemetry ingested yet.</p></article>
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
          {assets.length === 0 && (
            <article className="card"><p>No assets discovered yet.</p></article>
          )}
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
                  <span
                    className={`pill ${candidate.status === "conflict" ? "down" : "degraded"}`}
                  >
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
                <button onClick={() => void resolveCandidate(candidate, "new_asset")}>
                  Keep separate
                </button>
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
          Provider: <strong>{principal?.provider ?? "—"}</strong> · Roles:{" "}
          {principal?.roles.join(", ") ?? "—"}
        </p>
      </section>

      <footer>
        Phase 5 adds typed proposal and approval state only. OPA evaluates authorization and human
        decisions bind exact digests; there is no executor, infrastructure write worker or
        AI-controlled remediation path.
      </footer>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
