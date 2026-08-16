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
  manifest: {
    execution?: {
      adapter?: string;
      implementation?: string;
    };
  };
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

type ExecutionControl = {
  enabled: boolean;
  reason: string;
  updated_at?: string | null;
};

type Execution = {
  id: string;
  proposal_id: string;
  binding_id?: string | null;
  rollback_of_execution_id?: string | null;
  idempotency_key: string;
  capability: string;
  capability_version: string;
  target_asset_id: string;
  proposal_digest: string;
  capability_digest: string;
  implementation_digest: string;
  policy_version: string;
  target_criticality: string;
  target_protected_roles: string[];
  state: string;
  pre_state: Record<string, unknown>;
  executor_result: Record<string, unknown>;
  verification_result: Record<string, unknown>;
  error_category?: string | null;
  error_detail?: string | null;
  queued_at: string;
  started_at?: string | null;
  executor_completed_at?: string | null;
  verified_at?: string | null;
  completed_at?: string | null;
};

const DISPATCH_ROLES = new Set([
  "platform_admin",
  "security_admin",
  "network_operator",
  "endpoint_operator",
]);

const ROLLBACK_ELIGIBLE_STATES = new Set([
  "SUCCEEDED",
  "VERIFICATION_FAILED",
  "AMBIGUOUS",
]);

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
  const [proposals, setProposals] = useState<ActionProposal[]>([]);
  const [executionControl, setExecutionControl] = useState<ExecutionControl | null>(null);
  const [executions, setExecutions] = useState<Execution[]>([]);
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
        fetch("/api/v1/action-proposals?limit=50"),
        fetch("/api/v1/execution-control"),
        fetch("/api/v1/executions?limit=50"),
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
        proposalsResponse,
        executionControlResponse,
        executionsResponse,
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
      setProposals((await proposalsResponse.json()) as ActionProposal[]);
      setExecutionControl((await executionControlResponse.json()) as ExecutionControl);
      setExecutions((await executionsResponse.json()) as Execution[]);
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

  async function setExecutionEnabled(enabled: boolean) {
    if (!principal?.roles.includes("platform_admin")) {
      setError("platform_admin role is required to change the execution kill switch");
      return;
    }
    const confirmation = enabled
      ? "Enable deterministic infrastructure execution? Only already-authorized typed capabilities can dispatch, but this permits real managed-system changes."
      : "Disable new deterministic execution immediately? Monitoring and investigation remain active.";
    if (!window.confirm(confirmation)) {
      return;
    }
    try {
      const response = await fetch("/api/v1/execution-control", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled,
          reason: enabled
            ? "Enabled from operator dashboard"
            : "Emergency disable from operator dashboard",
        }),
      });
      if (!response.ok) {
        const body = (await response.json()) as { detail?: string };
        throw new Error(body.detail ?? `execution control update failed: ${response.status}`);
      }
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Execution control update failed");
    }
  }

  async function dispatchProposal(proposal: ActionProposal) {
    const capability = capabilityForProposal(proposal);
    if (!capability || !isExecutable(capability)) {
      setError("This proposal does not use a reviewed Phase 6 execution adapter");
      return;
    }
    if (!executionControl?.enabled) {
      setError("Execution is disabled by the global kill switch");
      return;
    }
    if (!principalCanDispatch()) {
      setError("Your current roles do not permit execution dispatch");
      return;
    }
    if (
      !window.confirm(
        `Dispatch ${proposal.capability} against ${proposal.target_asset_id.slice(0, 8)}? ` +
          "The control plane and executor will re-check authorization before any side effect.",
      )
    ) {
      return;
    }
    try {
      const response = await fetch(`/api/v1/action-proposals/${proposal.id}/dispatch`, {
        method: "POST",
      });
      if (!response.ok) {
        const body = (await response.json()) as { detail?: string };
        throw new Error(body.detail ?? `dispatch failed: ${response.status}`);
      }
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Dispatch failed");
    }
  }

  async function planRollback(execution: Execution) {
    if (
      !window.confirm(
        `Create a policy-gated rollback proposal for ${execution.capability}? ` +
          "This does not execute rollback directly.",
      )
    ) {
      return;
    }
    try {
      const response = await fetch(`/api/v1/executions/${execution.id}/rollback-proposal`, {
        method: "POST",
      });
      if (!response.ok) {
        const body = (await response.json()) as { detail?: string };
        throw new Error(body.detail ?? `rollback planning failed: ${response.status}`);
      }
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Rollback planning failed");
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

  function principalCanDispatch(): boolean {
    return (principal?.roles ?? []).some((role) => DISPATCH_ROLES.has(role));
  }

  function capabilityForProposal(proposal: ActionProposal): Capability | undefined {
    return capabilities.find(
      (item) =>
        item.capability_id === proposal.capability && item.version === proposal.capability_version,
    );
  }

  function capabilityForExecution(execution: Execution): Capability | undefined {
    return capabilities.find(
      (item) =>
        item.capability_id === execution.capability && item.version === execution.capability_version,
    );
  }

  function isExecutable(capability: Capability): boolean {
    const adapter = capability.manifest.execution?.adapter;
    return Boolean(adapter && adapter !== "reserved_phase6");
  }

  function executionStateClass(state: string): "ok" | "degraded" | "down" {
    if (state === "SUCCEEDED") {
      return "ok";
    }
    if (["FAILED", "VERIFICATION_FAILED", "CANCELLED"].includes(state)) {
      return "down";
    }
    return "degraded";
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
  const authorizedExecutableProposals = proposals.filter((proposal) => {
    const capability = capabilityForProposal(proposal);
    return proposal.state === "AUTHORIZED" && capability != null && isExecutable(capability);
  });
  const pendingDispatchProposals = authorizedExecutableProposals.filter(
    (proposal) => !executions.some((execution) => execution.proposal_id === proposal.id),
  );

  return (
    <main>
      <header>
        <div>
          <p className="eyebrow">AUTONOMOUS INFRASTRUCTURE OPERATIONS</p>
          <h1>Agentic Network Management</h1>
          <p className="subtitle">
            Reconcile infrastructure state, investigate security incidents and execute only typed,
            policy-authorized remediation through a deterministic, independently verified worker.
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
            <p className="eyebrow">DETERMINISTIC EXECUTION</p>
            <h2>{pendingDispatchProposals.length} authorized actions ready to dispatch</h2>
          </div>
          <span className={`pill ${executionControl?.enabled ? "down" : "ok"}`}>
            execution {executionControl?.enabled ? "enabled" : "disabled"}
          </span>
        </div>
        <div className="grid">
          <article className="card">
            <div className="card-title">
              <h3>Global execution kill switch</h3>
              <span className={`pill ${executionControl?.enabled ? "down" : "ok"}`}>
                {executionControl?.enabled ? "live writes permitted" : "safe default"}
              </span>
            </div>
            <p>{executionControl?.reason ?? "Loading execution policy state…"}</p>
            <p className="protected">
              AI has no execution or secret access. Dispatch and the executor re-check OPA,
              approvals, digests and target state before any side effect.
            </p>
            {principal?.roles.includes("platform_admin") ? (
              <div className="actions">
                {executionControl?.enabled ? (
                  <button onClick={() => void setExecutionEnabled(false)}>Emergency disable</button>
                ) : (
                  <button onClick={() => void setExecutionEnabled(true)}>Enable execution</button>
                )}
              </div>
            ) : (
              <p>Only a platform administrator can change this switch.</p>
            )}
          </article>
          <article className="card">
            <div className="card-title">
              <h3>Execution boundary</h3>
              <span className="pill ok">deterministic only</span>
            </div>
            <p>Executor: policy + approvals + JIT OpenBao secret + reviewed adapter.</p>
            <p>Verifier: separate read-only observation path with no secret access.</p>
            <p className="protected">
              Executor success is intermediate. Only independent verification can produce SUCCEEDED.
            </p>
          </article>
        </div>
        <div className="review-list">
          {pendingDispatchProposals.map((proposal) => {
            const capability = capabilityForProposal(proposal);
            const adapter = capability?.manifest.execution?.adapter ?? "unknown";
            const mayDispatch = executionControl?.enabled === true && principalCanDispatch();
            return (
              <article key={proposal.id} className="card review-card">
                <div>
                  <div className="card-title">
                    <h3>{proposal.capability}</h3>
                    <span className="pill degraded">risk {capability?.risk ?? "?"}</span>
                  </div>
                  <p>
                    Target {proposal.target_asset_id.slice(0, 8)} · incident{" "}
                    {proposal.incident_id.slice(0, 8)} · adapter {adapter}
                  </p>
                  <p>{proposal.reason}</p>
                  <p>
                    Proposal {proposal.proposal_digest.slice(0, 12)}… · implementation{" "}
                    {proposal.implementation_digest.slice(0, 12)}… · policy {proposal.policy_version}
                  </p>
                  {!executionControl?.enabled && (
                    <p className="protected">Dispatch blocked by the global execution kill switch.</p>
                  )}
                  {!principalCanDispatch() && (
                    <p className="protected">Your current roles do not permit dispatch.</p>
                  )}
                </div>
                <div className="actions">
                  <button disabled={!mayDispatch} onClick={() => void dispatchProposal(proposal)}>
                    Dispatch
                  </button>
                </div>
              </article>
            );
          })}
          {pendingDispatchProposals.length === 0 && (
            <article className="card">
              <p>No newly authorized executable proposals are waiting for dispatch.</p>
            </article>
          )}
        </div>
      </section>

      <section>
        <div className="section-heading">
          <div>
            <p className="eyebrow">EXECUTION VERIFICATION</p>
            <h2>{executions.length} recent execution records</h2>
          </div>
          <span className="pill ok">independent verification required</span>
        </div>
        <div className="review-list">
          {executions.map((execution) => {
            const capability = capabilityForExecution(execution);
            const canPlanRollback =
              capability?.reversible === true && ROLLBACK_ELIGIBLE_STATES.has(execution.state);
            return (
              <article key={execution.id} className="card review-card">
                <div>
                  <div className="card-title">
                    <h3>{execution.capability}</h3>
                    <span className={`pill ${executionStateClass(execution.state)}`}>
                      {execution.state}
                    </span>
                  </div>
                  <p>
                    Execution {execution.id.slice(0, 8)} · target{" "}
                    {execution.target_asset_id.slice(0, 8)} · criticality {execution.target_criticality}
                  </p>
                  <p>
                    Proposal {execution.proposal_digest.slice(0, 12)}… · implementation{" "}
                    {execution.implementation_digest.slice(0, 12)}…
                  </p>
                  {execution.rollback_of_execution_id && (
                    <p>Rollback of execution {execution.rollback_of_execution_id.slice(0, 8)}</p>
                  )}
                  {execution.state === "AMBIGUOUS" && (
                    <p className="protected">
                      Remote outcome is uncertain. The executor will not blindly retry this action.
                    </p>
                  )}
                  {execution.state === "VERIFICATION_FAILED" && (
                    <p className="protected">
                      The executor reported success, but the independent verifier did not observe the
                      required end state.
                    </p>
                  )}
                  {execution.error_category && (
                    <p className="protected">
                      {execution.error_category}
                      {execution.error_detail ? ` · ${execution.error_detail}` : ""}
                    </p>
                  )}
                </div>
                {canPlanRollback && (
                  <div className="actions">
                    <button onClick={() => void planRollback(execution)}>Plan rollback</button>
                  </div>
                )}
              </article>
            );
          })}
          {executions.length === 0 && (
            <article className="card"><p>No execution has been dispatched yet.</p></article>
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
          <span className="pill degraded">approval is not execution</span>
        </div>
        <div className="review-list">
          {approvalQueue.map(({ proposal, approvals }) => {
            const capability = capabilityForProposal(proposal);
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
                    Approval authorizes this exact digest only. Dispatch is a separate Phase 6 gate.
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
                {capabilities.filter(isExecutable).length} of {capabilities.length} enabled typed
                operations currently bind reviewed deterministic execution adapters.
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
            <p className="protected">No managed-network, execution or secret access from ai-worker</p>
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
        Phase 6 permits only reviewed deterministic capabilities. AI remains read-only; secrets stay
        inside the isolated executor; ambiguous outcomes are never blindly retried; success requires
        independent verification; rollback follows the normal proposal, OPA and approval path.
      </footer>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
