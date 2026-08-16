# Phase 4 — Read-only AI investigation

Phase 4 adds optional AI reasoning on top of the deterministic Phase-3 incident engine.

## Safety model

The reasoning worker is intentionally isolated:

```text
PostgreSQL/NATS -> ai-worker -> internal ai network -> model-relay -> model provider
                                      X
                              no OpenBao/secrets
                              no discovery network
                              no telemetry network
                              no model-egress network
```

`ai-worker` has no OpenBao mount/network and no non-internal network. It cannot directly
reach model providers or managed-network connectors. `model-relay` is a deterministic
transport boundary: it resolves provider configuration, obtains only the provider API
credential from OpenBao, validates the destination and performs the OpenAI-compatible
HTTP request. Provider credentials are HTTP headers only and are never added to model
messages.

External providers must use HTTPS. The relay rejects external destinations resolving to
private, loopback, link-local, multicast, unspecified or reserved addresses. An
`isolated_local` provider is allowed only when its hostname is explicitly listed in
`ANM_AI_LOCAL_PROVIDER_HOSTS`; HTTP is permitted only for this isolated-local mode.

## Enablement

AI is disabled by default:

```text
ANM_AI_ENABLED=false
```

Telemetry, inventory, deterministic findings, incidents and manual incident state
transitions remain available with AI disabled or unavailable.

To enable investigations:

1. Put a model provider credential in OpenBao (external providers only).
2. Create a provider through `POST /api/v1/ai/providers`.
3. Set `ANM_AI_ENABLED=true`.
4. Restart the control API and AI worker.
5. Request an investigation with
   `POST /api/v1/incidents/{incident_id}/investigations`.

Provider `base_url` paths must end in `/v1`; a prefix before `/v1` is allowed. This covers
common OpenAI-compatible layouts such as OpenAI `/v1`, OpenRouter `/api/v1` and Groq
`/openai/v1`. The relay appends `/chat/completions`. Local Ollama/LiteLLM-style
deployments should use the isolated model-provider network and explicit hostname allowlist.

## Evidence minimisation

Model evidence is intentionally lossy. The Phase-4 bundle excludes raw command lines,
full logs, arbitrary HTTP headers/bodies, URLs and unbounded protocol dictionaries. SOC
and Network Analyst bundles contain generated event labels plus selected structured
fields only. This allowlist is the primary data-minimisation control.

A recursive redactor remains defense in depth for selected string fields and removes
obvious credential keys, bearer tokens, assignment-style secret markers, private-key
blocks and OpenBao references. Context size and event count are capped. Every source item
remains labelled `untrusted_evidence`.

## Agent execution

Phase 4 runs:

- SOC Analyst for every incident
- Network Analyst when canonical network evidence is present
- Supervisor after specialist outputs validate

Models receive no function/tool definitions. Tool allowlists are platform contracts for
future internal read-only dispatch and are stored on each agent step, but no provider-side
tool call can be made in Phase 4.

Model output must validate against
`schemas/investigation-result.schema.json`. Evidence IDs must be a subset of the IDs
actually supplied to that agent. Invalid JSON, extra fields such as `tool_calls`, role
mismatches or fabricated evidence IDs fail the investigation.

## Audit/cost data

The platform stores:

- investigation run/provider/model
- agent role and allowlist
- evidence-bundle digest
- request/response SHA-256 hashes
- input/output token counts
- configured cost estimate
- validated findings/hypotheses
- incident timeline entry
- redacted failed-invocation metadata when a provider call itself fails

Raw prompts, raw model responses, provider credentials and raw provider exception text are
not persisted as model-invocation records.

Provider config may define:

```json
{
  "monthly_budget_usd": 25,
  "input_cost_per_million": 1.0,
  "output_cost_per_million": 4.0,
  "max_output_tokens": 1600,
  "supports_json_schema": true
}
```

Budget exhaustion stops new model calls for that provider. Cost values are operator
configuration, not pricing fetched from the provider.
