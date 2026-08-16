# Security Policy

Agentic Network Management is a security-sensitive infrastructure automation project. Security boundaries are part of the product contract.

## Reporting a vulnerability

Do not publish exploitable vulnerabilities, credentials or customer/environment data in a public issue.

Until a dedicated private reporting address/process is configured, use GitHub's private vulnerability reporting feature if enabled for the repository or contact the repository owner privately through an agreed channel.

A future release must document a stable security contact and disclosure SLA before the software is represented as production-ready.

## Architecture security requirements

Contributors must read:

- `docs/security/SECURITY_INVARIANTS.md`
- `docs/security/THREAT_MODEL.md`
- `docs/security/TEST_STRATEGY.md`

Changes touching agents, connectors, actions, policy, authentication, secrets, service networking or execution must state which security invariants apply and how tests prove them.

## Prohibited implementation patterns

Production code must not introduce:

- LLM access to plaintext infrastructure secrets
- direct model access to managed-network sockets
- generic AI-accessible shell/SSH/PowerShell execution
- AI-generated production playbooks executed automatically
- a write path that bypasses OPA
- approval encoded only as chat text or model output
- executor success treated as final success without verification
- plaintext credentials in the repository, application database or logs
- floating `latest` container tags in release manifests

## Secrets

- Commit no real credentials, tokens, certificates or private keys.
- Use development placeholders in `.env.example`-style files.
- Runtime infrastructure secrets belong in OpenBao or an approved provider behind the secret abstraction.
- Test secrets must be ephemeral/lab-only.

## Security release gates

Before production claims or guarded autonomy are enabled, the project must have:

- invariant-mapped automated tests
- prompt-injection/adversarial tests
- OPA fail-closed tests
- executor idempotency/retry tests
- approval replay/mutation tests
- verification/rollback tests
- SBOM and dependency/licence inventory
- container/dependency vulnerability scanning
- documented backup/restore and emergency autonomy-disable procedures

## Supported versions

No versions are formally supported yet. The project is in architecture/pre-implementation status.
