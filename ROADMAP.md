# Pulse 249 Roadmap

Pulse 249 is under active development. This roadmap communicates the project's current engineering direction without treating future targets as already certified production capability.

## Current priorities

### 1. Monitoring and observability

- Expand device and interface monitoring coverage.
- Improve availability, utilization, traffic, error, discard, uptime, and status presentation.
- Continue improving polling-engine capacity visibility and operational health reporting.
- Strengthen monitoring history, search, filtering, and troubleshooting workflows.

### 2. Discovery and inventory

- Improve scalable device and interface discovery.
- Expand inventory discovery and reconciliation.
- Add broader vendor/device support through adapters and templates.
- Improve partial-retry behavior, duplicate protection, fairness, and capacity-aware routing.

### 3. Configuration management

- Expand configuration templates and device support.
- Improve configuration capture, review, deployment, and operational-history workflows.
- Continue strengthening safety controls around parallel configuration execution.

### 4. Secure remote access

- Continue improving browser-based SSH and secure WebGUI access.
- Strengthen credential-reference, session, TLS trust, and auditing controls.
- Keep legacy plaintext transports disabled by default unless explicitly required.

### 5. Scale and reliability

- Continue qualification of distributed workers and polling engines.
- Improve database, queue, worker, and scheduler capacity controls.
- Expand recovery, fail-safe, and runtime-qualification procedures.
- Validate large-estate behavior progressively rather than publishing unverified capacity claims.

### 6. Open-source readiness

- Improve installation and deployment documentation.
- Add reproducible development and test workflows suitable for external contributors.
- Expand contributor documentation and issue triage.
- Add screenshots, architecture documentation, and example deployments as they become safe and representative to publish.

## Longer-term direction

Pulse 249 is intended to evolve into an extensible network operations platform useful to telecommunications operators, ISPs, enterprises, universities, managed-service providers, and infrastructure teams.

Longer-term areas include:

- broader multi-vendor support;
- additional network protocols and device adapters;
- richer topology and dependency visualization;
- improved automation and operational workflows;
- stronger reporting and capacity planning;
- hardened deployment patterns for large managed-device estates;
- community-maintained monitoring definitions, templates, and integrations.

## Contributing to the roadmap

The roadmap is expected to evolve with operational experience and community feedback. Please open a GitHub issue for feature proposals, device/vendor requests, deployment requirements, or other improvements.

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting code changes.
