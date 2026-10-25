<h1 align="center">Pulse 249</h1>

<p align="center">
  <strong>Open-source network operations platform for monitoring, managing, discovering, configuring, and securely accessing network devices at scale.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/License-Apache--2.0-blue.svg"></a>
  <img alt="Status: Active Development" src="https://img.shields.io/badge/status-active%20development-orange.svg">
  <img alt="Focus: Network Operations" src="https://img.shields.io/badge/focus-network%20operations-brightgreen.svg">
</p>

## Why Pulse 249?

Network teams frequently have to combine several disconnected products for monitoring, discovery, inventory, configuration, secure device access, reporting, and operational control. That fragmentation can increase cost, complexity, and operational risk.

**Pulse 249** is being built as a unified network operations platform that brings these workflows together behind a web-based interface and a distributed backend architecture.

The project is particularly motivated by the needs of telecommunications operators, ISPs, enterprises, universities, and infrastructure teams in **Sudan and similar markets**, where access to flexible, locally adaptable network-management software can be limited. The goal is to contribute serious infrastructure software from the Sudanese engineering ecosystem while building something useful to network operators internationally.

> **Project status:** Pulse 249 is under active development. APIs, deployment procedures, interfaces, and architecture may evolve before the first stable release.

## What it covers

| Area | Capabilities |
| --- | --- |
| **Monitoring** | Device availability, SNMP telemetry, interface traffic/utilization, errors/discards, uptime, administrative/operational state, monitoring history, availability visualization |
| **Discovery** | Device discovery, batch discovery, interface discovery, inventory discovery, SNMP and HTTP/HTTPS discovery, controlled parallel execution, retry workflows |
| **Inventory & topology** | Devices, interfaces, IP addresses, device classifications, networks, cities, locations, sectors, groups, VLANs, customer/service relationships |
| **Secure access** | Web SSH, Web Telnet where explicitly enabled, secure WebGUI access, HTTP/HTTPS management proxying, access templates, credential references, TLS trust workflows |
| **Configuration** | Configuration templates, capture, review, deployment workflows, configuration artifacts, operational history, controlled execution |
| **Operations** | Role-based access control, user/permission management, audit logging, session management, password lifecycle, maintenance, notifications, restore points, reporting |
| **Capacity & orchestration** | Distributed workers, polling engines, workload isolation, capacity-aware routing, bounded retries, execution fencing, operational health visibility |

## Architecture

Pulse 249 uses a distributed service architecture so operational workloads can scale independently rather than being forced through a single process.

Core technologies and components include:

- **Frontend:** React + TypeScript
- **Backend API:** Python + FastAPI
- **Persistence:** PostgreSQL
- **Coordination / queues:** Redis + Celery
- **Network protocols:** SNMP, SSH, HTTP/HTTPS, and Telnet where explicitly enabled
- **Execution services:** monitoring, discovery, availability, configuration, and supporting workers
- **Polling architecture:** primary and additional polling engines with explicit capacity controls
- **Security controls:** RBAC, session controls, audit logging, credential references, and controlled remote access
- **Deployment:** Docker-based development and deployment configurations

```text
                         +----------------------+
                         |      Pulse 249       |
                         |     Web Frontend     |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         |      Backend API     |
                         +----------+-----------+
                                    |
                   +----------------+----------------+
                   |                                 |
                   v                                 v
          +----------------+                +----------------+
          | PostgreSQL     |                | Redis / Celery |
          +----------------+                +--------+-------+
                                                    |
                   +----------------+---------------+----------------+
                   |                |               |                |
                   v                v               v                v
             Monitoring         Discovery      Availability    Configuration
               Workers           Workers         Workers          Workers
                   |                |               |                |
                   +----------------+---------------+----------------+
                                    |
                                    v
                         +----------------------+
                         |   Network Devices    |
                         +----------------------+
```

## Scale and reliability direction

Scalability is a primary engineering objective rather than an afterthought.

Current engineering work includes:

- controlled parallel device operations;
- multiple polling engines;
- distributed asynchronous workers;
- capacity-aware routing;
- database connection-capacity controls;
- workload isolation and execution fencing;
- duplicate-execution protection;
- bounded retries and partial-retry behavior;
- service health and capacity visibility;
- recovery and runtime qualification procedures.

The long-term architecture is being developed for network estates containing **tens of thousands of managed devices**. Published scale figures should be treated as engineering targets until they are formally certified on production hardware.

## Designed for practical network operations

Pulse 249 is intended for environments such as:

- telecommunications operators;
- Internet service providers;
- enterprise networks;
- universities and research institutions;
- managed service providers;
- infrastructure and NOC teams;
- organizations operating heterogeneous network-device estates.

The project is vendor-agnostic by design and is intended to evolve through additional adapters, templates, protocol support, monitoring definitions, and community contributions.

## Getting started

Clone the repository:

```bash
git clone https://github.com/OBI-512/pulse-249.git
cd pulse-249
```

Create a local environment file from the supplied example:

```bash
cp .env.example .env
```

Review and replace **all placeholder credentials** before starting any services.

The repository contains Docker Compose definitions for development and deployment scenarios. Because Pulse 249 is still under active development, review the configuration and environment examples before running it in your environment.

## Security

Pulse 249 interacts with network infrastructure and can process sensitive operational credentials. Security is therefore part of the system design, not just a deployment concern.

Never commit real:

- passwords;
- SNMP community strings;
- SNMPv3 authentication or privacy secrets;
- SSH private keys;
- API keys or access tokens;
- production `.env` files;
- database dumps;
- confidential network/device configurations.

See [SECURITY.md](SECURITY.md) for vulnerability-reporting guidance.

## Contributing

Pulse 249 is newly public and is being opened for broader technical collaboration.

Useful contributions include:

- new device/vendor support;
- monitoring and telemetry improvements;
- discovery adapters;
- protocol support;
- tests and qualification tooling;
- documentation;
- UI/UX improvements;
- deployment improvements;
- performance and scalability work;
- security improvements.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes.

## Open-source mission

Pulse 249 is intended to help close a gap between expensive or fragmented proprietary network-management tooling and the practical needs of organizations that require an extensible operations platform they can inspect, adapt, and improve.

The project also has a regional mission: to demonstrate that advanced network-infrastructure software can originate from the Sudanese engineering community and contribute back to the wider open-source and networking ecosystems.

The repository is newly public, so community adoption metrics such as downloads, stars, forks, and external dependents are expected to develop over time. The current emphasis is on building a technically credible foundation and making the project accessible to contributors and early users.

## License

Pulse 249 is licensed under the **Apache License 2.0**.

See [LICENSE](LICENSE) for the full license text.

## Disclaimer

Pulse 249 is under active development. Before production deployment, operators are responsible for reviewing security configuration, credentials, network permissions, backup procedures, deployment architecture, and applicable organizational policies.
