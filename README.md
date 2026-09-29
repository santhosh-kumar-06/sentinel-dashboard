# Sentinel Security Dashboard

A responsive single-page security dashboard with a small, dependency-free Node.js backend.

## Run locally

Requires Node.js 18 or newer.

```bash
node server.mjs
```

Open <http://127.0.0.1:4173>.

To use another local port:

```bash
PORT=5000 node server.mjs
```

## What it does

- Scans a fixed list of 18 common TCP ports on a domain, URL, or IP you enter.
- Requires an explicit authorization checkbox and enforces a short scan cooldown.
- Shows a simple exposure estimate, reachable services, general threat scenarios, and mitigations.
- Starts with an empty event timeline. `GET /api/events` returns the current in-memory feed; `POST /api/events` accepts basic events from an authorized log integration.
- Binds to `127.0.0.1` only and uses Node built-ins; no packages to install.

## Important limits

Use only against systems you own or are explicitly authorized to assess. The scanner is a limited TCP connect check, not a vulnerability scanner: it does not identify software versions, validate CVEs, attempt logins, exploit services, or test application behavior. The score is a heuristic exposure estimate, not CVSS or a compliance result. No attacks are performed.

Real attack timelines require logs from a WAF/CDN, web server, identity provider, host agent, or SIEM to be securely integrated. The timeline stays empty until events are ingested and is not monitoring a website by itself. The prototype does not automatically change firewall rules or take remediation actions.

## Test event ingestion

With the server running, this authorized local test adds one event to the
in-memory timeline. Refresh the dashboard afterward:

```bash
curl -X POST http://127.0.0.1:4173/api/events \
  -H "Content-Type: application/json" \
  -d '{"type":"Repeated authentication failures","asset":"example.com","severity":"High","source":"203.0.113.10"}'
```

Events are stored only in memory and are cleared when the Node.js server restarts.

For production use, add authentication, TLS, durable storage, audit trails, CSRF/rate-limit controls, secure event ingestion, and a vetted scanning/telemetry pipeline. Keep scanning authorization and scope explicit.