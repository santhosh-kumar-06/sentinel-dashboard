import http from "node:http";
import net from "node:net";
import dns from "node:dns/promises";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 4173);
const HOST = "127.0.0.1";
const SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200];
const SERVICE_META = {
  21: { service: "FTP", risk: "High", attacks: ["Credential brute-force", "Clear-text credential interception", "Anonymous/over-permissive file access"], defenses: ["Disable FTP where possible and migrate to SFTP/FTPS.", "Block TCP/21 from the public internet; allow only trusted source networks through the firewall.", "Disable anonymous login and remove unused accounts.", "Enforce long unique passwords, account lockout/rate limits, and MFA on the replacement remote-access path.", "Monitor repeated failed logins, unexpected file uploads/downloads, and configuration changes."] },
  22: { service: "SSH", risk: "Low", attacks: ["Password guessing", "Stolen-key login", "Privilege abuse after account compromise"], defenses: ["Disable password authentication where practical and require SSH keys.", "Disable direct root login and use least-privilege sudo access.", "Restrict TCP/22 to VPN, bastion, or approved administrator IP ranges.", "Use MFA on the bastion/VPN and rotate or revoke unused SSH keys.", "Enable rate limiting such as fail2ban/sshd MaxAuthTries and alert on repeated failures or new key installation."] },
  23: { service: "Telnet", risk: "Critical", attacks: ["Clear-text credential interception", "Credential replay", "Unauthorized remote administration"], defenses: ["Disable Telnet immediately and replace it with SSH.", "Block TCP/23 at perimeter and host firewalls.", "Reset credentials that may have been used over Telnet because they could have crossed the network unencrypted.", "Restrict remote administration to VPN/bastion access with MFA.", "Review authentication and command logs for unexpected sessions."] },
  25: { service: "SMTP", risk: "Medium", attacks: ["Open-relay abuse", "Password spraying against mail accounts", "Spoofed mail if sender controls are weak"], defenses: ["Disable unauthenticated relaying for untrusted networks.", "Require TLS for authenticated submission and keep the mail server patched.", "Use SPF, DKIM, and DMARC for the organization domain.", "Apply connection and authentication rate limits; enforce MFA for mail accounts where supported.", "Monitor relay attempts, unusual outbound volume, repeated auth failures, and reputation/blocklist alerts."] },
  53: { service: "DNS", risk: "Medium", attacks: ["Open-recursion abuse", "Unauthorized zone transfer", "DNS amplification participation"], defenses: ["Disable public recursion unless the server is intentionally a public resolver.", "Restrict AXFR/IXFR zone transfers to authorized secondary DNS servers only.", "Apply response-rate limiting and network ACLs.", "Separate authoritative and recursive DNS roles when possible and patch DNS software promptly.", "Monitor unusual query volume, transfer attempts, and spikes in large UDP responses."] },
  80: { service: "HTTP", risk: "Low", attacks: ["Clear-text session interception", "Web application attacks against exposed routes", "Security-header downgrade/misconfiguration"], defenses: ["Redirect all HTTP traffic to HTTPS and enable HSTS on the HTTPS site.", "Keep the web server/framework patched and remove unused modules/routes.", "Deploy a WAF or equivalent filtering for common web attacks and rate-limit sensitive endpoints.", "Set secure cookies plus CSP, X-Content-Type-Options, and frame protections as appropriate.", "Monitor 4xx/5xx spikes, repeated authentication failures, and suspicious request patterns."] },
  110: { service: "POP3", risk: "Medium", attacks: ["Clear-text credential interception", "Password guessing", "Mailbox access after credential compromise"], defenses: ["Disable plaintext POP3; use POP3S/TLS or a modern mail-access protocol.", "Restrict access to trusted networks/VPN if remote POP access is not required.", "Enforce strong authentication and MFA where the mail platform supports it.", "Rate-limit repeated failures and lock or challenge suspicious login attempts.", "Review mailbox login history and alert on new geographies/devices when supported."] },
  139: { service: "NetBIOS", risk: "High", attacks: ["Legacy Windows service discovery", "Credential/hash exposure through legacy file-sharing paths", "Lateral movement on flat networks"], defenses: ["Disable NetBIOS over TCP/IP where it is not required.", "Block TCP/139 at internet and inter-segment firewalls except for explicit legacy dependencies.", "Use network segmentation to prevent workstation-to-workstation lateral access.", "Disable legacy name-resolution protocols where feasible and enforce host firewalls.", "Monitor unexpected SMB/NetBIOS connections between user endpoints."] },
  143: { service: "IMAP", risk: "Medium", attacks: ["Clear-text credential interception", "Password spraying", "Mailbox access after account compromise"], defenses: ["Require IMAPS/TLS and disable plaintext authentication on unencrypted sessions.", "Enforce MFA where supported and disable legacy authentication methods.", "Apply login throttling and suspicious-login detection.", "Restrict administrative interfaces separately from user IMAP access.", "Monitor unusual mailbox access, mass downloads, forwarding-rule changes, and repeated login failures."] },
  443: { service: "HTTPS", risk: "Low", attacks: ["Web application attacks", "Credential attacks against login endpoints", "TLS/certificate misconfiguration abuse"], defenses: ["Patch the web server, framework, CMS, and dependencies on a defined cadence.", "Use a WAF for common injection, traversal, bot, and exploit patterns; tune rules to the application.", "Require MFA for privileged/admin accounts and rate-limit login/reset endpoints.", "Use modern TLS (prefer TLS 1.2/1.3), trusted certificates, HSTS, and secure cookie settings.", "Centralize access/WAF/application logs and alert on exploit signatures, auth anomalies, and sudden error-rate changes."] },
  445: { service: "SMB", risk: "Critical", attacks: ["Credential/hash theft or relay", "Ransomware/lateral movement", "Exploitation of unpatched SMB vulnerabilities"], defenses: ["Never expose TCP/445 directly to the public internet; block it at perimeter firewalls.", "Disable SMBv1 and require current SMB versions; enable SMB signing where compatible.", "Patch Windows/Samba systems promptly and isolate file servers from user VLANs.", "Use least-privilege shares, remove Everyone/guest write access, and protect admin shares.", "Enable endpoint protection plus alerts for mass file modification, remote-service creation, and abnormal SMB fan-out."] },
  3306: { service: "MySQL", risk: "High", attacks: ["Database password guessing", "Unauthorized direct database access", "Data theft after weak-account compromise"], defenses: ["Keep MySQL on a private subnet; do not expose TCP/3306 to the internet.", "Allow inbound connections only from approved application hosts/security groups.", "Use dedicated least-privilege DB users; remove anonymous/test accounts and remote root login.", "Require TLS for remote DB connections and rotate application/database secrets.", "Enable audit/error logging and alert on repeated login failures, privilege changes, and unusual export volume."] },
  3389: { service: "RDP", risk: "Critical", attacks: ["Password spraying/brute-force", "Stolen-credential remote login", "Ransomware entry through exposed remote desktop"], defenses: ["Remove direct internet exposure to TCP/3389; place RDP behind VPN, Zero Trust access, or RD Gateway.", "Require MFA before RDP access and enable Network Level Authentication (NLA).", "Restrict allowed users and source networks; disable dormant accounts.", "Patch Windows hosts promptly and apply account-lockout/rate-limit controls.", "Alert on repeated failures, successful logins from new sources, off-hours admin sessions, and new local-admin membership."] },
  5432: { service: "PostgreSQL", risk: "High", attacks: ["Database credential guessing", "Unauthorized remote DB access", "Data extraction after account compromise"], defenses: ["Bind PostgreSQL to private interfaces and block public TCP/5432 exposure.", "Use pg_hba.conf to allow only required application/user sources with the strongest practical auth method.", "Require TLS for remote connections and rotate credentials/secrets.", "Use separate least-privilege roles for applications, migrations, and administrators.", "Enable connection/audit logging and alert on auth failures, role changes, schema changes, and unusual query/export behavior."] },
  6379: { service: "Redis", risk: "Critical", attacks: ["Unauthenticated data access", "Unauthorized configuration changes", "Abuse of an exposed in-memory datastore"], defenses: ["Bind Redis to localhost/private interfaces only and block public TCP/6379 exposure.", "Use ACLs/authentication and unique strong credentials; do not rely on network location alone.", "Run Redis as an unprivileged service account and disable/rename dangerous administrative commands where operationally appropriate.", "Use TLS when Redis traffic crosses untrusted networks.", "Monitor config changes, keyspace flushes, unexpected persistence changes, and connections from new sources."] },
  8080: { service: "HTTP alternate", risk: "Medium", attacks: ["Exposed admin/development console", "Web application attacks", "Unencrypted access if used for production traffic"], defenses: ["Identify the exact application on TCP/8080 and confirm that public exposure is intentional.", "Restrict admin/dev consoles to VPN or trusted management networks.", "Place production traffic behind HTTPS/reverse proxy and require authentication for management functions.", "Patch the application/container and remove default credentials/sample apps.", "Monitor access to administrative paths and repeated 401/403/5xx responses."] },
  8443: { service: "HTTPS alternate", risk: "Low", attacks: ["Exposed administrative interface", "Web application attacks", "Weak TLS configuration"], defenses: ["Confirm what service is listening and whether internet exposure is required.", "Restrict administrative interfaces to management networks/VPN.", "Use modern TLS and a valid certificate; disable obsolete protocol versions/ciphers.", "Require MFA for privileged interfaces and remove default credentials.", "Monitor privileged logins, configuration changes, and suspicious request patterns."] },
  9200: { service: "Elasticsearch", risk: "Critical", attacks: ["Unauthenticated index access", "Bulk data theft or deletion", "Administrative API abuse"], defenses: ["Keep TCP/9200 private; block direct internet access with firewalls/security groups.", "Enable Elasticsearch security features: authentication, authorization/RBAC, and TLS.", "Use least-privilege roles for applications and administrators; remove broad wildcard privileges.", "Protect snapshots/backups and test restoration procedures.", "Monitor index deletion, bulk export/search activity, privilege changes, and connections from new source addresses."] }
};

// The event feed intentionally starts empty. Real events must be ingested from
// an authorized WAF, web server, host agent, or SIEM through POST /api/events.
let events = [];
const lastScanAt = new Map();

function json(res, status, data) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", chunk => {
      raw += chunk;
      if (raw.length > 8_000) {
        reject(new Error("Request body is too large."));
        req.destroy();
      }
    });
    req.on("end", () => {
      try { resolve(JSON.parse(raw || "{}")); }
      catch { reject(new Error("Request body must be valid JSON.")); }
    });
    req.on("error", reject);
  });
}

function extractHost(value) {
  if (typeof value !== "string" || value.length > 300) throw new Error("Enter a valid domain, URL, or IP address.");
  let input = value.trim();
  if (!input) throw new Error("Enter a domain, URL, or IP address.");
  let host;
  try {
    const normalized = /^[a-z][a-z\d+.-]*:\/\//i.test(input) ? input : `https://${input}`;
    host = new URL(normalized).hostname;
  } catch { throw new Error("That target is not a valid URL or IP address."); }
  host = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (host.includes("@") || host.includes("%") || host === "localhost.localdomain") throw new Error("Enter a plain hostname or IP address.");
  if (net.isIP(host)) return host;
  if (host.length > 253 || !/^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?)(?:\.(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?))*\.?$/i.test(host)) {
    throw new Error("Enter a valid DNS hostname or IP address.");
  }
  return host.replace(/\.$/, "");
}

function probe(ip, port, timeoutMs = 750) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let settled = false;
    const finish = open => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
    socket.connect({ host: ip, port });
  });
}

async function mapLimit(items, limit, fn) {
  const output = new Array(items.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++;
      output[index] = await fn(items[index]);
    }
  }));
  return output;
}

async function scanTarget(input) {
  const host = extractHost(input);
  const resolved = net.isIP(host) ? [{ address: host, family: net.isIP(host) }] : await dns.lookup(host, { all: true, verbatim: true });
  if (!resolved.length) throw new Error("The hostname did not resolve to an address.");
  const address = resolved[0].address;
  const openPorts = (await mapLimit(SCAN_PORTS, 6, async port => (await probe(address, port)) ? port : null))
    .filter(port => port !== null);
  const services = openPorts.map(port => {
    const meta = SERVICE_META[port];
    return { port, ...meta };
  });
  const weights = { Critical: 26, High: 15, Medium: 8, Low: 3 };
  const exposure = Math.min(100, services.reduce((sum, item) => sum + weights[item.risk], 0));
  return {
    id: randomUUID(),
    target: host,
    address,
    scannedAt: new Date().toISOString(),
    portsChecked: SCAN_PORTS.length,
    openPorts: services,
    score: Math.max(0, 100 - exposure),
    scoreLabel: "Exposure-based estimate",
    note: "A TCP port check identifies reachable services only. It does not confirm a vulnerability or test an exploit."
  };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  if (req.method === "GET" && url.pathname === "/api/health") return json(res, 200, { status: "ok", service: "Sentinel Security Dashboard" });
  if (req.method === "GET" && url.pathname === "/api/events") return json(res, 200, { events });
  if (req.method === "POST" && url.pathname === "/api/events") {
    try {
      const body = await readBody(req);
      if (!body || typeof body.type !== "string" || typeof body.asset !== "string") return json(res, 400, { error: "Event type and asset are required." });
      const event = {
        id: randomUUID().slice(0, 8),
        time: new Date().toISOString(),
        severity: ["Critical", "High", "Medium", "Low"].includes(body.severity) ? body.severity : "Medium",
        source: typeof body.source === "string" ? body.source.slice(0, 80) : "unknown",
        type: body.type.slice(0, 120),
        asset: body.asset.slice(0, 120),
        status: "New"
      };
      events = [event, ...events].slice(0, 100);
      return json(res, 201, { event });
    } catch (error) { return json(res, 400, { error: error.message }); }
  }
  if (req.method === "POST" && url.pathname === "/api/scan") {
    try {
      const body = await readBody(req);
      if (body.authorized !== true) return json(res, 403, { error: "Confirm that you own or are authorized to assess this target." });
      const key = req.socket.remoteAddress || "local";
      const prior = lastScanAt.get(key) || 0;
      if (Date.now() - prior < 12_000) return json(res, 429, { error: "Please wait 12 seconds before starting another scan." });
      lastScanAt.set(key, Date.now());
      const result = await scanTarget(body.target);
      return json(res, 200, result);
    } catch (error) {
      const message = error.code === "ENOTFOUND" || error.code === "EAI_AGAIN"
        ? "Could not resolve that hostname. Check the target and try again."
        : (error.message || "The scan could not be completed.");
      return json(res, 400, { error: message });
    }
  }

  if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
    try {
      const html = await readFile(path.join(ROOT, "index.html"));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      return res.end(html);
    } catch { return json(res, 500, { error: "Dashboard file could not be loaded." }); }
  }
  json(res, 404, { error: "Not found." });
});

server.listen(PORT, HOST, () => {
  console.log(`Sentinel dashboard running at http://${HOST}:${PORT}`);
  console.log("Local-only MVP. Scan only systems you own or are authorized to assess.");
});