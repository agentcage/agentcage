#!/usr/bin/env node

// agentcage test suite — runs inside the caged agent container
// Tests: allowed domains, blocked domains, secret leak blocking

const tests = [];
let passed = 0;
let failed = 0;

function test(name, fn) {
  tests.push({ name, fn });
}

async function run() {
  console.log("=== agentcage cage test suite ===\n");

  for (const { name, fn } of tests) {
    process.stdout.write(`  ${name} ... `);
    try {
      await fn();
      passed++;
      console.log("PASS");
    } catch (err) {
      failed++;
      console.log(`FAIL: ${err.message}`);
    }
  }

  console.log(`\n=== Results: ${passed} passed, ${failed} failed, ${tests.length} total ===`);
  if (failed > 0) {
    console.log("\nTests failed. Container staying up for debugging.");
  } else {
    console.log("\nAll tests passed. Container staying up.");
  }
  // Keep the container alive so systemd doesn't restart/remove it
  setInterval(() => {}, 1 << 30);
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// ── Test: allowed domain (httpbin.org) ───────────────

test("GET to allowed domain (httpbin.org) succeeds", async () => {
  const res = await fetch("https://httpbin.org/get");
  assert(res.ok, `expected 200, got ${res.status}`);
  const body = await res.json();
  assert(body.url === "https://httpbin.org/get", "unexpected response body");
});

test("POST to allowed domain works", async () => {
  const res = await fetch("https://httpbin.org/post", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hello: "world" }),
  });
  assert(res.ok, `expected 200, got ${res.status}`);
  const body = await res.json();
  assert(body.json.hello === "world", "POST body not echoed back");
});

// ── Test: blocked domain ─────────────────────────────

test("GET to blocked domain (example.com) returns 403", async () => {
  const res = await fetch("https://example.com");
  assert(res.status === 403, `expected 403, got ${res.status}`);
});

test("GET to blocked domain (evil.com) returns 403", async () => {
  const res = await fetch("https://evil.com");
  assert(res.status === 403, `expected 403, got ${res.status}`);
});

// ── Test: second allowed domain (api.github.com) ─────

test("GET to api.github.com succeeds", async () => {
  const res = await fetch("https://api.github.com/zen");
  assert(res.ok, `expected 200, got ${res.status}`);
});

// ── Test: secret leak detection ──────────────────────

test("POST with fake API key in body is blocked", async () => {
  const res = await fetch("https://httpbin.org/post", {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: "here is my key: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  });
  assert(res.status === 403, `expected 403, got ${res.status}`);
});

test("POST with GitHub token in body is blocked", async () => {
  const res = await fetch("https://httpbin.org/post", {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab",
  });
  assert(res.status === 403, `expected 403, got ${res.status}`);
});

// ── Test: clean POST to allowed domain passes ────────

test("POST with clean body to allowed domain succeeds", async () => {
  const res = await fetch("https://httpbin.org/post", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: "this is totally fine" }),
  });
  assert(res.ok, `expected 200, got ${res.status}`);
});

run();
