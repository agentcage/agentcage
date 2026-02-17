#!/usr/bin/env node
/**
 * Unit tests for proxy-fetch.mjs fetch patching.
 *
 * Validates that when HTTPS_PROXY is set, globalThis.fetch is replaced
 * with a patched version that forces undici's EnvHttpProxyAgent dispatcher
 * on all fetch calls.
 *
 * Run:  HTTPS_PROXY=http://dummy:8080 node --import ./src/agentcage/data/patches/proxy-fetch.mjs tests/test_proxy_fetch.mjs
 *
 * The proxy URL doesn't need to be reachable — this test only exercises
 * the fetch wrapper, not actual HTTP connections.
 */

import { strict as assert } from 'node:assert';

let passed = 0;
let failed = 0;

async function test(label, fn) {
  try {
    await fn();
    console.log(`  PASS  ${label}`);
    passed++;
  } catch (err) {
    console.log(`  FAIL  ${label}`);
    console.log(`        ${err.message}`);
    failed++;
  }
}

console.log('=== proxy-fetch.mjs tests ===\n');

// Verify the patch was loaded
assert.ok(
  process.env.HTTPS_PROXY || process.env.HTTP_PROXY,
  'HTTPS_PROXY or HTTP_PROXY must be set for the patch to activate',
);

// --- globalThis.fetch patch test ---

await test('globalThis.fetch is patched', () => {
  assert.equal(globalThis.fetch.name, 'patchedFetch');
});

// --- Summary ---
console.log(`\n=== ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
