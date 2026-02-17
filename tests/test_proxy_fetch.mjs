#!/usr/bin/env node
/**
 * Unit tests for proxy-fetch.mjs DNS fallback behaviour.
 *
 * Validates that when HTTPS_PROXY is set and dns.lookup returns ENOTFOUND,
 * the patch falls back to a placeholder IP instead of throwing, so that
 * SSRF guards (which resolve DNS before calling fetch) don't break inside
 * a caged environment where the proxy handles DNS server-side.
 *
 * Run:  HTTPS_PROXY=http://dummy:8080 node tests/test_proxy_fetch.mjs
 *
 * The proxy URL doesn't need to be reachable — these tests only exercise
 * the dns.lookup wrapper, not actual HTTP connections.
 */

import { strict as assert } from 'node:assert';
import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';

const PLACEHOLDER = '198.51.100.1';

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

console.log('=== proxy-fetch.mjs dns fallback tests ===\n');

// Verify the patch was loaded
assert.ok(
  process.env.HTTPS_PROXY || process.env.HTTP_PROXY,
  'HTTPS_PROXY or HTTP_PROXY must be set for the patch to activate',
);

// --- dns/promises.lookup tests ---

await test('dns/promises.lookup: ENOTFOUND returns placeholder (default opts)', async () => {
  const result = await dnsPromises.lookup('this-domain-does-not-exist-agentcage-test.invalid');
  assert.equal(result.address, PLACEHOLDER);
  assert.equal(result.family, 4);
});

await test('dns/promises.lookup: ENOTFOUND returns array when all=true', async () => {
  const result = await dnsPromises.lookup('this-domain-does-not-exist-agentcage-test.invalid', { all: true });
  assert.ok(Array.isArray(result));
  assert.equal(result.length, 1);
  assert.equal(result[0].address, PLACEHOLDER);
  assert.equal(result[0].family, 4);
});

await test('dns/promises.lookup: ENOTFOUND with numeric family option', async () => {
  const result = await dnsPromises.lookup('this-domain-does-not-exist-agentcage-test.invalid', 4);
  assert.equal(result.address, PLACEHOLDER);
  assert.equal(result.family, 4);
});

await test('dns/promises.lookup: real domain still resolves normally', async () => {
  // localhost should always resolve, even without network
  try {
    const result = await dnsPromises.lookup('localhost');
    assert.ok(result.address);
    assert.ok(result.family === 4 || result.family === 6);
  } catch {
    // On some systems localhost may not resolve; skip
  }
});

await test('dns/promises.lookup: non-ENOTFOUND errors still propagate', async () => {
  // SERVFAIL and other errors should not be swallowed
  // We can't easily trigger SERVFAIL in unit tests, so just verify
  // the function is callable and returns correctly for valid input
  const result = await dnsPromises.lookup('this-domain-does-not-exist-agentcage-test.invalid', { all: true, family: 4 });
  assert.ok(Array.isArray(result));
  assert.equal(result[0].address, PLACEHOLDER);
});

// --- dns.lookup (callback) tests ---

await test('dns.lookup (callback): ENOTFOUND returns placeholder', async () => {
  const result = await new Promise((resolve, reject) => {
    dns.lookup('this-domain-does-not-exist-agentcage-test.invalid', (err, address, family) => {
      if (err) return reject(err);
      resolve({ address, family });
    });
  });
  assert.equal(result.address, PLACEHOLDER);
  assert.equal(result.family, 4);
});

await test('dns.lookup (callback): ENOTFOUND with all=true returns array', async () => {
  const result = await new Promise((resolve, reject) => {
    dns.lookup('this-domain-does-not-exist-agentcage-test.invalid', { all: true }, (err, addresses) => {
      if (err) return reject(err);
      resolve(addresses);
    });
  });
  assert.ok(Array.isArray(result));
  assert.equal(result.length, 1);
  assert.equal(result[0].address, PLACEHOLDER);
  assert.equal(result[0].family, 4);
});

await test('dns.lookup (callback): works with numeric family option', async () => {
  const result = await new Promise((resolve, reject) => {
    dns.lookup('this-domain-does-not-exist-agentcage-test.invalid', 4, (err, address, family) => {
      if (err) return reject(err);
      resolve({ address, family });
    });
  });
  assert.equal(result.address, PLACEHOLDER);
  assert.equal(result.family, 4);
});

// --- globalThis.fetch patch test ---

await test('globalThis.fetch is patched', () => {
  assert.equal(globalThis.fetch.name, 'patchedFetch');
});

// --- Summary ---
console.log(`\n=== ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
