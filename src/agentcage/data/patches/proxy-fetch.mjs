import { createRequire } from 'node:module';
import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';

const proxyUrl = process.env.HTTPS_PROXY || process.env.https_proxy ||
                 process.env.HTTP_PROXY  || process.env.http_proxy;

if (proxyUrl) {
  // Resolve undici from the agentcage patches directory (mounted at /agentcage/)
  const require = createRequire(import.meta.url);
  const { EnvHttpProxyAgent } = require('undici');
  const proxyAgent = new EnvHttpProxyAgent();
  const origFetch = globalThis.fetch;

  // --- Patch globalThis.fetch ---
  // Force all fetch() calls through the HTTP proxy, even when callers
  // supply their own undici Agent dispatcher (e.g. for DNS-pinned SSRF
  // guards).  The proxy resolves DNS server-side, so the pinned IP is
  // unused.
  globalThis.fetch = function patchedFetch(input, init) {
    if (!init?.dispatcher || init.dispatcher.constructor?.name === 'Agent') {
      return origFetch.call(this, input, { ...init, dispatcher: proxyAgent });
    }
    return origFetch.call(this, input, init);
  };

  // --- Patch dns.lookup / dns/promises.lookup ---
  // Some frameworks (e.g. OpenClaw's SSRF guard) resolve DNS *before*
  // calling fetch().  Inside the cage, dnsmasq may not resolve every
  // allowed domain (e.g. when the first upstream DNS is Tailscale
  // MagicDNS).  Since all connections are routed through the proxy —
  // which resolves DNS itself — a local lookup failure is non-fatal.
  //
  // Strategy: wrap the lookup functions so that ENOTFOUND errors fall
  // back to a documentation-range placeholder IP (RFC 5737, TEST-NET-2:
  // 198.51.100.1).  The IP is never actually connected to because the
  // fetch patch above always routes through the proxy agent.

  const PLACEHOLDER_IPV4 = '198.51.100.1';

  // Wrap dns/promises.lookup (async version used by most modern code)
  const origLookup = dnsPromises.lookup;
  dnsPromises.lookup = async function patchedLookup(hostname, options) {
    try {
      return await origLookup.call(this, hostname, options);
    } catch (err) {
      if (err?.code === 'ENOTFOUND') {
        const opts = typeof options === 'number'
          ? { family: options }
          : (options ?? {});
        if (opts.all) {
          return [{ address: PLACEHOLDER_IPV4, family: 4 }];
        }
        return { address: PLACEHOLDER_IPV4, family: 4 };
      }
      throw err;
    }
  };

  // Wrap dns.lookup (callback version, used by undici/Node internals)
  const origLookupCb = dns.lookup;
  dns.lookup = function patchedLookupCb(hostname, options, callback) {
    const cb = typeof options === 'function' ? options : callback;
    const opts = typeof options === 'function' ? {} : options;

    const wrappedCb = (err, address, family) => {
      if (err?.code === 'ENOTFOUND') {
        const o = typeof opts === 'number' ? { family: opts } : (opts ?? {});
        if (o.all) {
          return cb(null, [{ address: PLACEHOLDER_IPV4, family: 4 }]);
        }
        return cb(null, PLACEHOLDER_IPV4, 4);
      }
      return cb(err, address, family);
    };

    if (typeof options === 'function') {
      return origLookupCb.call(this, hostname, wrappedCb);
    }
    return origLookupCb.call(this, hostname, options, wrappedCb);
  };
}
