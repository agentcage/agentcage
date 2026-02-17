import { createRequire } from 'node:module';

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
}
