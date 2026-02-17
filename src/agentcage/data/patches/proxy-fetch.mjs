import { createRequire } from 'node:module';

const proxyUrl = process.env.HTTPS_PROXY || process.env.https_proxy ||
                 process.env.HTTP_PROXY  || process.env.http_proxy;

if (proxyUrl) {
  // Resolve undici from the agentcage patches directory (mounted at /agentcage/)
  const require = createRequire(import.meta.url);
  const { EnvHttpProxyAgent } = require('undici');
  const proxyAgent = new EnvHttpProxyAgent();
  const origFetch = globalThis.fetch;

  globalThis.fetch = function patchedFetch(input, init) {
    if (!init?.dispatcher || init.dispatcher.constructor?.name === 'Agent') {
      return origFetch.call(this, input, { ...init, dispatcher: proxyAgent });
    }
    return origFetch.call(this, input, init);
  };
}
