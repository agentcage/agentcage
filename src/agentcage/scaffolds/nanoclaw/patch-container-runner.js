// Patch NanoClaw's compiled container-runner.js for agentcage integration.
//
// 1. --network host: inner containers reach the cage proxy
// 2. Forward proxy/cert env vars to inner containers
// 3. Mount /certs and /agentcage volumes into inner containers
//
// This runs at image build time against dist/container-runner.js.

const fs = require('fs');
const path = require('path');

const file = path.join('/app', 'dist', 'container-runner.js');
let code = fs.readFileSync(file, 'utf8');

// 1. --network host: insert after ['run', '-i', '--rm'
//    Matches both single and double quotes from tsc output.
const networkPatched = code.replace(
  /(\[['"]run['"],\s*['"](?:-i)['"],\s*['"]--rm['"])/,
  "$1, '--network', 'host'"
);
if (networkPatched === code) {
  console.error("PATCH FAILED: could not find ['run', '-i', '--rm'] pattern");
  process.exit(1);
}
code = networkPatched;

// 2. Forward proxy/cert env vars after the TZ push.
//    Pattern: args.push('-e', `TZ=${TIMEZONE}`);
const envVarLines = [
  "    if (process.env.HTTP_PROXY) args.push('-e', 'HTTP_PROXY=' + process.env.HTTP_PROXY);",
  "    if (process.env.HTTPS_PROXY) args.push('-e', 'HTTPS_PROXY=' + process.env.HTTPS_PROXY);",
  "    if (process.env.NODE_EXTRA_CA_CERTS) args.push('-e', 'NODE_EXTRA_CA_CERTS=' + process.env.NODE_EXTRA_CA_CERTS);",
  "    if (process.env.SSL_CERT_FILE) args.push('-e', 'SSL_CERT_FILE=' + process.env.SSL_CERT_FILE);",
  "    if (process.env.NODE_OPTIONS) args.push('-e', 'NODE_OPTIONS=' + process.env.NODE_OPTIONS);",
].join('\n');

const tzPattern = /(args\.push\(['"](?:-e)['"],\s*`TZ=\$\{TIMEZONE\}`\);)/;
const envPatched = code.replace(tzPattern, '$1\n' + envVarLines);
if (envPatched === code) {
  console.error("PATCH FAILED: could not find TZ push pattern");
  process.exit(1);
}
code = envPatched;

// 3. Mount /certs and /agentcage volumes before CONTAINER_IMAGE push.
const mountLines = [
  "    args.push('-v', '/certs:/certs:ro');",
  "    args.push('-v', '/agentcage:/agentcage:ro');",
].join('\n');

const imagePattern = /(args\.push\(CONTAINER_IMAGE\))/;
const mountPatched = code.replace(imagePattern, mountLines + '\n    $1');
if (mountPatched === code) {
  console.error("PATCH FAILED: could not find CONTAINER_IMAGE push pattern");
  process.exit(1);
}
code = mountPatched;

fs.writeFileSync(file, code);
console.log('Patched dist/container-runner.js for agentcage');
