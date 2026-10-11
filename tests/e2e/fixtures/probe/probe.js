// In-cage client for the egress-feature e2e phase (phase9_egress_features.sh).
//
// Mounted read-only into the test cage at /probe and run with
// `agentcage cage exec <cage> -- node /probe/probe.js <command> ...`.
// Node built-ins only (node:22-slim has no curl and no python). Every
// command prints ONE line of JSON on stdout so the shell side can pick
// fields out with grep.
//
// A host argument of "egress" means the egress's address on the cage
// network, taken from $HTTPS_PROXY (http://<egress>:8080) — where the
// protocol relays listen.

"use strict";

const net = require("net");
const tls = require("tls");
const http = require("http");

function out(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

function egressHost(host) {
  if (host !== "egress") return host;
  return new URL(process.env.HTTPS_PROXY || process.env.HTTP_PROXY).hostname;
}

// A line-oriented TCP session: `expect(re)` resolves with everything
// received up to and including the first match of `re`.
function session(host, port) {
  const sock = net.connect({ host: egressHost(host), port: Number(port) });
  let buf = "";
  let waiter = null;
  let closed = false;
  const check = () => {
    if (!waiter) return;
    const m = waiter.re.exec(buf);
    if (m) {
      const end = m.index + m[0].length;
      const got = buf.slice(0, end);
      buf = buf.slice(end);
      const w = waiter;
      waiter = null;
      w.resolve(got);
    } else if (closed) {
      const w = waiter;
      waiter = null;
      w.resolve(buf + "<closed>");
      buf = "";
    }
  };
  sock.setEncoding("utf8");
  sock.on("data", (d) => { buf += d; check(); });
  sock.on("close", () => { closed = true; check(); });
  sock.on("error", (e) => { buf += `<error ${e.message}>`; closed = true; check(); });
  return {
    sock,
    send: (s) => sock.write(s),
    expect: (re, ms = 10000) => new Promise((resolve) => {
      const t = setTimeout(() => {
        waiter = null;
        resolve(buf + "<timeout>");
        buf = "";
      }, ms);
      waiter = { re, resolve: (v) => { clearTimeout(t); resolve(v); } };
      check();
    }),
  };
}

// imap HOST PORT CMD...  — greeting, then each command tagged a1, a2, ...
async function imap(host, port, ...cmds) {
  const s = session(host, port);
  const greeting = await s.expect(/\r\n/);
  const responses = [];
  for (let i = 0; i < cmds.length; i++) {
    const tag = `a${i + 1}`;
    s.send(`${tag} ${cmds[i]}\r\n`);
    responses.push(await s.expect(new RegExp(`(^|\\r\\n)${tag} (OK|NO|BAD)[^\\r\\n]*\\r\\n`)));
  }
  s.sock.destroy();
  out({ greeting, responses });
}

// smtp HOST PORT FROM TO[,TO...] BODY [abort]
//   One transaction. With "abort" the connection is dropped half way
//   through DATA, after part of the body and before the final ".".
async function smtp(host, port, from, tos, body, mode) {
  const s = session(host, port);
  const reply = () => s.expect(/(^|\r\n)\d{3} [^\r\n]*\r\n/);
  const replies = {};
  replies.greeting = await reply();
  s.send("EHLO probe\r\n");
  replies.ehlo = await reply();
  s.send(`MAIL FROM:<${from}>\r\n`);
  replies.mail = await reply();
  replies.rcpt = [];
  for (const to of tos.split(",")) {
    s.send(`RCPT TO:<${to}>\r\n`);
    replies.rcpt.push(await reply());
  }
  s.send("DATA\r\n");
  replies.data = await reply();
  if (replies.data.startsWith("354")) {
    const msg = `From: <${from}>\r\nTo: <${tos}>\r\nSubject: e2e\r\n\r\n${body}\r\n`;
    if (mode === "abort") {
      s.send(msg);
      await new Promise((r) => setTimeout(r, 500));
      s.sock.destroy();
      out(replies);
      return;
    }
    s.send(msg + ".\r\n");
    replies.end = await reply();
  }
  s.send("QUIT\r\n");
  replies.quit = await reply();
  s.sock.destroy();
  out(replies);
}

// ws URL MESSAGE — open, send one text message, print the first reply.
async function ws(url, message) {
  const sock = new WebSocket(url);
  const result = await new Promise((resolve) => {
    const t = setTimeout(() => resolve({ error: "timeout" }), 15000);
    sock.onopen = () => sock.send(message);
    sock.onmessage = (ev) => { clearTimeout(t); resolve({ reply: String(ev.data) }); };
    sock.onerror = (ev) => { clearTimeout(t); resolve({ error: String(ev.message || ev.type) }); };
  });
  try { sock.close(); } catch (_) { /* already gone */ }
  out(result);
}

// tls-peer HOST PORT SNI — the certificate the cage is shown.
function tlsPeer(host, port, sni) {
  const sock = tls.connect({
    host: egressHost(host), port: Number(port), servername: sni,
    rejectUnauthorized: false, ALPNProtocols: ["http/1.1"],
  });
  const t = setTimeout(() => { out({ error: "timeout" }); sock.destroy(); }, 15000);
  sock.on("secureConnect", () => {
    clearTimeout(t);
    const c = sock.getPeerCertificate();
    out({
      subject: (c.subject && c.subject.CN) || "",
      issuer: (c.issuer && c.issuer.CN) || "",
      issuerO: (c.issuer && c.issuer.O) || "",
    });
    sock.destroy();
  });
  sock.on("error", (e) => { clearTimeout(t); out({ error: e.message }); });
}

// http-raw HOST PORT HOST_HEADER PATH — a plain HTTP GET to an address,
// with a Host header naming something else (no DNS involved).
function httpRaw(host, port, hostHeader, path) {
  const req = http.request({
    host: egressHost(host), port: Number(port), path, method: "GET",
    headers: { Host: hostHeader }, timeout: 15000,
  }, (res) => {
    let body = "";
    res.setEncoding("utf8");
    res.on("data", (d) => { body += d; });
    res.on("end", () => out({ status: res.statusCode, body }));
  });
  req.on("timeout", () => { req.destroy(new Error("timeout")); });
  req.on("error", (e) => out({ error: e.message }));
  req.end();
}

// api METHOD PATH [JSON] — the Policy API at https://agentcage.local.
async function api(method, path, json) {
  try {
    const res = await fetch(`https://agentcage.local${path}`, {
      method,
      headers: json ? { "Content-Type": "application/json" } : {},
      body: json || undefined,
      signal: AbortSignal.timeout(30000),
    });
    out({ status: res.status, body: await res.text() });
  } catch (e) {
    out({ error: String(e.cause ? e.cause.message || e.cause : e.message) });
  }
}

// get URL — status and body of a plain fetch.
async function get(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    out({ status: res.status, body: (await res.text()).slice(0, 512) });
  } catch (e) {
    out({ error: String(e.cause ? e.cause.message || e.cause : e.message) });
  }
}

const [cmd, ...args] = process.argv.slice(2);
const commands = {
  imap, smtp, ws, "tls-peer": tlsPeer, "http-raw": httpRaw, api, get,
};
if (!commands[cmd]) {
  out({ error: `unknown command ${cmd}` });
  process.exit(2);
}
Promise.resolve(commands[cmd](...args)).catch((e) => out({ error: String(e) }));
