"use strict";

/*
 * Unit tests verifying Node.js explicit offline guards.
 *
 * Ensures HTTP, HTTPS, HTTP/2, TCP, TLS, UDP, the entire DNS surface, and global
 * fetch/WebSocket are blocked locally without attempting any external network traffic,
 * while allowing fake fetch and DOM emulation inside VM contexts.
 *
 * Independent lower-layer sentinels stub native bindings underneath the preload so
 * any guard regression or omission fails the test safely without generating real traffic.
 */

const sentinelHits = [];
function sentinelThrow(name) {
  return function lowerSentinelBlocked(...args) {
    sentinelHits.push(name);
    throw new Error(`LOWER_SENTINEL_HIT: ${name}`);
  };
}

try {
  const tcp = process.binding("tcp_wrap");
  const proto = tcp.TCP?.prototype;
  if (proto) {
    for (const m of ["connect", "connect6", "bind", "bind6", "listen"]) {
      if (typeof proto[m] === "function") proto[m] = sentinelThrow(`tcp_wrap.TCP.${m}`);
    }
  }
} catch (_) {}

try {
  const udp = process.binding("udp_wrap");
  const proto = udp.UDP?.prototype;
  if (proto) {
    for (const m of ["connect", "connect6", "send", "send6", "bind", "bind6"]) {
      if (typeof proto[m] === "function") proto[m] = sentinelThrow(`udp_wrap.UDP.${m}`);
    }
  }
} catch (_) {}

try {
  const cares = process.binding("cares_wrap");
  for (const m of ["getaddrinfo", "getnameinfo"]) {
    if (typeof cares[m] === "function") cares[m] = sentinelThrow(`cares_wrap.${m}`);
  }
  const cproto = cares.ChannelWrap?.prototype;
  if (cproto) {
    for (const m of [
      "queryAny", "queryA", "queryAaaa", "queryCaa", "queryCname", "queryMx",
      "queryNs", "queryTxt", "querySrv", "queryPtr", "queryNaptr", "querySoa",
      "queryTlsa", "getHostByAddr",
    ]) {
      if (typeof cproto[m] === "function") cproto[m] = sentinelThrow(`cares_wrap.ChannelWrap.${m}`);
    }
  }
} catch (_) {}

const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const https = require("node:https");
let http2;
try {
  http2 = require("node:http2");
} catch (_) {}
const net = require("node:net");
const tls = require("node:tls");
const dgram = require("node:dgram");
const dns = require("node:dns");
const vm = require("node:vm");

test("node offline guard: http.request and http.get fail locally", () => {
  let r1, r2, r3;
  try {
    assert.throws(
      () => { r1 = http.request("http://192.0.2.1", { timeout: 20 }); },
      /Offline guard: http\.request is disabled in tests/
    );
    assert.throws(
      () => { r2 = http.get("http://192.0.2.1", { timeout: 20 }); },
      /Offline guard: http\.get is disabled in tests/
    );
    assert.throws(
      () => { r3 = new http.ClientRequest("http://192.0.2.1", { timeout: 20 }); },
      /Offline guard: http\.ClientRequest is disabled in tests/
    );
  } finally {
    if (r1 && typeof r1.destroy === "function") r1.destroy();
    if (r2 && typeof r2.destroy === "function") r2.destroy();
    if (r3 && typeof r3.destroy === "function") r3.destroy();
  }
});

test("node offline guard: https.request and https.get fail locally", () => {
  let r1, r2;
  try {
    assert.throws(
      () => { r1 = https.request("https://192.0.2.1", { timeout: 20 }); },
      /Offline guard: https\.request is disabled in tests/
    );
    assert.throws(
      () => { r2 = https.get("https://192.0.2.1", { timeout: 20 }); },
      /Offline guard: https\.get is disabled in tests/
    );
  } finally {
    if (r1 && typeof r1.destroy === "function") r1.destroy();
    if (r2 && typeof r2.destroy === "function") r2.destroy();
  }
});

test("node offline guard: http2.connect fails locally", () => {
  if (http2 && typeof http2.connect === "function") {
    assert.throws(
      () => http2.connect("https://192.0.2.1"),
      /Offline guard: http2\.connect is disabled in tests/
    );
  }
});

test("node offline guard: net.connect and net.Socket fail locally without network calls", () => {
  let s1, s2, s3;
  try {
    assert.throws(
      () => { s1 = net.connect({ host: "192.0.2.1", port: 80, timeout: 20 }); },
      /Offline guard: net\.connect is disabled in tests/
    );
    assert.throws(
      () => { s2 = net.createConnection({ host: "192.0.2.1", port: 80, timeout: 20 }); },
      /Offline guard: net\.createConnection is disabled in tests/
    );
    s3 = new net.Socket();
    assert.throws(
      () => { s3.connect({ host: "192.0.2.1", port: 80 }); },
      /Offline guard: net\.Socket\.prototype\.connect is disabled in tests/
    );
  } finally {
    if (s1 && typeof s1.destroy === "function") s1.destroy();
    if (s2 && typeof s2.destroy === "function") s2.destroy();
    if (s3 && typeof s3.destroy === "function") s3.destroy();
  }
});

test("node offline guard: tls.connect fails locally", () => {
  let s;
  try {
    assert.throws(
      () => { s = tls.connect({ host: "192.0.2.1", port: 443, timeout: 20 }); },
      /Offline guard: tls\.connect is disabled in tests/
    );
  } finally {
    if (s && typeof s.destroy === "function") s.destroy();
  }
});

test("node offline guard: dgram.createSocket fails locally", () => {
  let s;
  try {
    assert.throws(
      () => { s = dgram.createSocket("udp4"); },
      /Offline guard: dgram\.createSocket is disabled in tests/
    );
  } finally {
    if (s && typeof s.close === "function") s.close();
  }
});

test("node offline guard: dns.lookup and dns.resolve fail locally without resolution", () => {
  assert.throws(
    () => dns.lookup("example.invalid", () => {}),
    /Offline guard: dns\.lookup is disabled in tests/
  );
  assert.throws(
    () => dns.resolve("example.invalid", () => {}),
    /Offline guard: dns\.resolve is disabled in tests/
  );
  assert.throws(
    () => dns.resolve4("example.invalid", () => {}),
    /Offline guard: dns\.resolve4 is disabled in tests/
  );
  assert.throws(
    () => dns.resolve6("example.invalid", () => {}),
    /Offline guard: dns\.resolve6 is disabled in tests/
  );
  assert.throws(
    () => dns.lookupService("127.0.0.1", 80, () => {}),
    /Offline guard: dns\.lookupService is disabled in tests/
  );
});

test("node offline guard: standard DNS resolver APIs and Resolver instances fail locally", async () => {
  assert.throws(
    () => dns.resolveTxt("example.invalid", () => {}),
    /Offline guard: dns\.resolveTxt is disabled in tests/
  );
  assert.throws(
    () => dns.reverse("192.0.2.1", () => {}),
    /Offline guard: dns\.reverse is disabled in tests/
  );
  const resolver = new dns.Resolver();
  assert.throws(
    () => resolver.resolve4("example.invalid", () => {}),
    /Offline guard: dns\.Resolver\.prototype\.resolve4 is disabled in tests/
  );

  if (dns.promises) {
    assert.throws(
      () => dns.promises.lookup("example.invalid"),
      /Offline guard: dns\.promises\.lookup is disabled in tests/
    );
    assert.throws(
      () => dns.promises.resolveMx("example.invalid"),
      /Offline guard: dns\.promises\.resolveMx is disabled in tests/
    );
    if (dns.promises.Resolver) {
      const pResolver = new dns.promises.Resolver();
      assert.throws(
        () => pResolver.resolve4("example.invalid"),
        /Offline guard: dns\.promises\.Resolver\.prototype\.resolve4 is disabled in tests/
      );
    }
  }
});

test("node offline guard: every enumerable function on dns and dns.promises is wrapped", () => {
  for (const key of Object.keys(dns)) {
    if (key === "Resolver" || key === "promises") continue;
    if (typeof dns[key] === "function") {
      assert.equal(
        dns[key].name,
        "blockedOfflineTransport",
        `dns.${key} must be wrapped with offline guard`
      );
    }
  }
  if (dns.promises) {
    for (const key of Object.keys(dns.promises)) {
      if (key === "Resolver") continue;
      if (typeof dns.promises[key] === "function") {
        assert.equal(
          dns.promises[key].name,
          "blockedOfflineTransport",
          `dns.promises.${key} must be wrapped with offline guard`
        );
      }
    }
  }
  if (dns.Resolver && dns.Resolver.prototype) {
    for (const key of Object.getOwnPropertyNames(dns.Resolver.prototype)) {
      if (key === "constructor") continue;
      if (typeof dns.Resolver.prototype[key] === "function") {
        assert.equal(
          dns.Resolver.prototype[key].name,
          "blockedOfflineTransport",
          `dns.Resolver.prototype.${key} must be wrapped with offline guard`
        );
      }
    }
  }
  if (dns.promises && dns.promises.Resolver && dns.promises.Resolver.prototype) {
    for (const key of Object.getOwnPropertyNames(dns.promises.Resolver.prototype)) {
      if (key === "constructor") continue;
      if (typeof dns.promises.Resolver.prototype[key] === "function") {
        assert.equal(
          dns.promises.Resolver.prototype[key].name,
          "blockedOfflineTransport",
          `dns.promises.Resolver.prototype.${key} must be wrapped with offline guard`
        );
      }
    }
  }
});

test("node offline guard: globalThis.fetch fails locally", () => {
  assert.throws(
    () => fetch("https://192.0.2.1", { signal: AbortSignal.timeout(20) }),
    /Offline guard: globalThis\.fetch is disabled in tests/
  );
});

test("node offline guard: VM fake fetch/chrome/DOM contexts still work", () => {
  const sandbox = {
    fetch: (url) => ({ status: 200, url, mock: true }),
    chrome: { runtime: { id: "test-id" } },
    document: { createElement: () => ({}) },
    result: null,
  };
  const context = vm.createContext(sandbox);
  vm.runInContext("result = fetch('https://vm.mock.local')", context);
  assert.equal(sandbox.result.status, 200);
  assert.equal(sandbox.result.url, "https://vm.mock.local");
  assert.equal(sandbox.chrome.runtime.id, "test-id");
});

test("node offline guard: lower-layer sentinels were not hit during guarded run", () => {
  assert.equal(
    sentinelHits.length,
    0,
    `No lower sentinels should be reached when preload is active: ${sentinelHits.join(", ")}`
  );
});
