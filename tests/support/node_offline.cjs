"use strict";

/*
 * Explicit offline transport preload for Node.js test suites.
 *
 * Denies outbound network operations across HTTP, HTTPS, HTTP/2, raw TCP, TLS,
 * UDP, the entire DNS surface (callback, promise, and Resolver instances), and
 * global fetch / WebSocket to ensure all tests run hermetically offline.
 * Fake fetch and DOM mocks created inside VM contexts remain unaffected.
 */

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

function block(apiName) {
  return function blockedOfflineTransport(...args) {
    throw new Error(`Offline guard: ${apiName} is disabled in tests`);
  };
}

// 1. HTTP and HTTPS client transport
http.request = block("http.request");
http.get = block("http.get");
https.request = block("https.request");
https.get = block("https.get");

const origClientRequest = http.ClientRequest;
http.ClientRequest = function BlockedClientRequest(...args) {
  throw new Error("Offline guard: http.ClientRequest is disabled in tests");
};
http.ClientRequest.prototype = origClientRequest.prototype;

// 2. HTTP/2 client transport
if (http2 && typeof http2.connect === "function") {
  http2.connect = block("http2.connect");
}

// 3. Raw TCP socket connections
net.connect = block("net.connect");
net.createConnection = block("net.createConnection");
net.Socket.prototype.connect = block("net.Socket.prototype.connect");

// 4. TLS transport
tls.connect = block("tls.connect");
tls.TLSSocket.prototype.connect = block("tls.TLSSocket.prototype.connect");

// 5. UDP transport
dgram.createSocket = block("dgram.createSocket");
dgram.Socket.prototype.send = block("dgram.Socket.prototype.send");
dgram.Socket.prototype.bind = block("dgram.Socket.prototype.bind");
dgram.Socket.prototype.connect = block("dgram.Socket.prototype.connect");

// 6. Deny the whole DNS surface (callback and promise variants, plus Resolver prototypes)
// Enumerate all function properties on dns
for (const key of Object.keys(dns)) {
  if (key === "Resolver" || key === "promises") continue;
  if (typeof dns[key] === "function") {
    dns[key] = block(`dns.${key}`);
  }
}

// Enumerate all function properties on dns.promises
if (dns.promises) {
  for (const key of Object.keys(dns.promises)) {
    if (key === "Resolver") continue;
    if (typeof dns.promises[key] === "function") {
      dns.promises[key] = block(`dns.promises.${key}`);
    }
  }
}

// Patch Resolver prototype instance methods
if (dns.Resolver && dns.Resolver.prototype) {
  for (const key of Object.getOwnPropertyNames(dns.Resolver.prototype)) {
    if (key === "constructor") continue;
    if (typeof dns.Resolver.prototype[key] === "function") {
      dns.Resolver.prototype[key] = block(`dns.Resolver.prototype.${key}`);
    }
  }
}

// Patch promises.Resolver prototype instance methods
if (dns.promises && dns.promises.Resolver && dns.promises.Resolver.prototype) {
  for (const key of Object.getOwnPropertyNames(dns.promises.Resolver.prototype)) {
    if (key === "constructor") continue;
    if (typeof dns.promises.Resolver.prototype[key] === "function") {
      dns.promises.Resolver.prototype[key] = block(`dns.promises.Resolver.prototype.${key}`);
    }
  }
}

// 7. Global fetch and WebSocket
if (typeof globalThis.fetch === "function") {
  globalThis.fetch = block("globalThis.fetch");
}
if (typeof globalThis.WebSocket === "function") {
  globalThis.WebSocket = function BlockedWebSocket(...args) {
    throw new Error("Offline guard: WebSocket is disabled in tests");
  };
}
