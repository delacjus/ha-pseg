"use strict";

/*
 * Unit tests for custom_components/pseg/frontend/pseg-captcha-helper.js.
 *
 * The helper runs inside a vm context with a minimal fake DOM, fake timers and
 * fake clipboard. Fixtures are synthetic: no real credential, cookie, CAPTCHA
 * response or network call is used anywhere here.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SOURCE = fs.readFileSync(
  path.join(__dirname, "..", "custom_components", "pseg", "frontend", "pseg-captcha-helper.js"),
  "utf8"
);

const SITE_ORIGIN = "https://mysmartenergy.nj.pseg.com";
const PROOF_SELECTOR = 'textarea[name="g-recaptcha-response"]';
const HOST_ID = "pseg-captcha-helper-panel";
const MARKER = "__psegCaptchaHelperV1";
const FIXTURE_PROOF = "FIXTURE_ONLY_proof_9f3a7c_not_a_real_recaptcha_token";
const OTHER_PROOF = "FIXTURE_ONLY_proof_second_2b81d0_not_real";

/* ------------------------------------------------------------------ fake DOM */

class FakeElement {
  constructor(doc, tag) {
    this.ownerDocument = doc;
    this.tagName = String(tag).toUpperCase();
    this.children = [];
    this.parentNode = null;
    this.style = {};
    this.attributes = {};
    this.listeners = {};
    this.textContent = "";
    this.value = "";
    this.id = "";
    this.type = "";
    this.disabled = false;
  }

  appendChild(child) {
    child.parentNode = this;
    this.children.push(child);
    return child;
  }

  removeChild(child) {
    const index = this.children.indexOf(child);
    if (index >= 0) {
      this.children.splice(index, 1);
      child.parentNode = null;
    }
    return child;
  }

  remove() {
    if (this.parentNode) {
      this.parentNode.removeChild(this);
    }
  }

  setAttribute(name, value) {
    this.attributes[name] = String(value);
    if (name === "id") {
      this.id = String(value);
    }
  }

  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }

  removeAttribute(name) {
    delete this.attributes[name];
  }

  addEventListener(type, handler) {
    if (!this.listeners[type]) {
      this.listeners[type] = [];
    }
    this.listeners[type].push(handler);
  }

  removeEventListener(type, handler) {
    const handlers = this.listeners[type];
    if (!handlers) {
      return;
    }
    const index = handlers.indexOf(handler);
    if (index >= 0) {
      handlers.splice(index, 1);
    }
  }

  dispatchEvent(event) {
    const evt = event || { type: "event" };
    evt.target = this;
    if (typeof evt.preventDefault !== "function") {
      evt.preventDefault = function () {};
    }
    const handlers = [...(this.listeners[evt.type] || [])];
    for (const handler of handlers) {
      handler.call(this, evt);
    }
    return true;
  }

  click() {
    return this.dispatchEvent({ type: "click" });
  }

  select() {}
}

function findElement(root, predicate) {
  if (!root) {
    return null;
  }
  if (predicate(root)) {
    return root;
  }
  for (const child of root.children) {
    const found = findElement(child, predicate);
    if (found) {
      return found;
    }
  }
  return null;
}

function makeDocument() {
  const doc = {};
  doc.documentElement = new FakeElement(doc, "html");
  doc.head = new FakeElement(doc, "head");
  doc.body = new FakeElement(doc, "body");
  doc.documentElement.appendChild(doc.head);
  doc.documentElement.appendChild(doc.body);
  doc.querySelectorCalls = [];
  doc.createElement = (tag) => new FakeElement(doc, tag);
  doc.createTextNode = (text) => {
    const node = new FakeElement(doc, "#text");
    node.textContent = String(text);
    return node;
  };
  doc.querySelector = (selector) => {
    doc.querySelectorCalls.push(selector);
    return selector === PROOF_SELECTOR ? doc._proof : null;
  };
  doc.getElementById = (id) => findElement(doc.documentElement, (node) => node.id === id);
  doc.addEventListener = () => {};
  doc.removeEventListener = () => {};
  doc.execCommand = undefined;
  doc.cookie = "";

  doc._proof = doc.createElement("textarea");
  doc._proof.setAttribute("name", "g-recaptcha-response");
  doc._proof.value = "";
  doc.body.appendChild(doc._proof);
  return doc;
}

/* ---------------------------------------------------------------- fake clock */

function createClock(start) {
  let now = start;
  let nextId = 1;
  const timers = new Map();

  function schedule(fn, ms, repeat) {
    const id = nextId++;
    timers.set(id, {
      fn,
      at: now + Math.max(0, Number(ms) || 0),
      repeat: repeat ? Math.max(1, Number(ms) || 1) : 0,
    });
    return id;
  }

  function advance(ms) {
    const target = now + Math.max(0, Number(ms) || 0);
    for (let guard = 0; guard < 100000; guard += 1) {
      let dueId = null;
      let due = null;
      for (const [id, timer] of timers) {
        if (timer.at > target) {
          continue;
        }
        if (!due || timer.at < due.at || (timer.at === due.at && id < dueId)) {
          due = timer;
          dueId = id;
        }
      }
      if (!due) {
        break;
      }
      now = due.at;
      if (due.repeat) {
        due.at = now + due.repeat;
      } else {
        timers.delete(dueId);
      }
      due.fn();
    }
    now = target;
  }

  return {
    now: () => now,
    setTimeout: (fn, ms) => schedule(fn, ms, false),
    setInterval: (fn, ms) => schedule(fn, ms, true),
    clearTimeout: (id) => timers.delete(id),
    clearInterval: (id) => timers.delete(id),
    pending: () => timers.size,
    advance,
  };
}

/* --------------------------------------------------------------- environment */

function makeProcessAjax() {
  const fn = function processAjaxMock() {
    fn.calls.push({
      args: Array.prototype.slice.call(arguments),
      receiver: this,
    });
    return fn.returnValue;
  };
  fn.calls = [];
  fn.returnValue = { from: "original-processAjax" };
  return fn;
}

function createEnv(options = {}) {
  const timers = createClock(options.now || 1000000);
  const doc = makeDocument();
  const listeners = {};
  const alerts = [];
  const consoleCalls = [];
  const clipboardWrites = [];
  const original = makeProcessAjax();
  let sourceRuns = 0;

  let clipboard = null;
  if (options.clipboard === null) {
    clipboard = null;
  } else if (options.clipboard) {
    clipboard = options.clipboard;
  } else {
    clipboard = {
      writeText(value) {
        clipboardWrites.push(value);
        return Promise.resolve();
      },
    };
  }

  const sandbox = {
    document: doc,
    navigator: clipboard ? { clipboard } : {},
    URL,
    Math,
    Date: { now: () => timers.now() },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout,
    setInterval: timers.setInterval,
    clearInterval: timers.clearInterval,
    alert: (message) => alerts.push(String(message)),
    console: {
      log: (...args) => consoleCalls.push(["log", args]),
      warn: (...args) => consoleCalls.push(["warn", args]),
      error: (...args) => consoleCalls.push(["error", args]),
      info: (...args) => consoleCalls.push(["info", args]),
      debug: (...args) => consoleCalls.push(["debug", args]),
    },
    location: {
      origin: options.origin || SITE_ORIGIN,
      protocol: `${(options.origin || SITE_ORIGIN).split(":")[0]}:`,
      host: (options.origin || SITE_ORIGIN).replace(/^https?:\/\//, ""),
    },
    addEventListener(type, handler) {
      if (!listeners[type]) {
        listeners[type] = [];
      }
      listeners[type].push(handler);
    },
    removeEventListener(type, handler) {
      const handlers = listeners[type];
      if (!handlers) {
        return;
      }
      const index = handlers.indexOf(handler);
      if (index >= 0) {
        handlers.splice(index, 1);
      }
    },
    dispatchEvent(event) {
      const evt = event || {};
      for (const handler of [...(listeners[evt.type] || [])]) {
        handler(evt);
      }
      return true;
    },
  };

  if (options.hasProcessAjax !== false) {
    sandbox.processAjax = original;
  }
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);

  function run() {
    sourceRuns += 1;
    vm.runInContext(SOURCE, sandbox, { filename: "pseg-captcha-helper.js" });
  }

  return {
    sandbox,
    doc,
    timers,
    original,
    alerts,
    consoleCalls,
    clipboardWrites,
    listeners,
    get sourceRuns() {
      return sourceRuns;
    },
    setClipboard(next) {
      sandbox.navigator.clipboard = next;
    },
    setProof(value) {
      doc._proof.value = value;
    },
    run,
    findHost() {
      return doc.getElementById(HOST_ID);
    },
    hostCount() {
      return doc.body.children.filter((child) => child.id === HOST_ID).length;
    },
  };
}

/* ------------------------------------------------------------------- helpers */

function settle() {
  return new Promise((resolve) => setImmediate(resolve));
}

async function clickAndSettle(element) {
  element.click();
  await settle();
  await settle();
}

function treeText(node) {
  if (!node) {
    return "";
  }
  let text = typeof node.textContent === "string" ? node.textContent : "";
  for (const child of node.children) {
    text += "\n" + treeText(child);
  }
  return text;
}

function treeAttributeValues(node) {
  if (!node) {
    return [];
  }
  const values = [];
  if (node.id) {
    values.push(String(node.id));
  }
  if (node.value) {
    values.push(String(node.value));
  }
  for (const styleValue of Object.values(node.style || {})) {
    values.push(String(styleValue));
  }
  for (const [name, value] of Object.entries(node.attributes || {})) {
    values.push(String(name), String(value));
  }
  for (const child of node.children) {
    values.push(...treeAttributeValues(child));
  }
  return values;
}

function findButton(root, label) {
  return findElement(
    root,
    (node) => node.tagName === "BUTTON" && node.textContent === label
  );
}

function assertPanelHidesProof(host, proof) {
  assert.ok(host, "helper panel is present");
  assert.ok(!treeText(host).includes(proof), "panel text does not expose the proof");
  assert.ok(
    !treeAttributeValues(host).some((value) => value.includes(proof)),
    "panel attributes/styles do not expose the proof"
  );
}

function loginOptions() {
  return { url: "/Home/Login" };
}

// A clipboard promise the test settles by hand, standing in for a platform
// write that is still in flight while the helper is closed or expires.
function deferred() {
  const box = {};
  box.promise = new Promise((resolve, reject) => {
    box.resolve = resolve;
    box.reject = reject;
  });
  return box;
}

async function flush() {
  await settle();
  await settle();
}

function clickCopy(env) {
  const button = findButton(env.findHost(), "Copy verification");
  assert.ok(button, "copy button is present");
  button.click();
}

/* --------------------------------------------------------------------- tests */

test("source survives bookmarklet URL-encoding unchanged", () => {
  assert.equal(decodeURIComponent(encodeURIComponent(SOURCE)), SOURCE);
  assert.match(SOURCE, /^\/\*/);
});

test("wrong origin: refuses, installs nothing, and does not wrap processAjax", () => {
  const env = createEnv({ origin: "https://evil.example" });
  env.run();

  assert.equal(env.sandbox.processAjax, env.original);
  assert.equal(env.findHost(), null);
  assert.equal(env.alerts.length, 1);
  assert.match(env.alerts[0], /only runs on https:\/\/mysmartenergy\.nj\.pseg\.com/);
});

test("install is idempotent: one wrapper, one panel, one pagehide listener", () => {
  const env = createEnv();
  env.run();
  const firstWrapper = env.sandbox.processAjax;
  assert.notEqual(firstWrapper, env.original);

  env.run();

  assert.equal(env.sandbox.processAjax, firstWrapper);
  assert.equal(env.hostCount(), 1);
  assert.equal((env.listeners.pagehide || []).length, 1);
  assert.equal(env.sourceRuns, 2);

  // A second run while a proof is held must not reset or lose it.
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());
  env.run();

  assert.equal(env.sandbox.processAjax, firstWrapper);
  assert.match(treeText(env.findHost()), /Verification captured/);
  assert.equal(findButton(env.findHost(), "Copy verification").disabled, false);
});

test("panel is labelled and exposes an accessible live status", () => {
  const env = createEnv();
  env.run();

  const host = env.findHost();
  assert.equal(host.getAttribute("role"), "dialog");
  assert.equal(host.getAttribute("aria-modal"), "false");
  const labelId = host.getAttribute("aria-labelledby");
  const describedBy = host.getAttribute("aria-describedby");
  assert.ok(labelId && describedBy);
  assert.match(treeText(env.doc.getElementById(labelId)), /PSE&G verification helper/);

  const status = env.doc.getElementById("pseg-captcha-helper-panel-status");
  assert.ok(describedBy.split(" ").includes(status.id));
  assert.equal(status.getAttribute("role"), "status");
  assert.equal(status.getAttribute("aria-live"), "polite");

  const copy = findButton(host, "Copy verification");
  assert.equal(copy.type, "button");
  assert.equal(copy.disabled, true);
  assert.equal(findButton(host, "Close helper").type, "button");
});

test("exact same-origin /Home/Login only; unrelated AJAX delegates unchanged", () => {
  const env = createEnv();
  env.run();

  const receiver = { kind: "jquery-receiver" };
  const unrelated = [
    "/Dashboard/GetChartData",
    "/home/login",
    "/Home/Login/",
    "/Home/LoginData",
    "/Home/Logout",
    "https://evil.example/Home/Login",
    "//evil.example/Home/Login",
    "https://mysmartenergy.nj.pseg.com.evil.example/Home/Login",
  ];

  for (const url of unrelated) {
    const options = { url, data: "ignored" };
    const result = env.sandbox.processAjax.call(receiver, options);
    assert.equal(result, env.original.returnValue, `return value preserved for ${url}`);
  }

  assert.equal(env.original.calls.length, unrelated.length);
  for (const call of env.original.calls) {
    assert.equal(call.receiver, receiver, "receiver preserved");
    assert.equal(call.args.length, 1);
  }
  assert.match(treeText(env.findHost()), /Ready\./);
});

test("captures manual proof, blocks the site login, never calls it", () => {
  const env = createEnv();
  env.run();
  env.setProof(FIXTURE_PROOF);

  const options = { url: "/Home/Login", data: "not-read" };
  const result = env.sandbox.processAjax(options);

  assert.equal(result, undefined);
  assert.equal(env.original.calls.length, 0, "original login request must not run");
  assert.equal(env.doc._proof.value, FIXTURE_PROOF, "site textarea is left untouched");

  const host = env.findHost();
  assert.match(treeText(host), /Verification captured/);
  assertPanelHidesProof(host, FIXTURE_PROOF);
  assert.deepEqual(env.clipboardWrites, [], "capture alone never copies");

  const copyButton = findButton(host, "Copy verification");
  assert.ok(copyButton);
  assert.equal(copyButton.disabled, false);
});

test("accepts the same-origin absolute login URL and blocks it", () => {
  const env = createEnv();
  env.run();
  env.setProof(FIXTURE_PROOF);

  env.sandbox.processAjax({
    url: "https://mysmartenergy.nj.pseg.com/Home/Login",
  });

  assert.equal(env.original.calls.length, 0);
  assert.match(treeText(env.findHost()), /Verification captured/);
});

test("missing proof: login is blocked with instructions, not submitted", () => {
  const env = createEnv();
  env.run();
  env.setProof("");

  env.sandbox.processAjax(loginOptions());

  assert.equal(env.original.calls.length, 0);
  const host = env.findHost();
  assert.match(treeText(host), /no verification response/);
  assert.match(treeText(host), /nothing was sent to PSE&G/i);
  assert.equal(findButton(host, "Copy verification").disabled, true);
});

test("never reads credentials, cookies, data or other option fields", () => {
  const env = createEnv();
  env.run();
  env.setProof(FIXTURE_PROOF);

  let dataReads = 0;
  let successReads = 0;
  let cookieReads = 0;
  let passwordReads = 0;

  Object.defineProperty(env.doc, "cookie", {
    configurable: true,
    get() {
      cookieReads += 1;
      throw new Error("helper must not read cookies");
    },
  });

  const passwordInput = env.doc.createElement("input");
  passwordInput.setAttribute("type", "password");
  Object.defineProperty(passwordInput, "value", {
    get() {
      passwordReads += 1;
      throw new Error("helper must not read credentials");
    },
  });
  env.doc.body.appendChild(passwordInput);

  const options = { url: "/Home/Login" };
  Object.defineProperty(options, "data", {
    get() {
      dataReads += 1;
      throw new Error("helper must not read serialized form data");
    },
  });
  Object.defineProperty(options, "success", {
    get() {
      successReads += 1;
      throw new Error("helper must not read callbacks");
    },
  });

  assert.doesNotThrow(() => env.sandbox.processAjax(options));
  assert.equal(dataReads, 0);
  assert.equal(successReads, 0);
  assert.equal(cookieReads, 0);
  assert.equal(passwordReads, 0);
  assert.equal(env.original.calls.length, 0);
  assert.deepEqual(
    [...new Set(env.doc.querySelectorCalls)],
    [PROOF_SELECTOR],
    "only the reCAPTCHA textarea is queried"
  );
});

test("copy is explicit, uses the clipboard, and reports success", async () => {
  const env = createEnv();
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());

  await clickAndSettle(findButton(env.findHost(), "Copy verification"));

  assert.deepEqual(env.clipboardWrites, [FIXTURE_PROOF]);
  assert.match(treeText(env.findHost()), /Copied\./);
  assertPanelHidesProof(env.findHost(), FIXTURE_PROOF);
});

test("copy rejection falls back without rendering the proof", async () => {
  const env = createEnv({
    clipboard: {
      writeText() {
        return Promise.reject(new Error("clipboard denied"));
      },
    },
  });
  env.doc.execCommand = () => false;
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());

  await clickAndSettle(findButton(env.findHost(), "Copy verification"));

  const host = env.findHost();
  assert.match(treeText(host), /Copy was blocked by the browser/);
  assert.equal(findButton(host, "Copy verification").disabled, false);
  assertPanelHidesProof(host, FIXTURE_PROOF);
  assert.ok(!env.doc.body.children.some((child) => treeText(child).includes(FIXTURE_PROOF)));

  env.setClipboard({
    writeText(value) {
      env.clipboardWrites.push(value);
      return Promise.resolve();
    },
  });
  await clickAndSettle(findButton(host, "Copy verification"));
  assert.deepEqual(env.clipboardWrites, [FIXTURE_PROOF]);
  assert.match(treeText(host), /Copied/);
});

test("execCommand fallback succeeds and removes the temporary field", async () => {
  let execCalls = 0;
  const env = createEnv({
    clipboard: {
      writeText() {
        return Promise.reject(new Error("clipboard denied"));
      },
    },
  });
  env.doc.execCommand = (command) => {
    execCalls += 1;
    return command === "copy";
  };
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());

  await clickAndSettle(findButton(env.findHost(), "Copy verification"));

  assert.equal(execCalls, 1);
  assert.match(treeText(env.findHost()), /Copied/);
  assertPanelHidesProof(env.findHost(), FIXTURE_PROOF);
  assert.equal(
    findElement(env.doc.body, (node) => node.value === FIXTURE_PROOF && node !== env.doc._proof),
    null,
    "temporary selection field is removed"
  );
});

test("never displays or logs the raw proof", async () => {
  const env = createEnv();
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());
  await clickAndSettle(findButton(env.findHost(), "Copy verification"));

  const host = env.findHost();
  assertPanelHidesProof(host, FIXTURE_PROOF);
  assert.ok(!JSON.stringify(env.consoleCalls).includes(FIXTURE_PROOF));
  assert.deepEqual(Object.keys(env.sandbox[MARKER]).sort(), ["remove", "show", "version"]);
  assert.ok(!JSON.stringify(Object.keys(env.sandbox[MARKER])).includes(FIXTURE_PROOF));
});

test("proof expires at 120 seconds and cannot be copied afterwards", async () => {
  const env = createEnv();
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());

  env.timers.advance(119000);
  assert.equal(findButton(env.findHost(), "Copy verification").disabled, false);

  env.timers.advance(1000);

  const host = env.findHost();
  assert.match(treeText(host), /Verification expired after 2 minutes/);
  assert.equal(findButton(host, "Copy verification").disabled, true);
  assert.equal(env.timers.pending(), 0, "expiry clears its timers");

  await clickAndSettle(findButton(host, "Copy verification"));
  assert.deepEqual(env.clipboardWrites, []);
  assert.ok(env.sandbox[MARKER], "helper stays installed after expiry");
});

test("repeated capture of the same proof does not extend its lifetime", () => {
  const env = createEnv();
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());

  env.timers.advance(60000);
  env.sandbox.processAjax(loginOptions());
  env.timers.advance(60000);

  assert.match(treeText(env.findHost()), /Verification expired after 2 minutes/);
});

test("a fresh challenge replaces the old proof", () => {
  const env = createEnv();
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());

  env.timers.advance(30000);
  env.setProof(OTHER_PROOF);
  env.sandbox.processAjax(loginOptions());

  assert.match(treeText(env.findHost()), /Verification captured/);
  assert.equal(findButton(env.findHost(), "Copy verification").disabled, false);
  // The second capture restarts the 120 s window.
  env.timers.advance(119000);
  assert.match(treeText(env.findHost()), /Verification captured/);
  env.timers.advance(1000);
  assert.match(treeText(env.findHost()), /Verification expired/);
});

test("Close restores processAjax, removes the panel, and clears the proof", async () => {
  const env = createEnv();
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());

  await clickAndSettle(findButton(env.findHost(), "Close helper"));

  assert.equal(env.sandbox.processAjax, env.original);
  assert.equal(env.findHost(), null);
  assert.equal(env.sandbox[MARKER], undefined);
  assert.equal(env.timers.pending(), 0);
  assert.equal((env.listeners.pagehide || []).length, 0);
  assert.equal(env.doc._proof.value, FIXTURE_PROOF, "helper does not clear the site field");

  env.sandbox.processAjax(loginOptions());
  assert.equal(env.original.calls.length, 1, "page is back to its own behavior");

  env.run();
  assert.notEqual(env.sandbox.processAjax, env.original);
  assert.equal(env.hostCount(), 1);
});

test("pagehide tears down and restores the page", () => {
  const env = createEnv();
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());

  env.sandbox.dispatchEvent({ type: "pagehide" });

  assert.equal(env.sandbox.processAjax, env.original);
  assert.equal(env.findHost(), null);
  assert.equal(env.sandbox[MARKER], undefined);
  assert.equal(env.timers.pending(), 0);
  assert.equal((env.listeners.pagehide || []).length, 0);
});

test("unexpected login-call shape fails closed with instructions", () => {
  const env = createEnv();
  env.run();
  env.setProof(FIXTURE_PROOF);

  env.sandbox.processAjax("/Home/Login");

  assert.equal(env.original.calls.length, 0);
  assert.match(treeText(env.findHost()), /did not have the expected shape/);
  assert.match(treeText(env.findHost()), /Reload this page/);
  assertPanelHidesProof(env.findHost(), FIXTURE_PROOF);

  const throwingOptions = {};
  Object.defineProperty(throwingOptions, "url", {
    get() {
      throw new Error("url unreadable");
    },
  });
  env.sandbox.processAjax(throwingOptions);
  assert.equal(env.original.calls.length, 0);

  env.sandbox.processAjax({ url: new URL(`${SITE_ORIGIN}/Home/Login`) });
  assert.equal(env.original.calls.length, 0);
});

test("missing site hook fails closed with instructions and can be retried", () => {
  const env = createEnv({ hasProcessAjax: false });
  assert.doesNotThrow(() => env.run());

  assert.equal(env.sandbox.processAjax, undefined);
  assert.equal(env.sandbox[MARKER], undefined);
  const host = env.findHost();
  assert.ok(host, "instructions are still shown");
  assert.match(treeText(host), /could not attach to the site's login call/);
  assert.match(treeText(host), /Reload this page/);

  env.sandbox.processAjax = env.original;
  env.run();
  assert.notEqual(env.sandbox.processAjax, env.original);
  assert.ok(env.sandbox[MARKER]);
  assert.equal(env.hostCount(), 1);
  assert.match(treeText(env.findHost()), /Ready\./);
});

test("no storage, URL rewriting or network side effects", async () => {
  const env = createEnv();
  const touched = { localStorage: 0, sessionStorage: 0, fetch: 0, xhr: 0, history: 0 };

  for (const name of Object.keys(touched)) {
    Object.defineProperty(env.sandbox, name, {
      configurable: true,
      get() {
        touched[name] += 1;
        throw new Error(`${name} must not be touched`);
      },
    });
  }

  assert.doesNotThrow(() => env.run());
  env.setProof(FIXTURE_PROOF);
  assert.doesNotThrow(() => env.sandbox.processAjax(loginOptions()));
  await clickAndSettle(findButton(env.findHost(), "Copy verification"));

  assert.deepEqual(touched, {
    localStorage: 0,
    sessionStorage: 0,
    fetch: 0,
    xhr: 0,
    history: 0,
  });
  assert.deepEqual(env.clipboardWrites, [FIXTURE_PROOF]);
});

test("no clipboard API: falls back to selection instead of throwing", async () => {
  const env = createEnv({ clipboard: null });
  env.doc.execCommand = () => false;
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());

  await clickAndSettle(findButton(env.findHost(), "Copy verification"));
  assert.match(treeText(env.findHost()), /Copy was blocked by the browser/);
  assertPanelHidesProof(env.findHost(), FIXTURE_PROOF);
});

/* ------------------------------------- deferred clipboard: late settlement */

test("deferred clipboard rejection after Close never falls back or copies", async () => {
  const pending = deferred();
  const writes = [];
  let execCalls = 0;
  const env = createEnv({
    clipboard: {
      writeText(value) {
        writes.push(value);
        return pending.promise;
      },
    },
  });
  env.doc.execCommand = () => {
    execCalls += 1;
    return true;
  };
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());
  clickCopy(env);
  await settle();
  assert.deepEqual(writes, [FIXTURE_PROOF], "the platform write was requested once");

  await clickAndSettle(findButton(env.findHost(), "Close helper"));

  pending.reject(new Error("late clipboard denial"));
  await flush();

  assert.equal(execCalls, 0, "no delayed selection fallback after teardown");
  assert.deepEqual(writes, [FIXTURE_PROOF], "no extra clipboard write");
  assert.equal(env.findHost(), null, "panel is not rebuilt by the late rejection");
  assert.equal(env.hostCount(), 0);
  assert.equal(env.sandbox[MARKER], undefined);
  assert.equal(env.sandbox.processAjax, env.original, "page behavior stays restored");
  assert.equal(env.timers.pending(), 0);
});

test("deferred clipboard rejection after expiry never falls back or copies", async () => {
  const pending = deferred();
  const writes = [];
  let execCalls = 0;
  const env = createEnv({
    clipboard: {
      writeText(value) {
        writes.push(value);
        return pending.promise;
      },
    },
  });
  env.doc.execCommand = () => {
    execCalls += 1;
    return true;
  };
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());
  clickCopy(env);
  await settle();

  env.timers.advance(120000);
  assert.match(treeText(env.findHost()), /Verification expired after 2 minutes/);

  pending.reject(new Error("late clipboard denial"));
  await flush();

  assert.equal(execCalls, 0, "no delayed selection fallback after expiry");
  assert.deepEqual(writes, [FIXTURE_PROOF], "no extra clipboard write");
  const host = env.findHost();
  assert.ok(host, "helper stays installed after expiry");
  assert.match(treeText(host), /Verification expired after 2 minutes/);
  assert.ok(!treeText(host).includes("Copied"));
  assert.equal(findButton(host, "Copy verification").disabled, true);
});

test("a delayed rejection from an old proof never copies the replacement proof", async () => {
  const pending = deferred();
  const writes = [];
  let execCalls = 0;
  let clipboardCalls = 0;
  const env = createEnv({
    clipboard: {
      writeText(value) {
        writes.push(value);
        clipboardCalls += 1;
        return clipboardCalls === 1 ? pending.promise : Promise.resolve();
      },
    },
  });
  env.doc.execCommand = () => {
    execCalls += 1;
    return true;
  };
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());
  clickCopy(env);
  await settle();

  env.timers.advance(30000);
  env.setProof(OTHER_PROOF);
  env.sandbox.processAjax(loginOptions());
  assert.match(treeText(env.findHost()), /Verification captured/);

  pending.reject(new Error("late clipboard denial for the old proof"));
  await flush();

  assert.equal(execCalls, 0, "old delayed rejection must not copy anything");
  assert.deepEqual(writes, [FIXTURE_PROOF], "replacement proof is not written by the old callback");
  const host = env.findHost();
  assert.match(treeText(host), /Verification captured/);
  assert.ok(!treeText(host).includes("Copied"));
  assert.equal(findButton(host, "Copy verification").disabled, false);

  // The replacement proof is still copyable through its own gesture.
  await clickAndSettle(findButton(host, "Copy verification"));
  assert.deepEqual(writes, [FIXTURE_PROOF, OTHER_PROOF]);
  assert.match(treeText(host), /Copied/);
});

test("deferred clipboard success after cleanup never revives the UI", async () => {
  const closePending = deferred();
  const closeWrites = [];
  let closeExecCalls = 0;
  const closed = createEnv({
    clipboard: {
      writeText(value) {
        closeWrites.push(value);
        return closePending.promise;
      },
    },
  });
  closed.doc.execCommand = () => {
    closeExecCalls += 1;
    return true;
  };
  closed.run();
  closed.setProof(FIXTURE_PROOF);
  closed.sandbox.processAjax(loginOptions());
  clickCopy(closed);
  await settle();
  await clickAndSettle(findButton(closed.findHost(), "Close helper"));

  closePending.resolve();
  await flush();

  assert.equal(closed.hostCount(), 0, "late success does not rebuild a closed panel");
  assert.equal(closeExecCalls, 0);
  assert.deepEqual(closeWrites, [FIXTURE_PROOF]);

  const expiredPending = deferred();
  const expired = createEnv({
    clipboard: {
      writeText() {
        return expiredPending.promise;
      },
    },
  });
  expired.run();
  expired.setProof(FIXTURE_PROOF);
  expired.sandbox.processAjax(loginOptions());
  clickCopy(expired);
  await settle();
  expired.timers.advance(120000);

  expiredPending.resolve();
  await flush();

  const expiredHost = expired.findHost();
  assert.ok(expiredHost);
  assert.match(treeText(expiredHost), /Verification expired after 2 minutes/);
  assert.ok(!treeText(expiredHost).includes("Copied"), "late success does not report a stale copy");
});

test("reinstalled helper is not disturbed by callbacks from the closed instance", async () => {
  const pending = deferred();
  const writes = [];
  const env = createEnv({
    clipboard: {
      writeText(value) {
        writes.push(value);
        return pending.promise;
      },
    },
  });
  let execCalls = 0;
  env.doc.execCommand = () => {
    execCalls += 1;
    return true;
  };
  env.run();
  env.setProof(FIXTURE_PROOF);
  env.sandbox.processAjax(loginOptions());
  clickCopy(env);
  await settle();
  await clickAndSettle(findButton(env.findHost(), "Close helper"));

  env.run();
  env.setProof(OTHER_PROOF);
  env.sandbox.processAjax(loginOptions());
  const reinstalledHost = env.findHost();
  assert.match(treeText(reinstalledHost), /Verification captured/);

  pending.reject(new Error("late denial from the closed instance"));
  await flush();

  assert.equal(execCalls, 0, "the closed instance never falls back");
  assert.deepEqual(writes, [FIXTURE_PROOF]);
  assert.equal(findButton(env.findHost(), "Copy verification").disabled, false);
  assert.match(treeText(env.findHost()), /Verification captured/);
  assert.ok(!treeText(env.findHost()).includes("Copied"));
  assert.equal(env.hostCount(), 1);

  env.setClipboard({
    writeText(value) {
      writes.push(value);
      return Promise.resolve();
    },
  });
  await clickAndSettle(findButton(env.findHost(), "Copy verification"));
  assert.deepEqual(writes, [FIXTURE_PROOF, OTHER_PROOF]);
  assert.match(treeText(env.findHost()), /Copied/);
});
