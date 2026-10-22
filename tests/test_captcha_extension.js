"use strict";

/*
 * Tests for the MV3 wrapper around custom_components/pseg/frontend/pseg-captcha-helper.js:
 * manifest.json (permission budget) and service-worker.js (toolbar click only).
 *
 * The worker is loaded for real from disk with a fake `chrome` object, so these
 * tests exercise the shipped listener registration rather than a copy. All
 * fixtures are synthetic: no real credential, cookie, CAPTCHA response or
 * network call is used anywhere here.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const FRONTEND_DIR = path.join(__dirname, "..", "custom_components", "pseg", "frontend");
const MANIFEST_PATH = path.join(FRONTEND_DIR, "manifest.json");
const WORKER_PATH = path.join(FRONTEND_DIR, "service-worker.js");
const HELPER_PATH = path.join(FRONTEND_DIR, "pseg-captcha-helper.js");

const PORTAL_ORIGIN = "https://mysmartenergy.nj.pseg.com";
const HELPER_FILE = "pseg-captcha-helper.js";
const CANDIDATE_FILES = ["manifest.json", "service-worker.js", "pseg-captcha-helper.js"];

const MANIFEST = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
const WORKER_SOURCE = fs.readFileSync(WORKER_PATH, "utf8");

test("toolbar Promise rejections stay handled for every click outcome", async () => {
  for (const failInjection of [false, true]) {
    await withWorker({
      rejectFeedback: true,
      executeScript: () => failInjection
        ? Promise.reject(new Error("synthetic injection failure"))
        : Promise.resolve([]),
    }, async (env) => {
      await env.click({ id: 7, url: PORTAL_ORIGIN + "/" });
      await env.click({ id: 7, url: "https://example.com/" });
      await env.click({});
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(env.injected.length, 1);
      assert.deepEqual(env.consoleCalls, []);
    });
  }
});

/* --------------------------------------------------------- chrome test double */

function createChrome(options = {}) {
  const feedback = { titles: [], badges: [], colors: [] };
  const injected = [];
  const accessed = [];
  let clickHandler = null;

  const action = {
    onClicked: {
      addListener(handler) {
        assert.equal(clickHandler, null, "exactly one action.onClicked listener");
        clickHandler = handler;
      },
    },
    setTitle(details) {
      feedback.titles.push({ ...details });
      if (options.rejectFeedback) return Promise.reject(new Error("synthetic toolbar failure"));
    },
    setBadgeText(details) {
      feedback.badges.push({ ...details });
      if (options.rejectFeedback) return Promise.reject(new Error("synthetic toolbar failure"));
    },
    setBadgeBackgroundColor(details) {
      feedback.colors.push({ ...details });
      if (options.rejectFeedback) return Promise.reject(new Error("synthetic toolbar failure"));
    },
  };

  const scripting = {
    executeScript(details) {
      injected.push(details);
      const impl = options.executeScript;
      if (typeof impl === "function") {
        return impl(details);
      }
      return Promise.resolve([{ frameId: 0, result: undefined }]);
    },
  };

  const base = { action, scripting };
  // Any other chrome API is a hard failure: the worker must not need tabs,
  // storage, alarms or anything else, and must not be able to navigate.
  const chrome = new Proxy(base, {
    get(target, prop) {
      if (typeof prop !== "string") {
        return target[prop];
      }
      accessed.push(prop);
      if (!Object.prototype.hasOwnProperty.call(target, prop)) {
        throw new Error("unexpected chrome API access: " + prop);
      }
      return target[prop];
    },
  });

  return {
    chrome,
    feedback,
    injected,
    accessed,
    hasListener: () => typeof clickHandler === "function",
    click: (tab) => clickHandler(tab),
  };
}

async function withWorker(options, run) {
  const env = createChrome(options);
  const hadChrome = Object.prototype.hasOwnProperty.call(globalThis, "chrome");
  const previousChrome = globalThis.chrome;
  const levels = ["log", "error", "warn", "info", "debug", "trace"];
  const previousConsole = {};
  const consoleCalls = [];
  for (const level of levels) {
    previousConsole[level] = console[level];
    console[level] = (...args) => {
      consoleCalls.push({ level, args });
    };
  }

  globalThis.chrome = env.chrome;
  let loadError = null;
  try {
    delete require.cache[require.resolve(WORKER_PATH)];
    require(WORKER_PATH);
  } catch (err) {
    loadError = err;
  }

  try {
    if (loadError) {
      throw loadError;
    }
    return await run({ ...env, consoleCalls });
  } finally {
    for (const level of levels) {
      console[level] = previousConsole[level];
    }
    delete require.cache[require.resolve(WORKER_PATH)];
    if (hadChrome) {
      globalThis.chrome = previousChrome;
    } else {
      delete globalThis.chrome;
    }
  }
}

/* ---------------------------------------------------------------- assertions */

function feedbackText(feedback) {
  return []
    .concat(feedback.titles.map((entry) => entry.title))
    .concat(feedback.badges.map((entry) => entry.text))
    .join(" | ");
}

// The worker must emit only fixed generic text. Anything URL- or data-shaped
// means page content leaked into the browser UI.
function assertGenericFeedback(feedback, forbidden = []) {
  for (const entry of feedback.titles) {
    assert.equal(typeof entry.title, "string");
    assert.ok(entry.title.length > 0, "titles are not empty");
    assert.ok(!entry.title.includes("http"), "title carries no URL: " + entry.title);
    assert.ok(!entry.title.includes("/"), "title carries no path: " + entry.title);
    assert.ok(!entry.title.includes("?"), "title carries no query: " + entry.title);
    assert.ok(!entry.title.includes("="), "title carries no parameter: " + entry.title);
  }
  for (const entry of feedback.badges) {
    assert.ok(entry.text.length <= 4, "badge text stays generic: " + entry.text);
    assert.ok(!/[?/=]/.test(entry.text), "badge carries no query data: " + entry.text);
  }
  const text = feedbackText(feedback);
  for (const value of forbidden) {
    assert.ok(!text.includes(value), "no leaked value in feedback: " + value);
  }
}

function assertNoConsoleOutput(consoleCalls) {
  assert.deepEqual(
    consoleCalls.map((call) => call.level),
    [],
    "the worker never logs page data, results or errors"
  );
}

function portalTab(overrides = {}) {
  return { id: 42, url: PORTAL_ORIGIN + "/", active: true, ...overrides };
}

/* -------------------------------------------------------------- manifest budget */

test("manifest is MV3 with exactly activeTab and scripting and a background worker", () => {
  assert.equal(MANIFEST.manifest_version, 3);
  assert.deepEqual(MANIFEST.permissions, ["activeTab", "scripting"]);
  assert.equal(MANIFEST.background.service_worker, "service-worker.js");
  assert.match(MANIFEST.version, /^\d+\.\d+\.\d+$/);
  assert.equal(typeof MANIFEST.action, "object");
  assert.equal(MANIFEST.action.default_popup, undefined, "a popup would swallow action clicks");
});

test("manifest grants no host access, content scripts, storage or remote resources", () => {
  const forbidden = [
    "host_permissions",
    "optional_host_permissions",
    "optional_permissions",
    "content_scripts",
    "externally_connectable",
    "web_accessible_resources",
    "declarative_net_request",
    "content_security_policy",
    "storage",
    "update_url",
    "options_page",
    "options_ui",
    "devtools_page",
    "chrome_url_overrides",
    "side_panel",
    "commands",
  ];
  for (const key of forbidden) {
    assert.ok(!(key in MANIFEST), "manifest must not declare " + key);
  }
  const serialized = JSON.stringify(MANIFEST);
  assert.ok(!serialized.includes("http://"), "no remote origin or script");
  assert.ok(!serialized.includes(PORTAL_ORIGIN), "no portal host permission or URL");
  assert.ok(!serialized.includes("<all_urls>"));
  assert.ok(!serialized.includes("*://"), "no match patterns");
});

test("manifest references only the three allowlisted sibling files", () => {
  const allowedKeys = new Set([
    "manifest_version",
    "name",
    "version",
    "description",
    "permissions",
    "action",
    "background",
  ]);
  for (const key of Object.keys(MANIFEST)) {
    assert.ok(allowedKeys.has(key), "unexpected manifest key pulls in another file or capability: " + key);
  }
  assert.deepEqual(Object.keys(MANIFEST.action), ["default_title"]);
  assert.deepEqual(Object.keys(MANIFEST.background), ["service_worker"]);
  assert.equal(MANIFEST.icons, undefined, "the candidate needs no icon file");
  assert.notEqual(MANIFEST.background.service_worker, HELPER_FILE, "worker and helper are distinct files");
  for (const name of CANDIDATE_FILES) {
    assert.ok(fs.statSync(path.join(FRONTEND_DIR, name)).isFile(), name + " is a sibling regular file");
  }
});

/* ------------------------------------------------------------- worker shape */

test("service worker is a classic script with helper as a sibling file", () => {
  assert.doesNotThrow(() => new vm.Script(WORKER_SOURCE, { filename: "service-worker.js" }));
  assert.equal(path.dirname(HELPER_PATH), FRONTEND_DIR);
  assert.ok(fs.statSync(HELPER_PATH).size > 0);
  assert.ok(!/^\s*(import|export)\s/m.test(WORKER_SOURCE), "no module syntax in a classic worker");
});

test("worker registers one click listener and injects nothing at startup", async () => {
  await withWorker({}, async (env) => {
    assert.ok(env.hasListener(), "action.onClicked is registered");
    assert.equal(env.injected.length, 0, "no autostart injection");
    assert.equal(env.feedback.titles.length, 0, "no startup toolbar feedback");
    assert.equal(env.feedback.badges.length, 0, "no startup badge");
    assert.deepEqual([...new Set(env.accessed)], ["action"], "load touches action only, never scripting or tabs");
    assertNoConsoleOutput(env.consoleCalls);
  });
});

/* ----------------------------------------------------------- refusal paths */

test("wrong origin is refused before injection, with generic feedback only", async () => {
  const cases = [
    { id: 7, url: "https://example.com/Home/Login" },
    { id: 7, url: PORTAL_ORIGIN + ".evil.example/Home/Login" },
    { id: 7, url: "http://mysmartenergy.nj.pseg.com/" },
    { id: 7, url: "https://mysmartenergy.nj.pseg.com:8443/" },
    { id: 7, url: "https://user:pass@mysmartenergy.nj.pseg.com/" },
    { id: 7, url: "chrome://extensions/" },
    { id: 7, url: "about:blank" },
    { id: 7, url: "file:///tmp/x.html" },
  ];
  for (const tab of cases) {
    await withWorker({}, async (env) => {
      await env.click(tab);
      assert.equal(env.injected.length, 0, "refused: " + tab.url);
      const titles = env.feedback.titles.map((entry) => entry.title);
      assert.ok(titles.length > 0, "a refusal is reported");
      assert.match(feedbackText(env.feedback), /Open the PSE&G MyMeter page first/);
      assert.ok(
        env.feedback.badges.some((entry) => entry.text === "!"),
        "refusal shows a generic error badge"
      );
      assert.equal(env.feedback.badges[env.feedback.badges.length - 1].tabId, 7);
      assertGenericFeedback(env.feedback, [tab.url, PORTAL_ORIGIN + ".evil.example", "user", "pass"]);
      assertNoConsoleOutput(env.consoleCalls);
    });
  }
});

test("missing or unusable tab id is refused without any injection", async () => {
  const cases = [
    undefined,
    null,
    {},
    { url: PORTAL_ORIGIN + "/" },
    { id: -1, url: PORTAL_ORIGIN + "/", active: true },
    { id: "42", url: PORTAL_ORIGIN + "/" },
    { id: 42.5, url: PORTAL_ORIGIN + "/" },
    { id: null, url: PORTAL_ORIGIN + "/" },
  ];
  for (const tab of cases) {
    await withWorker({}, async (env) => {
      await env.click(tab);
      assert.equal(env.injected.length, 0, "no injection for tab " + JSON.stringify(tab));
      assert.ok(env.feedback.titles.length > 0);
      assert.match(feedbackText(env.feedback), /Open the PSE&G MyMeter page first/);
      assertGenericFeedback(env.feedback, [String(tab && tab.id), "?x="]);
      assertNoConsoleOutput(env.consoleCalls);
    });
  }
});

/* ------------------------------------------------------------ injection args */

test("a portal click injects exactly the helper file into the top frame main world", async () => {
  await withWorker({}, async (env) => {
    await env.click(portalTab({ id: 42, url: PORTAL_ORIGIN + "/Home/Login" }));
    assert.equal(env.injected.length, 1);
    assert.deepEqual(env.injected[0], {
      target: { tabId: 42, frameIds: [0] },
      files: [HELPER_FILE],
      world: "MAIN",
    });
    assertGenericFeedback(env.feedback);
    assertNoConsoleOutput(env.consoleCalls);
  });
});

test("the toolbar action is the only trigger: each click injects once, never on navigation", async () => {
  await withWorker({}, async (env) => {
    await env.click(portalTab({ id: 11 }));
    await env.click(portalTab({ id: 11 }));
    assert.equal(env.injected.length, 2, "one injection per user click");
    assert.deepEqual(env.injected[1], env.injected[0]);
    assert.ok(env.injected.every((call) => call.target.tabId === 11));
    assert.deepEqual([...new Set(env.accessed)].sort(), ["action", "scripting"]);
  });
});

test("a resolved injection claims a request, not a visible panel", async () => {
  await withWorker({}, async (env) => {
    await env.click(portalTab());
    const text = feedbackText(env.feedback);
    assert.match(text, /injection requested/i);
    assert.match(text, /look for the panel/i);
    assert.doesNotMatch(text, /\bshown\b|\bvisible\b|\bopened\b|\bsucceeded\b|\bready panel\b/i);
    assert.ok(env.feedback.badges.some((entry) => entry.text === "OK"));
  });
});

/* ------------------------------------------------------- rejection handling */

test("a rejected injection is reported generically without echoing the error or URL", async () => {
  const secretUrl = PORTAL_ORIGIN + "/private?token=CANARY_QUERY_VALUE";
  await withWorker(
    {
      executeScript() {
        return Promise.reject(
          new Error(
            "Cannot access contents of url " +
              secretUrl +
              ": CSP_VALUE_CANARY and extension id abc"
          )
        );
      },
    },
    async (env) => {
      await env.click(portalTab({ id: 9, url: secretUrl }));
      assert.equal(env.injected.length, 1, "no retry after a rejection");
      assert.match(feedbackText(env.feedback), /could not be injected/i);
      assert.ok(env.feedback.badges.some((entry) => entry.text === "!"));
      assertGenericFeedback(env.feedback, [
        "CANARY_QUERY_VALUE",
        "CSP_VALUE_CANARY",
        "private",
        "Cannot access",
        "abc",
        secretUrl,
      ]);
      assertNoConsoleOutput(env.consoleCalls);
    }
  );
});

test("a synchronous throw from scripting is handled like a rejection", async () => {
  await withWorker(
    {
      executeScript() {
        throw new TypeError("SYNC_CANARY no tab with id");
      },
    },
    async (env) => {
      await env.click(portalTab({ id: 5 }));
      assert.equal(env.injected.length, 1);
      assert.match(feedbackText(env.feedback), /could not be injected/i);
      assertGenericFeedback(env.feedback, ["SYNC_CANARY", "no tab"]);
      assertNoConsoleOutput(env.consoleCalls);
    }
  );
});

/* ------------------------------------------------------- result data hygiene */

test("injection results are discarded and never surface in UI or console", async () => {
  const canary = "RESULT_CANARY_page_text_7f21";
  await withWorker(
    {
      executeScript() {
        return Promise.resolve([{ frameId: 0, result: { html: canary, token: canary } }]);
      },
    },
    async (env) => {
      await env.click(portalTab({ id: 3, url: PORTAL_ORIGIN + "/?session=" + canary }));
      assert.equal(env.injected.length, 1);
      assertGenericFeedback(env.feedback, [canary, "session", "html", "token"]);
      assertNoConsoleOutput(env.consoleCalls);
      assert.match(feedbackText(env.feedback), /injection requested/i);
    }
  );
});
