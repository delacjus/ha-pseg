/*
 * PSE&G MyMeter verification helper (experimental, user-invoked).
 *
 * Purpose: let a human keep the invisible reCAPTCHA v2 response that
 * MyMeter produces when they press the site's own Sign In button, instead of
 * letting the site immediately spend it on its own /Home/Login request. The
 * human then copies the response into the masked verification field in Home
 * Assistant's PSE&G config flow.
 *
 * Safety contract:
 * - Only runs on the exact MyMeter origin.
 * - Reads exactly one thing from the page: textarea[name="g-recaptcha-response"].
 *   It never reads credentials, form data, cookies or storage.
 * - Wraps window.processAjax. A call whose first argument is an object whose
 *   url resolves to the exact same-origin path /Home/Login is stopped before
 *   the original request is sent; every other call is delegated unchanged.
 * - The response stays in this closure's memory only. It is never written to
 *   the DOM, console, URL, storage or the network. Only an explicit Copy
 *   button (a user gesture) puts it on the clipboard. A deferred clipboard
 *   callback re-checks that its own response is still the current one before
 *   it may copy again or report success, so a late settle cannot revive a
 *   closed, expired or replaced capture.
 * - The response and panel are cleared after 120 seconds, on Close, and on
 *   pagehide. Closing restores the original window.processAjax.
 *
 * This file is self-executing so it can also be URL-encoded verbatim into a
 * bookmarklet (comments and newlines included).
 */
(function () {
  "use strict";

  var ORIGIN = "https://mysmartenergy.nj.pseg.com";
  var LOGIN_PATH = "/Home/Login";
  var PROOF_SELECTOR = 'textarea[name="g-recaptcha-response"]';
  var TTL_MS = 120000;
  var HOST_ID = "pseg-captcha-helper-panel";
  var MARKER = "__psegCaptchaHelperV1";

  var win = window;
  var doc = document;

  function currentOrigin() {
    try {
      if (win.location && typeof win.location.origin === "string") {
        return win.location.origin;
      }
      if (win.location) {
        return String(win.location.protocol) + "//" + String(win.location.host);
      }
    } catch (err) {
      /* fall through */
    }
    return "";
  }

  function refuse(message) {
    try {
      if (typeof win.alert === "function") {
        win.alert(message);
      }
    } catch (err) {
      /* no-op: refusing must never throw */
    }
  }

  if (currentOrigin() !== ORIGIN) {
    refuse(
      "The PSE&G verification helper only runs on " +
        ORIGIN +
        ". Nothing was changed on this page."
    );
    return;
  }

  // Idempotent: a second run only re-opens the existing panel.
  if (win[MARKER] && typeof win[MARKER].show === "function") {
    win[MARKER].show();
    return;
  }

  var URLBuilder = typeof win.URL === "function" ? win.URL : null;
  var originalProcessAjax = win.processAjax;
  var state = {
    token: null,
    capturedAt: 0,
    expiresAt: 0,
    // Bumped whenever the held response changes or is discarded, so a deferred
    // clipboard callback can tell that its proof is no longer current.
    generation: 0,
  };
  var panel = null;
  var expiryTimer = null;
  var countdownTimer = null;
  var copyAttempt = 0;
  var stopped = false;

  function isLoginUrl(raw) {
    if (typeof raw !== "string" || raw === "" || !URLBuilder) {
      return false;
    }
    var parsed;
    try {
      parsed = new URLBuilder(raw, ORIGIN + "/");
    } catch (err) {
      return false;
    }
    return parsed.origin === ORIGIN && parsed.pathname === LOGIN_PATH;
  }

  // "login": the documented login request, intercept it.
  // "fail": it looks like a login request but not in the shape we can trust,
  //         so stop it and tell the human instead of submitting silently.
  // "other": unrelated AJAX, delegate untouched.
  function classify(args) {
    if (!args || args.length === 0) {
      return "other";
    }
    var first = args[0];
    if (typeof first === "string") {
      return isLoginUrl(first) ? "fail" : "other";
    }
    if (!first || typeof first !== "object") {
      return "other";
    }
    var raw;
    try {
      raw = first.url;
    } catch (err) {
      return "fail";
    }
    if (raw === undefined || raw === null) {
      return "other";
    }
    if (typeof raw !== "string") {
      try {
        return isLoginUrl(String(raw)) ? "fail" : "other";
      } catch (err) {
        return "other";
      }
    }
    return isLoginUrl(raw) ? "login" : "other";
  }

  // The ONLY page content this helper reads.
  function readProof() {
    try {
      var field = doc.querySelector(PROOF_SELECTOR);
      if (!field || typeof field.value !== "string") {
        return "";
      }
      return field.value.trim();
    } catch (err) {
      return "";
    }
  }

  function clearTimers() {
    if (expiryTimer !== null) {
      try {
        win.clearTimeout(expiryTimer);
      } catch (err) {
        /* no-op */
      }
      expiryTimer = null;
    }
    if (countdownTimer !== null) {
      try {
        win.clearInterval(countdownTimer);
      } catch (err) {
        /* no-op */
      }
      countdownTimer = null;
    }
  }

  function dropProof() {
    state.token = null;
    state.capturedAt = 0;
    state.expiresAt = 0;
    state.generation += 1;
  }

  function hasLiveProof() {
    return !stopped && !!state.token && Date.now() < state.expiresAt;
  }

  // Deferred clipboard callbacks keep only these two numbers, never the
  // response, and call this before showing copy feedback or falling back.
  function isCurrentCopyAttempt(proofGeneration, attempt) {
    return (
      !stopped &&
      panel !== null &&
      attempt === copyAttempt &&
      proofGeneration === state.generation &&
      hasLiveProof()
    );
  }

  function setStatus(text) {
    if (panel) {
      panel.status.textContent = text;
    }
  }

  function setFeedback(text) {
    if (panel) {
      panel.feedback.textContent = text;
    }
  }

  function setCopyEnabled(enabled) {
    if (panel) {
      panel.copyBtn.disabled = !enabled;
    }
  }

  function updateCapturedStatus(msLeft) {
    var seconds = Math.max(0, Math.ceil(msLeft / 1000));
    setStatus(
      "Verification captured. Press Copy verification, then paste it into the " +
        "PSE&G verification field in Home Assistant. Nothing was sent to PSE&G. " +
        "Expires in " +
        seconds +
        " s."
    );
  }

  function expire() {
    clearTimers();
    dropProof();
    if (!stopped) {
      showPanel("expired");
    }
  }

  function scheduleExpiry() {
    clearTimers();
    var msLeft = state.expiresAt - Date.now();
    if (msLeft <= 0) {
      expire();
      return;
    }
    expiryTimer = win.setTimeout(expire, msLeft);
    countdownTimer = win.setInterval(function () {
      if (!state.token) {
        return;
      }
      var remaining = state.expiresAt - Date.now();
      if (remaining <= 0) {
        expire();
        return;
      }
      updateCapturedStatus(remaining);
    }, 1000);
    updateCapturedStatus(msLeft);
  }

  function storeProof(token) {
    var now = Date.now();
    if (state.token === token && state.expiresAt > now) {
      // Same still-valid challenge: do not extend the vendor's lifetime.
      showPanel("captured");
      return;
    }
    state.token = token;
    state.capturedAt = now;
    state.expiresAt = now + TTL_MS;
    state.generation += 1;
    showPanel("captured");
    scheduleExpiry();
  }

  function copySucceeded() {
    setFeedback("Copied. Paste it into Home Assistant now.");
  }

  function copyFailed() {
    setFeedback(
      "Copy was blocked by the browser. Allow clipboard access for this site " +
        "and press Copy verification again."
    );
  }

  // Off-screen selection is a last resort for browsers that deny the async
  // clipboard API. The value is removed from the document immediately. The
  // response is read from the live state here rather than passed around, so no
  // stale copy can leak through a deferred callback.
  function copyViaSelection() {
    var ok = false;
    var temp = null;
    var token = state.token;
    if (stopped || !token || Date.now() >= state.expiresAt) {
      return;
    }
    try {
      temp = doc.createElement("textarea");
      temp.value = token;
      token = "";
      temp.setAttribute("readonly", "readonly");
      temp.setAttribute("aria-hidden", "true");
      temp.style.position = "fixed";
      temp.style.left = "-9999px";
      temp.style.top = "0";
      temp.style.opacity = "0";
      var parent = doc.body || doc.documentElement;
      if (parent) {
        parent.appendChild(temp);
        if (typeof temp.select === "function") {
          temp.select();
        }
        ok = typeof doc.execCommand === "function" && doc.execCommand("copy") === true;
      }
    } catch (err) {
      ok = false;
    }
    try {
      if (temp && temp.parentNode) {
        temp.parentNode.removeChild(temp);
      }
    } catch (err) {
      /* no-op */
    }
    if (ok) {
      copySucceeded();
    } else {
      copyFailed();
    }
  }

  function onCopy() {
    if (stopped || !panel) {
      return;
    }
    if (!hasLiveProof()) {
      showPanel("expired");
      return;
    }
    var proofGeneration = state.generation;
    copyAttempt += 1;
    var attempt = copyAttempt;
    var clipboard = null;
    try {
      clipboard = win.navigator && win.navigator.clipboard;
    } catch (err) {
      clipboard = null;
    }
    if (clipboard && typeof clipboard.writeText === "function") {
      var result = null;
      try {
        result = clipboard.writeText(state.token);
      } catch (err) {
        result = null;
      }
      if (result && typeof result.then === "function") {
        // The platform write is already in flight and cannot be cancelled. These
        // callbacks hold only identity numbers, so a late settle can never copy
        // or report a proof that was replaced, expired or torn down.
        result.then(
          function () {
            if (!isCurrentCopyAttempt(proofGeneration, attempt)) {
              return;
            }
            copySucceeded();
          },
          function () {
            if (!isCurrentCopyAttempt(proofGeneration, attempt)) {
              return;
            }
            copyViaSelection();
          }
        );
        return;
      }
      // A synchronous throw is handled below; an unexpected return value is
      // treated as a failed copy rather than assumed successful.
    }
    copyViaSelection();
  }

  function makeButton(label, primary) {
    var button = doc.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.style.appearance = "none";
    button.style.border = "1px solid " + (primary ? "#0b57d0" : "#8c959f");
    button.style.borderRadius = "6px";
    button.style.padding = "7px 12px";
    button.style.fontSize = "13px";
    button.style.fontFamily = "inherit";
    button.style.fontWeight = "600";
    button.style.cursor = "pointer";
    button.style.background = primary ? "#0b57d0" : "#f6f8fa";
    button.style.color = primary ? "#ffffff" : "#1f2328";
    return button;
  }

  function ensurePanel() {
    if (panel && panel.host) {
      return panel;
    }
    var existing = null;
    try {
      existing = doc.getElementById(HOST_ID);
    } catch (err) {
      existing = null;
    }
    if (existing && existing.parentNode) {
      existing.parentNode.removeChild(existing);
    }

    var host = doc.createElement("div");
    host.id = HOST_ID;
    host.setAttribute("role", "dialog");
    host.setAttribute("aria-modal", "false");
    host.setAttribute("aria-labelledby", HOST_ID + "-title");
    host.setAttribute("aria-describedby", HOST_ID + "-directions " + HOST_ID + "-status");
    host.style.position = "fixed";
    host.style.right = "16px";
    host.style.bottom = "16px";
    host.style.zIndex = "2147483647";
    host.style.width = "calc(100vw - 32px)";
    host.style.maxWidth = "380px";
    host.style.boxSizing = "border-box";
    host.style.background = "#ffffff";
    host.style.color = "#1f2328";
    host.style.border = "1px solid #8c959f";
    host.style.borderRadius = "10px";
    host.style.boxShadow = "0 8px 28px rgba(0, 0, 0, 0.28)";
    host.style.padding = "14px 16px";
    host.style.fontFamily =
      "-apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif";
    host.style.fontSize = "13px";
    host.style.lineHeight = "1.45";
    host.style.textAlign = "left";

    var title = doc.createElement("h2");
    title.setAttribute("id", HOST_ID + "-title");
    title.textContent = "PSE&G verification helper (experimental)";
    title.style.margin = "0 0 6px 0";
    title.style.fontSize = "15px";
    title.style.lineHeight = "1.3";
    title.style.fontWeight = "700";

    var directions = doc.createElement("p");
    directions.setAttribute("id", HOST_ID + "-directions");
    directions.textContent =
      "Run this before clicking Sign In. Click the site's Sign In button and solve " +
      "the challenge yourself. Then press Copy verification and paste it into the " +
      "PSE&G verification field in Home Assistant within 2 minutes. The helper stops " +
      "the site's own login request so the verification stays unused. Experimental: " +
      "Home Assistant may still reject it.";
    directions.style.margin = "0 0 10px 0";
    directions.style.color = "#424a53";

    var status = doc.createElement("div");
    status.setAttribute("id", HOST_ID + "-status");
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    status.style.margin = "0 0 8px 0";

    var feedback = doc.createElement("div");
    feedback.setAttribute("role", "status");
    feedback.setAttribute("aria-live", "polite");
    feedback.style.margin = "0 0 8px 0";
    feedback.style.fontWeight = "600";

    var actions = doc.createElement("div");
    actions.style.display = "flex";
    actions.style.gap = "8px";
    actions.style.flexWrap = "wrap";

    var copyBtn = makeButton("Copy verification", true);
    copyBtn.disabled = true;
    var closeBtn = makeButton("Close helper", false);

    copyBtn.addEventListener("click", function (event) {
      if (event && typeof event.preventDefault === "function") {
        event.preventDefault();
      }
      onCopy();
    });
    closeBtn.addEventListener("click", function (event) {
      if (event && typeof event.preventDefault === "function") {
        event.preventDefault();
      }
      teardown();
    });

    actions.appendChild(copyBtn);
    actions.appendChild(closeBtn);
    host.appendChild(title);
    host.appendChild(directions);
    host.appendChild(status);
    host.appendChild(feedback);
    host.appendChild(actions);

    panel = {
      host: host,
      status: status,
      feedback: feedback,
      copyBtn: copyBtn,
      closeBtn: closeBtn,
    };

    try {
      var parentNode = doc.body || doc.documentElement;
      if (parentNode) {
        parentNode.appendChild(host);
      }
    } catch (err) {
      /* panel stays detached; the hook still blocks unsafe logins */
    }
    return panel;
  }

  var READY_TEXT =
    "Ready. Waiting for the site's Sign In. The helper will hold the verification " +
    "and will not send the login request to PSE&G.";
  var MISSING_TEXT =
    "The site's login call had no verification response, so it was blocked and " +
    "nothing was sent to PSE&G. Press Sign In again and solve the challenge, or " +
    "Close the helper to restore the page.";
  var SHAPE_TEXT =
    "The login request did not have the expected shape, so the helper blocked it " +
    "instead of submitting silently. Reload this page, run the helper again, then " +
    "press Sign In. Close the helper to restore the page.";
  var EXPIRED_TEXT =
    "Verification expired after 2 minutes and was discarded. Press Sign In again " +
    "and solve a new challenge.";
  var INSTALL_TEXT =
    "The helper could not attach to the site's login call. Reload this page, then " +
    "run the helper again before pressing Sign In.";

  function showPanel(kind) {
    ensurePanel();
    var hasToken = !!(state.token && Date.now() < state.expiresAt);
    setCopyEnabled(hasToken);
    if (kind !== "captured") {
      setFeedback("");
    }
    if (kind === "ready") {
      setStatus(READY_TEXT);
    } else if (kind === "captured") {
      if (hasToken) {
        updateCapturedStatus(state.expiresAt - Date.now());
      } else {
        setStatus(EXPIRED_TEXT);
      }
    } else if (kind === "missing-proof") {
      setStatus(MISSING_TEXT);
    } else if (kind === "shape-error") {
      setStatus(SHAPE_TEXT);
    } else if (kind === "expired") {
      setStatus(EXPIRED_TEXT);
    } else if (kind === "install-error") {
      setStatus(INSTALL_TEXT);
    }
    return panel;
  }

  function processAjaxWrapper() {
    var args = arguments;
    if (stopped) {
      // A page holding our old reference gets its own behavior back.
      return originalProcessAjax.apply(this, args);
    }
    var kind;
    try {
      kind = classify(args);
    } catch (err) {
      kind = "fail";
    }
    if (kind === "login") {
      var proof = readProof();
      if (proof) {
        storeProof(proof);
      } else {
        showPanel("missing-proof");
      }
      proof = "";
      // Stop the original request: the response must stay unused for HA.
      return undefined;
    }
    if (kind === "fail") {
      showPanel("shape-error");
      return undefined;
    }
    return originalProcessAjax.apply(this, args);
  }
  processAjaxWrapper.__psegCaptchaHelper = true;

  function onPageHide() {
    teardown();
  }

  function teardown() {
    if (stopped) {
      return;
    }
    stopped = true;
    clearTimers();
    dropProof();
    if (win.processAjax === processAjaxWrapper) {
      win.processAjax = originalProcessAjax;
    }
    if (panel && panel.host && panel.host.parentNode) {
      try {
        panel.host.parentNode.removeChild(panel.host);
      } catch (err) {
        /* no-op */
      }
    }
    panel = null;
    try {
      if (typeof win.removeEventListener === "function") {
        win.removeEventListener("pagehide", onPageHide);
      }
    } catch (err) {
      /* no-op */
    }
    try {
      delete win[MARKER];
    } catch (err) {
      try {
        win[MARKER] = undefined;
      } catch (err2) {
        /* no-op */
      }
    }
  }

  if (typeof originalProcessAjax !== "function") {
    // Fail closed at install time: explain, but do not pretend to be attached.
    showPanel("install-error");
    return;
  }

  win.processAjax = processAjaxWrapper;
  win[MARKER] = {
    version: 1,
    show: function () {
      if (stopped) {
        return;
      }
      if (state.token && Date.now() < state.expiresAt) {
        showPanel("captured");
      } else {
        showPanel("ready");
      }
    },
    remove: teardown,
  };
  try {
    if (typeof win.addEventListener === "function") {
      win.addEventListener("pagehide", onPageHide);
    }
  } catch (err) {
    /* pagehide cleanup is best-effort; expiry and Close still clear state */
  }
  showPanel("ready");
})();
