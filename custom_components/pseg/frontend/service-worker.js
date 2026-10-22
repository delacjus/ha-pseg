/*
 * PSE&G MyMeter verification helper: minimal MV3 toolbar injector.
 *
 * Purpose: run pseg-captcha-helper.js in the page's own JavaScript world when,
 * and only when, the human clicks this extension's toolbar action on a tab
 * whose origin is exactly the MyMeter portal. The helper itself then guards the
 * origin again, holds the site's reCAPTCHA response in memory, and restores the
 * page when the human closes it.
 *
 * Safety contract:
 * - Permissions are activeTab + scripting only. No host permissions, no
 *   content scripts, no storage, no network requests, no remote code.
 * - Nothing is injected at install, at startup, on tab update, or on
 *   navigation. The only trigger is a toolbar click (a user gesture).
 * - The clicked tab must carry a usable numeric id and its URL origin must
 *   equal https://mysmartenergy.nj.pseg.com. Anything else is refused before
 *   chrome.scripting is called.
 * - The injection result is page data and is deliberately discarded: it is not
 *   bound, inspected, stored or logged. The toolbar title and badge carry only
 *   fixed generic text, so no page URL, query string or error text reaches the
 *   browser UI or the console.
 * - A resolved injection proves only that chrome.scripting accepted the
 *   request. It is not evidence that the helper panel rendered; the wording
 *   below never claims the panel is visible.
 */
"use strict";

(function () {
  var PORTAL_ORIGIN = "https://mysmartenergy.nj.pseg.com";
  var HELPER_FILE = "pseg-captcha-helper.js";

  // Fixed strings only. Never interpolate tab or page data into these.
  var READY_TITLE = "PSE&G verification helper: open the MyMeter page, then click";
  var WRONG_PAGE_TITLE = "Open the PSE&G MyMeter page first";
  var ERROR_TITLE = "PSE&G helper could not be injected. Reload the page and try again";
  var REQUESTED_TITLE = "PSE&G helper injection requested. Look for the panel on the page";

  var BADGE_ERROR = "!";
  var BADGE_REQUESTED = "OK";
  var COLOR_ERROR = "#b3261e";
  var COLOR_REQUESTED = "#146c2e";

  var api = globalThis.chrome;

  function ignoreFeedbackFailure(result) {
    Promise.resolve(result).catch(function () {
      /* Toolbar feedback is best-effort, including asynchronous failures. */
    });
  }

  function setTitle(tabId, text) {
    try {
      if (typeof tabId === "number") {
        ignoreFeedbackFailure(api.action.setTitle({ tabId: tabId, title: text }));
      } else {
        ignoreFeedbackFailure(api.action.setTitle({ title: text }));
      }
    } catch (err) {
      /* Toolbar feedback is best-effort and must never break the click. */
    }
  }

  function setBadge(tabId, text, color) {
    if (typeof tabId !== "number") {
      return;
    }
    try {
      ignoreFeedbackFailure(api.action.setBadgeText({ tabId: tabId, text: text }));
      if (text) {
        ignoreFeedbackFailure(api.action.setBadgeBackgroundColor({ tabId: tabId, color: color }));
      }
    } catch (err) {
      /* Toolbar feedback is best-effort and must never break the click. */
    }
  }

  function usableTabId(tab) {
    if (!tab || typeof tab !== "object") {
      return null;
    }
    var id = tab.id;
    if (typeof id !== "number" || !Number.isInteger(id) || id < 0) {
      return null;
    }
    return id;
  }

  function isPortalUrl(raw) {
    if (typeof raw !== "string" || raw === "") {
      return false;
    }
    var parsed;
    try {
      parsed = new URL(raw);
    } catch (err) {
      return false;
    }
    // Exact origin only, and never a URL that smuggles embedded credentials.
    if (parsed.username !== "" || parsed.password !== "") {
      return false;
    }
    return parsed.origin === PORTAL_ORIGIN;
  }

  async function handleClick(tab) {
    var tabId = usableTabId(tab);
    if (tabId === null) {
      setTitle(null, WRONG_PAGE_TITLE);
      return;
    }
    // Clear the previous click's badge so the new outcome is unambiguous.
    setTitle(tabId, READY_TITLE);
    setBadge(tabId, "", null);
    if (!isPortalUrl(tab.url)) {
      setTitle(tabId, WRONG_PAGE_TITLE);
      setBadge(tabId, BADGE_ERROR, COLOR_ERROR);
      return;
    }
    try {
      // The resolve value is page data. It is intentionally not assigned.
      await api.scripting.executeScript({
        target: { tabId: tabId, frameIds: [0] },
        files: [HELPER_FILE],
        world: "MAIN",
      });
    } catch (err) {
      setTitle(tabId, ERROR_TITLE);
      setBadge(tabId, BADGE_ERROR, COLOR_ERROR);
      return;
    }
    setTitle(tabId, REQUESTED_TITLE);
    setBadge(tabId, BADGE_REQUESTED, COLOR_REQUESTED);
  }

  api.action.onClicked.addListener(function (tab) {
    return handleClick(tab);
  });
})();
