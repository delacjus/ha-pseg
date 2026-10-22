# PSE&G helper: browser extension delivery (experimental)

Status: **experimental delivery, not production-ready.** The helper extension has
been seen on one desktop browser: the panel showed **Ready**, and **Close helper**
removed it. Browser name/version was not recorded. That single observation is not
browser acceptance, does not cover other browsers, and does not show that PSE&G
accepts a CAPTCHA proof captured this way. Portability of the proof to Home
Assistant and unattended renewal are still unverified.

## What it is

Home Assistant serves a fixed, public ZIP at
`/api/pseg/captcha-helper/extension.zip`, linked first from the helper page
(`/api/pseg/captcha-helper`). The archive is built in memory from exactly three
files in `custom_components/pseg/frontend/`, flat at the ZIP root:

| File | Role |
| --- | --- |
| `manifest.json` | MV3 manifest. Permissions are exactly `activeTab` and `scripting`. No host permissions, content scripts, storage, remote resources or external connections. |
| `service-worker.js` | On a toolbar click only, checks the tab and its exact origin, then injects the helper. Nothing runs at install, startup, tab update or navigation. |
| `pseg-captcha-helper.js` | The existing helper, unchanged. It guards the origin again, holds the site's reCAPTCHA response in memory, and blocks the site's own login request until the human closes it. |

`pseg-energy-card.js` shares the folder but is never part of the archive. The
endpoint takes no caller-supplied filenames, flow ids or archive paths, ignores
query data, requires no authentication and reads nothing from the config flow.
The page and the ZIP are static: no account, cookie, flow or proof data.

Why an extension: MyMeter's strict CSP blocked a DOM-triggered `javascript:` link
in T3's browser. A physical bookmark-bar click has not been tested, so the page
keeps the bookmarklet only as an explicitly unverified fallback. The extension
does not solve CAPTCHA, read credentials or cookies, or log in for you.

## Prerequisites

- Desktop Chrome or Edge with extensions allowed.
- The helper page reachable from Home Assistant, e.g.
  `http://<your-home-assistant>:8123/api/pseg/captcha-helper`.
- A tab on the real portal, e.g. `https://mysmartenergy.nj.pseg.com/`.
- No credentials and no CAPTCHA challenge are needed to test injection. Do not
  type account details for this check.

## Steps

1. Open the helper page and click **Download helper extension (ZIP)**. Extract it
   so the three files sit directly in one folder.
2. Open `chrome://extensions` (or `edge://extensions`) and enable **Developer
   mode**.
3. **Load unpacked** and select that folder. The entry "PSE&G verification
   helper" appears with no popup; pin it to the toolbar if you like.
4. Go to the portal tab and confirm the address bar shows exactly
   `https://mysmartenergy.nj.pseg.com`.
5. Click the toolbar button once. Nothing is injected before this click.

Expected on a working injection: a panel labelled "PSE&G verification helper
(experimental)" appears bottom-right, with status "Ready. Click the site's
Login button…". The toolbar title reads "injection requested. Look for the
panel on the page" and the badge shows `OK`.

6. Click the toolbar button again: the existing panel is re-opened; the helper
   is not installed twice.
7. Click **Close helper** in the panel. The panel disappears and the page's own
   `window.processAjax` is restored, so the site's Login button behaves normally
   again. Reloading the tab also clears all helper state.
8. Negative check: open `https://example.com`, click the toolbar button. No
   panel appears, nothing is injected, the title reads "Open the PSE&G MyMeter
   page first" and the badge shows `!`.
9. To remove the extension: `chrome://extensions` -> **Remove**.

## What success looks like

After you click the site's Login button and complete any challenge yourself, the
panel reports "Verification captured. The portal login is paused on purpose."
and the portal stays on its sign-in screen. That page
looking inert is expected: the helper stopped the site's own login request so the
proof stays unused for Home Assistant. Press **Copy verification**, paste it into
the masked **CAPTCHA proof** field in the Home Assistant dialog, and submit before
the panel's countdown reaches zero (about two minutes). **Close helper** restores
the portal's login and discards the proof.

## Verification limits (read before believing a result)

- One desktop browser showed **Ready**, and **Close helper** removed the panel.
  The user later reported a captured verification, but the latest screenshot
  shows **Ready** while they report an unresponsive Login button. Capture on
  this attempt remains unresolved. Browser name/version was not recorded. Do
  not describe the helper as browser-verified, portable across browsers, or
  accepted by PSE&G.
- Badge `OK` means `chrome.scripting` accepted the request and the injection
  promise resolved. It is **not** evidence the panel rendered, and the toolbar
  wording deliberately does not claim it did. Only your eyes on the page prove
  the panel appears.
- **CSP compatibility: UNVERIFIED.** A DOM-triggered `javascript:` link was
  blocked on the public page; a physical bookmark-bar click was not observed.
  Neither result establishes privileged MAIN-world file injection.
- If the badge shows `OK` but no panel appears, that is the unverified case.
  Record: Chrome/Edge version, whether `chrome://extensions` shows a service
  worker error, and the kind of portal page (login page or another page). Never
  paste credentials, cookies or verification values into a report.
- The helper does not transfer a session to Home Assistant and does not change
  the integration. A captured proof still has to be accepted by PSE&G, and
  renewal after that sign-in is not demonstrated.

## Rollback

Remove the extension from `chrome://extensions`. Nothing was installed on
PSE&G or Home Assistant. Closing the panel or reloading the tab restores the
page's own login function.

## Automated coverage

`tests/test_captcha_helper.py` (Python) checks the extension-first page, the
ZIP view's public unauthenticated GET, `application/zip` content type, fixed
`Content-Disposition` filename, exact flat three-file membership and bytes,
deterministic output, ignored query data, idempotent route registration, and the
generic 404 when a member is missing. It also checks that the page and archive
contain no account or flow data.

`node --test tests/test_captcha_extension.js` loads the shipped worker with a
fake `chrome` object and checks the permission budget, refusal of wrong origins
and missing tab ids, the exact `tabId`/`frameIds:[0]`/`files`/`world:"MAIN"`
arguments, rejection handling, and that no result, error or page data reaches
the toolbar or console. Those tests use a mock API: they do not load the
extension in a browser.
