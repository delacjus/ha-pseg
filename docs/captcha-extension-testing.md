# PSE&G helper: Chrome/Edge extension test candidate

Status: **test candidate for a manual check, not production-ready.** The
extension-loading path for the helper has not been observed on the live portal.
Treat CSP compatibility as **UNVERIFIED** until a human sees the panel on the
real page in Chrome or Edge.

## What it is

Three files in `custom_components/pseg/frontend/`:

| File | Role |
| --- | --- |
| `manifest.json` | MV3 manifest. Permissions are exactly `activeTab` and `scripting`. No host permissions, content scripts, storage, remote resources or external connections. |
| `service-worker.js` | On a toolbar click only, checks the tab and its exact origin, then injects the helper. Nothing runs at install, startup, tab update or navigation. |
| `pseg-captcha-helper.js` | The existing helper, unchanged. It guards the origin again, holds the site's reCAPTCHA response in memory, and blocks the site's own login request until the human closes it. |

Why a wrapper: MyMeter's strict CSP blocked a DOM-triggered `javascript:` link
in T3's browser. A physical bookmark-bar click has not been tested. This
candidate offers toolbar-click injection, whose compatibility still needs the
desktop check below. It does not solve CAPTCHA,
read credentials or cookies, or log in for you.

## Prerequisites

- Desktop Chrome or Edge with extensions allowed.
- The candidate folder, unzipped from `pseg-captcha-extension-candidate.zip`
  (exactly `manifest.json`, `service-worker.js`, `pseg-captcha-helper.js`).
  The repo folder also holds an unrelated `pseg-energy-card.js`; the extension
  never reads it, but the ZIP is the cleaner thing to load.
- A tab on the real portal, e.g. `https://mysmartenergy.nj.pseg.com/`.
- No credentials and no CAPTCHA challenge are needed to test injection. Do not
  type account details for this check.

## Steps

1. Unzip the candidate so the three files sit directly in one folder.
2. Open `chrome://extensions` (or `edge://extensions`) and enable **Developer
   mode**.
3. **Load unpacked** and select that folder. The entry "PSE&G verification
   helper" appears with no popup; pin it to the toolbar if you like.
4. Go to the portal tab and confirm the address bar shows exactly
   `https://mysmartenergy.nj.pseg.com`.
5. Click the toolbar button once. Nothing is injected before this click.

Expected on a working injection: a panel labelled "PSE&G verification helper
(experimental)" appears bottom-right, with status "Ready. Waiting for the
site's Sign In…". The toolbar title reads "injection requested. Look for the
panel on the page" and the badge shows `OK`.

6. Click the toolbar button again: the existing panel is re-opened; the helper
   is not installed twice.
7. Click **Close helper** in the panel. The panel disappears and the page's own
   `window.processAjax` is restored, so the site's Sign In behaves normally
   again. Reloading the tab also clears all helper state.
8. Negative check: open `https://example.com`, click the toolbar button. No
   panel appears, nothing is injected, the title reads "Open the PSE&G MyMeter
   page first" and the badge shows `!`.
9. To remove the extension: `chrome://extensions` -> **Remove**.

## Verification limits (read before believing a result)

- Badge `OK` means `chrome.scripting` accepted the request and the injection
  promise resolved. It is **not** evidence the panel rendered, and the toolbar
  wording deliberately does not claim it did. Only your eyes on the page prove
  the panel appears.
- **CSP compatibility: UNVERIFIED.** A DOM-triggered `javascript:` link was
  blocked on the public page; a physical bookmark-bar click was not observed.
  Neither result establishes privileged MAIN-world file injection. This candidate must not be
  called browser-verified until someone observes the panel on the live portal.
- If the badge shows `OK` but no panel appears, that is the unverified case.
  Record: Chrome/Edge version, whether `chrome://extensions` shows a service
  worker error, and the kind of portal page (login page or another page). Never
  paste credentials, cookies or verification values into a report.
- This candidate does not log in, does not transfer a session to Home Assistant,
  and does not change the integration. The Home Assistant PSE&G entry stays
  disabled with its alert off, and nothing here is deployed to Home Assistant.

## Rollback

Remove the extension from `chrome://extensions`. Nothing was installed on
PSE&G or Home Assistant. Closing the panel or reloading the tab restores the
page's own login function.

## Automated coverage

`node --test tests/test_captcha_extension.js` loads the shipped worker with a
fake `chrome` object and checks the permission budget, refusal of wrong origins
and missing tab ids, the exact `tabId`/`frameIds:[0]`/`files`/`world:"MAIN"`
arguments, rejection handling, and that no result, error or page data reaches
the toolbar or console. Those tests use a mock API: they do not load the
extension in a browser.
