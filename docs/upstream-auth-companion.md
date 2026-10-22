# Upstream authentication companion

The upstream project has an optional browser service:
[`sidprax/ha-pseg-auth-addon`](https://github.com/sidprax/ha-pseg-auth-addon/tree/5210d641d5878f14fedc794f0b388869d3fdd1b5).
The Crestwood fork removed this authentication path. Installing the add-on alone
does not add it back to this fork.

Source inspection on 2026-10-22 used companion commit
`5210d641d5878f14fedc794f0b388869d3fdd1b5` and integration commit
`a02ea3ee1f0392f4823f9ba736c6427780aca9dc`.

## What it implements

The service runs Chromium through Selenium and visits PSE&G's **Sign in Via My
Account** route, `/Saml/okta-prod/SignIn`. It enters the Okta username/password,
requests SMS or email verification when instructed, and waits for the caller to
submit the received code. It does not read messages itself.

Its CAPTCHA function attempts an audio challenge through Google speech
recognition after the username step. There is no endpoint for a person to solve
the challenge. A blocked challenge returns an error and removes the saved browser
profile. This is a different login route from MyMeter's local email/password form
and its invisible reCAPTCHA.

After a successful login it returns portal cookies and closes the browser. Its
API exposes health, login, and MFA completion; it has no session-refresh or
keepalive endpoint. Future logins may require another user-supplied MFA code.
Account-specific reliability and session lifetime have not been tested here.

## Why it needs adaptation

The pinned service listens on all interfaces over HTTP without request
authentication and logs MFA codes. Its add-on requests host networking and write
access to the HA configuration and shared folders. The upstream integration also
contains hardcoded helper-address fallbacks to which it may send credentials.
These are concrete implementation details to address before deployment.

The upstream automated config flow identifies accounts by lowercased username.
This fork preserves meter identities and external statistics IDs. Reusing the
authentication service must preserve the existing entry, meter mapping, and
statistics history rather than copying that config flow verbatim.

The companion's existence corrects the earlier blanket conclusion that automatic
login was impossible. It supplies another implementation to evaluate; it does not
prove unattended renewal or reliable CAPTCHA handling for this account. No
companion has been installed as part of this investigation.
