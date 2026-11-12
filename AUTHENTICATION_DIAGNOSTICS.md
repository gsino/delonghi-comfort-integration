# De'Longhi Comfort v0.1.1 Authentication Diagnostics

Base: upstream tag `v0.1.1`, commit `1c6643d689c6721b4443ce36b9fa2e89d76cda6e`.
Working branch: `diagnostics/auth-v0.1.1`.

## Changes

This patch adds safe diagnostic logging to the eight authentication steps, token
refresh, and the configuration flow's exception handler. API endpoints, request
parameters, redirect settings, the signature extraction expression, token storage
and refresh behavior, return values, and entities remain unchanged.
This is a diagnostic patch. Authentication with a real account and testing in a
running Home Assistant instance have not been performed.

Three runtime files are affected:

- `custom_components/delonghi_comfort/api.py`: observes the existing authentication operations.
- `custom_components/delonghi_comfort/auth_diagnostics.py`: a new module that emits safe metadata and stack information.
- `custom_components/delonghi_comfort/config_flow.py`: replaces direct exception-string logging with safe diagnostics.

## Static Analysis

| Step | Existing request or operation | Expected elements observed |
|---|---|---|
| 01 authorize | GET Gigya OIDC `/authorize`, without following redirects | Presence of the `Location` header and a nonempty `context` query value |
| 02 socialize.getIDs | GET Gigya `socialize.getIDs` and parse the response body as JSON | A JSON object containing `ucid`, `gmid`, and `gmidTicket` |
| 03 accounts.login | POST Gigya `accounts.login` with credentials and the existing riskContext | `statusCode == 200` and `sessionInfo.login_token` |
| 04 socialize.getUserInfo | POST Gigya `socialize.getUserInfo` | `UID`, `UIDSignature`, and `signatureTimestamp` |
| 05 OIDCConsentPage.php | GET De'Longhi `OIDCConsentPage.php` with context and signature information, then extract the consent signature from HTML | HTTP status, Content-Type, HTML-like tags, variable name, legacy opening delimiter, closing delimiter, and whether a nonempty signature can be extracted in the expected format |
| 06 authorize/continue | GET Gigya `/authorize/continue` with consent JSON and signature, without following redirects | Presence of `Location` and a nonempty `code` query value |
| 07 Gigya token | POST Gigya `/token` to exchange the authorization code for an IDP access token | A JSON object containing `access_token` |
| 08 Ayla token_sign_in | POST Ayla Networks `/api/v1/token_sign_in` to exchange the IDP token for Ayla tokens | `refresh_token` and `access_token` |
| R1 Ayla refresh_token | POST Ayla `/users/refresh_token.json` | JSON and token fields on HTTP 200; the existing fallback to fresh authentication when no refresh token is held, the status is not 200, or an exception occurs |
| C1 config_flow | The existing exception handler in the integration setup flow | Safe exception locations; this scope also includes configuration operations outside the API client |

### Candidate IndexError Location

With ordinary built-in types and JSON data, the direct indexing risk in the
authentication flow is `[1]` in this expression:

```python
signature = consent_text.split("const consentObj2Sig = '")[1].split("';")[0]
```

A mocked HTML response without the opening delimiter reproduces `IndexError` in
step 05, during `extract_signature`. Even if the variable name remains, changes
to whitespace, quotation marks, or the declaration can prevent a match.
This is a strong candidate, but it does not establish the cause of the actual
failure reported around November 11, 2026.

The final `[0]` in the same expression does not have the same risk because a
normal string split returns at least one element. The `[0]` in
`get_query_param()` accesses either a nonempty list from `parse_qs()` or the
default `[None]`, so an ordinary URL does not produce this exception there.
A missing query value is passed to subsequent operations as `None`.

The legacy expression does not reject a missing closing `';` or an empty
signature. This patch preserves that behavior and records
`signature_extractable=False`. A `success` message means that the existing
processing reached the end of that step. It does not guarantee a successful HTTP
response, a valid signature, or server-side success.

### HTTP and Exception Handling

The eight fresh-authentication steps do not call `raise_for_status()`. Apart
from the JSON `statusCode` check in step 03, they do not explicitly validate
server success. HTML or JSON returned with HTTP 4xx/5xx may therefore reach the
normal parsing code. Missing headers can raise `KeyError`; unexpected JSON
structures can raise `KeyError` or `TypeError`; non-JSON bodies can raise
`JSONDecodeError`; request and body-read failures can raise aiohttp exceptions or
timeouts. Previously, the broad exception handler in `_get_new_access_token()`
logged only the exception string and returned `None`. The diagnostic version
preserves that return behavior and records the failing step, phase, and safe
exception locations.

`authenticate()` starts fresh authentication on each call. Ayla tokens are held
in memory on the API instance. A 401 response from a normal device API request
enters the existing refresh path. This patch does not add token storage to the
configuration entry. Static analysis cannot verify the hypothesis that the
official app avoids a fresh-authentication failure by using an existing token.
The app working after a device restart also does not establish that a fresh
Gigya login succeeds.

## Log Safety

Routine observations and detailed stack information use DEBUG. Existing
processing failures use ERROR. The recoverable refresh fallback on a non-200
HTTP response uses DEBUG.

Output is limited to fixed source-code labels, numeric HTTP statuses, redirect
counts and hop statuses, required-field presence and nonemptiness, and boolean
comparisons against expected status values. Content-Type parameters are removed.
Only `application/json`, `text/html`, `application/xhtml+xml`, and `text/plain`
are emitted verbatim; other media types become `other`, and an absent type
becomes `missing`.

Usernames, email addresses, passwords, tokens, authorization codes, session
identifiers, cookies, signature values, URLs, query values, and response bodies
are omitted. Unknown JSON keys are not enumerated. The logger does not format
`errorDetails`, exception strings, `exc_info`, source lines, or local variables.
Exception chains follow the same policy: known exception class names and frame
line numbers are retained. File and function names are retained for the three
affected modules; directory paths and other frame names are omitted. Unknown
exception class names become `Exception`. The HTML-body check is a tag-based
heuristic, not a validation of the page's content or purpose.

These guarantees apply to the authentication diagnostics added here. This patch
does not sanitize all Home Assistant logs, third-party library logs, or existing
device-operation logs.

## Validation

Thirteen offline unittest tests were run with Python 3.12 and aiohttp 3.14.5.
They cover the normal eight-step flow, changed HTML, missing closing delimiters
and empty signatures, invalid JSON, missing fields, HTTP errors, redirect
history and redirect-limit errors, request and body-read exceptions, exception
chains, refresh and fallback behavior, and suppression of synthetic secrets
embedded in bodies, headers, and exceptions.

One test loads the original v0.1.1 implementation from its git object and
compares 47 cases. Return values, token state, request URLs, parameters, headers,
and request order must match. Both implementations receive the same fixed clock.
That comparison test is skipped if the required git object is unavailable.

```sh
python -m venv .venv
# Activate the virtual environment before running the following commands.
python -m pip install aiohttp
python -m unittest discover -s tests -v
python -m compileall -q custom_components tests
git diff --check
```

All integration modules were compiled, and the API and diagnostic modules were
imported using the actual aiohttp package. Home Assistant itself was not installed
in the test environment; loading the integration, UI behavior, startup, and
authentication in a running instance remain untested. The manifest, entities,
and dependency requirements were not changed.

## Applying the Patch to Home Assistant

No Home Assistant files have been changed, and no instance has been restarted or
authenticated as part of this work. The following steps are for a later stage,
after the user chooses to run diagnostics in their environment.

1. **Prepare a backup:** Copy the current
   `config/custom_components/delonghi_comfort/` directory and
   `configuration.yaml` to a separate backup location. Estimated hands-on time:
   2-5 minutes.
2. **Apply the code:** Obtain the three affected files listed above from the
   working branch and place them in
   `config/custom_components/delonghi_comfort/`. Include the new
   `auth_diagnostics.py`. Estimated hands-on time: 2-5 minutes. If using the
   patch ZIP, copy its three files under `custom_components/delonghi_comfort/`.
   Keep the installed `manifest.json` and all other existing integration files.
3. **Prepare logging:** Merge the DEBUG configuration below into
   `configuration.yaml`. Estimated hands-on time: 1-2 minutes.
4. **Load the changes:** Check the configuration and restart Home Assistant Core
   to load the modified Python files. Estimated hands-on time: 1 minute.
   Estimated restart wait: 1-5 minutes, potentially longer depending on the
   environment and other integrations. An existing entry may attempt
   authentication during startup.

Full branch archive:
[diagnostics/auth-v0.1.1](https://github.com/gsino/delonghi-comfort-integration/archive/refs/heads/diagnostics/auth-v0.1.1.zip).
This archive contains the entire repository; use the three files listed above.

The source at tag v0.1.1 contains `version: 1.0.0` in `manifest.json`. The
existing release workflow rewrites the version when creating release archives.
This patch does not change the version, so retain the installed manifest.
Deleting and recreating the integration entry is not required to apply the patch.

To roll back, restore the original state of the three affected files from the
backup, remove the newly added module if it was not present before, and restart
Core. A HACS re-download or update can overwrite the patch; account for this
when updating during diagnostics.

## Collecting Diagnostic Logs

If `configuration.yaml` already has a `logger:` section, merge this entry into
its `logs:` mapping rather than creating duplicate keys. This enables DEBUG
only for the authentication diagnostics added by this patch:

```yaml
logger:
  logs:
    custom_components.delonghi_comfort.auth_diagnostics: debug
```

To change only the running log level without restarting, use the following
action in Developer Tools when the Logger integration is enabled:

```yaml
action: logger.set_level
data:
  custom_components.delonghi_comfort.auth_diagnostics: debug
```

Reference: [Home Assistant Logger documentation](https://www.home-assistant.io/integrations/logger/).

1. **Reproduce once:** Capture the startup failure or reload an existing entry
   once. If no entry exists, attempt to add it once. Estimated hands-on time:
   1-2 minutes. Allow roughly a few seconds to one minute for authentication,
   but this is an estimate rather than a bound: the original implementation
   does not set per-step timeouts, and network conditions and shared-session
   settings can extend the wait.
2. **Collect the output:** Open Settings > System > Logs and view or download
   the raw Home Assistant Core log. Look for
   `custom_components.delonghi_comfort.auth_diagnostics` or `Auth step=`.
   Retain the `File ...` lines after `sanitized traceback`.
   Estimated hands-on time: 1-3 minutes. Follow the official
   [log viewing and downloading instructions](https://www.home-assistant.io/common-tasks/general/logs/).
   The condensed error list alone does not include the required DEBUG detail.
3. **Restore the log level:** Restore the previous configuration. For a running
   log-level change, use the same `logger.set_level` action with `warning`;
   also restore any persistent YAML change. Estimated hands-on time: 1 minute.

On Home Assistant OS, use the UI or `ha core logs`. For Container installations,
`docker logs <container_name>` is another option. The availability of
`/config/home-assistant.log` depends on the installation type and configuration.
When sharing results, extract a single authentication attempt and its stack
lines. The full Home Assistant log can contain values from other integrations.

Illustrative output, not a capture from a real environment:

```text
Auth step=05 OIDCConsentPage.php start
Auth step=05 OIDCConsentPage.php HTTP status=200 http_error=False redirect_response=False redirect_followed=False redirect_count=0 location_present=False content_type=text/html
Auth step=05 OIDCConsentPage.php body_looks_html=True consentObj2Sig_present=False legacy_marker_present=False signature_terminator_present=False signature_extractable=False
Auth step=05 OIDCConsentPage.php phase=extract_signature failed reason=access_token_exception
Auth step=05 OIDCConsentPage.php sanitized traceback exception=IndexError
  File api.py, line <actual_line_number>, in _get_new_access_token
```

## Next Investigation by Result

| Observation | Interpretation and next investigation; fixes are separate work |
|---|---|
| 05, HTTP 200, HTML-like body, no variable name | A changed consent page, a different page, or an application error page is possible. HTTP 200 alone cannot distinguish them. After authorization, inspect the current page structure using a safe method. |
| 05, variable name present, legacy opening delimiter absent | Changes to quotation marks, whitespace, or the declaration are likely. Confirm the current syntax before changing the extractor and its tests. |
| 05, missing closing delimiter or empty signature, followed by failure in 06 | The legacy extractor may have accepted an incomplete value. Investigate delimiters and the signature handoff. |
| 05, HTTP 401/403, a different Content-Type, or redirects | Investigate the session, context, access restrictions, and redirect changes alongside step 04 and earlier steps. An HTML-structure change is not the only explanation. |
| HTTP 429 or 5xx at any step | Investigate rate limiting, a service outage, or the network path before changing HTML extraction. |
| 01/06, missing Location or query-presence check is False | Investigate changed OIDC redirect responses or error responses. |
| 02-04, invalid JSON, missing required fields, or failed status comparison | Investigate Gigya response formats, login request requirements, and session acquisition. |
| Failure in 07 | Investigate the authorization-code exchange for a Gigya IDP token. |
| Failure in 08 | Investigate the Ayla token exchange and response format after Gigya authentication. |
| Failure in R1 followed by failure in 01 or later | Distinguish a refresh failure from a fresh-login failure. |
| No HTTP response, with a request/read_body transport exception | Investigate DNS, TLS, connection failures, timeouts, and body reception. An HTTP status is unavailable if no response was received. |
| No new diagnostic messages | Check the installation directory, versions of all three files, restart, and logger name and level first. |

Because the logs omit response bodies, different error pages with the same HTTP
status cannot always be distinguished. Use the real diagnostic output to narrow
the failing step before selecting further observations and a separate fix.
