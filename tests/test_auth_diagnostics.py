"""Offline tests: no real credentials, Home Assistant installation or network.

The original v0.1.1 implementation is loaded from git for differential tests.
Only the API module is loaded, bypassing Home Assistant's package __init__.
"""

from copy import deepcopy
from datetime import datetime
import importlib
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

import aiohttp

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "_delonghi_auth_under_test"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(ROOT / "custom_components" / "delonghi_comfort")]
sys.modules[PACKAGE] = package
api_module = importlib.import_module(f"{PACKAGE}.api")
diagnostics_module = importlib.import_module(f"{PACKAGE}.auth_diagnostics")

SECRETS = {name: f"SENSITIVE_{name}_9a8b7c" for name in (
    "username", "password", "context", "ucid", "gmid", "gmidTicket", "login_token",
    "UID", "UIDSignature", "signatureTimestamp", "signature", "code", "idp_token",
    "access_token", "refresh_token", "cookie", "error_details", "url_query",
)}


class FixedDatetime:
    @staticmethod
    def now():
        return datetime(2026, 11, 12, 12, 0, 0)


class Response:
    def __init__(self, body="", status=200, headers=None, history=(), read_error=None):
        self.body = json.dumps(body) if isinstance(body, (dict, list)) else body
        self.status = status
        self.headers = headers if headers is not None else {"Content-Type": "application/json"}
        self.history = history
        self.read_error = read_error

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def text(self):
        if self.read_error:
            raise self.read_error
        return self.body

    async def json(self):
        return json.loads(await self.text())


class Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, deepcopy(kwargs)))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)


def responses():
    s = SECRETS
    return [
        Response(status=302, headers={"Location": f"https://example.invalid/?context={s['context']}"}),
        Response({key: s[key] for key in ("ucid", "gmid", "gmidTicket")}),
        Response({"statusCode": 200, "sessionInfo": {"login_token": s["login_token"]}}),
        Response({key: s[key] for key in ("UID", "UIDSignature", "signatureTimestamp")}),
        Response(f"<html><script>const consentObj2Sig = '{s['signature']}';</script></html>",
                 headers={"Content-Type": "text/html; charset=utf-8", "Set-Cookie": s["cookie"]}),
        Response(status=302, headers={"Location": f"https://example.invalid/?code={s['code']}"}),
        Response({"access_token": s["idp_token"]}),
        Response({"access_token": s["access_token"], "refresh_token": s["refresh_token"]}),
    ]


class AuthenticationTests(unittest.IsolatedAsyncioTestCase):
    async def run_flow(self, replies=None, module=api_module, refresh=False, refresh_token=None):
        session = Session(replies if replies is not None else responses())
        api = module.DeLonghiAPI(SECRETS["username"], SECRETS["password"], session)
        api.refresh_token = refresh_token
        with patch.object(module, "datetime", FixedDatetime):
            result = await (api.refresh_access_token() if refresh else api.authenticate())
        return result, api.access_token, api.refresh_token, session.calls

    def assert_safe(self, output):
        for secret in SECRETS.values():
            self.assertNotIn(secret, output)
        self.assertNotIn("https://", output)
        self.assertNotIn("Traceback (most recent call last)", output)

    async def capture(self, replies=None, **kwargs):
        with self.assertLogs(PACKAGE, level="DEBUG") as captured:
            result = await self.run_flow(replies, **kwargs)
        output = "\n".join(captured.output)
        self.assert_safe(output)
        return result, output

    async def test_success_and_all_steps(self):
        result, output = await self.capture()
        self.assertEqual(result[:3], (True, SECRETS["access_token"], SECRETS["refresh_token"]))
        self.assertEqual(len(result[3]), 8)
        for number in range(1, 9):
            self.assertIn(f"Auth step={number:02}", output)
        self.assertIn("signature_extractable=True", output)
        self.assertFalse(any("ERROR:" in line for line in output.splitlines()))

    async def test_changed_html_identifies_original_index_error(self):
        replies = responses()
        replies[4] = Response("<html><body>changed</body></html>", headers={"Content-Type": "text/html"})
        result, output = await self.capture(replies)
        self.assertFalse(result[0])
        self.assertEqual(len(result[3]), 5)
        self.assertIn("consentObj2Sig_present=False", output)
        self.assertIn("step=05 OIDCConsentPage.php phase=extract_signature failed", output)
        self.assertIn("exception=IndexError", output)
        self.assertRegex(output, r"File api.py, line \d+, in _get_new_access_token")

    async def test_marker_variation_and_unterminated_legacy_behavior(self):
        for body, marker, terminated, success in (
            ('<html><script>const consentObj2Sig = "changed";</script></html>', False, False, False),
            ("<html>const consentObj2Sig = 'unterminated", True, False, True),
            ("<html>const consentObj2Sig = '';", True, True, True),
        ):
            with self.subTest(body=body):
                replies = responses()
                replies[4] = Response(body, headers={"Content-Type": "text/html"})
                result, output = await self.capture(replies)
                self.assertEqual(result[0], success)
                self.assertIn(f"legacy_marker_present={marker}", output)
                self.assertIn(f"signature_terminator_present={terminated}", output)
                self.assertIn("signature_extractable=False", output)

    async def test_http_error_html_and_redirect_history(self):
        replies = responses()
        replies[4] = Response("<html>unavailable</html>", status=503,
                              headers={"Content-Type": "text/html", "Location": SECRETS["url_query"]},
                              history=(Response(status=302),))
        _, output = await self.capture(replies)
        self.assertIn("HTTP status=503 http_error=True", output)
        self.assertIn("redirect_followed=True redirect_count=1", output)
        self.assertIn("redirect_hop=1 HTTP status=302", output)
        self.assertIn("body_looks_html=True", output)

    async def test_invalid_json_and_non_object_json(self):
        for body, kind in ((SECRETS["error_details"], "JSONDecodeError"), ([], "TypeError")):
            replies = responses()
            replies[1] = Response(body, status=502, headers={"Content-Type": "text/plain"})
            result, output = await self.capture(replies)
            self.assertFalse(result[0])
            self.assertIn("HTTP status=502", output)
            self.assertIn(f"exception={kind}", output)

    async def test_missing_fields_for_every_json_step(self):
        for index, step in ((1, "02"), (2, "03"), (3, "04"), (6, "07"), (7, "08")):
            replies = responses()
            replies[index] = Response({"errorDetails": SECRETS["error_details"]})
            result, output = await self.capture(replies)
            self.assertFalse(result[0])
            self.assertIn(f"Auth step={step}", output)
            self.assertIn("present=False", output)
            self.assertIn("failed reason=", output)

    async def test_missing_location_and_query(self):
        for index, step in ((0, "01"), (5, "06")):
            replies = responses()
            replies[index] = Response(headers={})
            _, output = await self.capture(replies)
            self.assertIn(f"step={step}", output)
            self.assertIn("exception=KeyError", output)
            replies = responses()
            replies[index] = Response(status=302, headers={"Location": "https://example.invalid/"})
            result, output = await self.capture(replies)
            self.assertTrue(result[0])  # Legacy behavior: missing query value is passed onward.
            self.assertIn("present_nonempty=False", output)

    async def test_server_text_and_hostile_content_type_are_never_logged(self):
        replies = responses()
        replies[2] = Response({"statusCode": SECRETS["error_details"],
                               "errorCode": SECRETS["UID"], "errorDetails": SECRETS["password"]},
                              headers={"Content-Type": SECRETS["username"] + ";" + SECRETS["cookie"]})
        _, output = await self.capture(replies)
        self.assertIn("content_type=other", output)
        self.assertIn("reason=login_status_not_200", output)

    async def test_exception_messages_chains_urls_and_locals_are_suppressed(self):
        def make_error():
            private_local = SECRETS["password"]
            try:
                raise ValueError(private_local)
            except ValueError as cause:
                try:
                    raise aiohttp.ClientResponseError(
                        types.SimpleNamespace(real_url="https://example.invalid/?code=" + SECRETS["code"]),
                        (), status=403, message=SECRETS["error_details"],
                        headers={"Set-Cookie": SECRETS["cookie"]},
                    ) from cause
                except aiohttp.ClientResponseError as error:
                    return error
        for index in (0, 4):
            replies = responses()
            replies[index] = make_error() if index == 0 else Response(read_error=make_error())
            _, output = await self.capture(replies)
            self.assertIn("exception=ClientResponseError", output)
            self.assertIn("exception=ValueError", output)
            self.assertIn("exception_http_status=403", output)
            self.assertIn("File <external>", output)

    async def test_refresh_success_and_fallbacks(self):
        result, output = await self.capture(
            [Response({"access_token": SECRETS["access_token"], "refresh_token": SECRETS["refresh_token"]})],
            refresh=True, refresh_token="old_refresh",
        )
        self.assertEqual(result[0], SECRETS["access_token"])
        self.assertIn("step=R1 Ayla refresh_token success", output)
        for first in (Response(status=401), TimeoutError(SECRETS["password"]), Response({})):
            result, output = await self.capture([first] + responses(), refresh=True, refresh_token="old_refresh")
            self.assertEqual(result[0], SECRETS["access_token"])
            self.assertEqual(len(result[3]), 9)
        result, output = await self.capture(refresh=True)
        self.assertIn("no_refresh_token_fallback", output)
        self.assertEqual(len(result[3]), 8)

    async def test_redirect_limit_exception_has_safe_history(self):
        replies = responses()
        replies[4] = aiohttp.TooManyRedirects(
            types.SimpleNamespace(real_url="https://example.invalid/?code=" + SECRETS["code"]),
            (Response(status=302, headers={"Location": SECRETS["url_query"]}),),
            status=0, message=SECRETS["error_details"],
        )
        _, output = await self.capture(replies)
        self.assertIn("exception=TooManyRedirects", output)
        self.assertIn("exception_redirect_count=1", output)
        self.assertIn("exception_redirect_hop=1 HTTP status=302", output)

    async def test_default_level_has_safe_error_summary(self):
        replies = responses()
        replies[4] = Response(SECRETS["error_details"])
        with self.assertLogs(PACKAGE, level="ERROR") as captured:
            await self.run_flow(replies)
        output = "\n".join(captured.output)
        self.assert_safe(output)
        self.assertIn("step=05 OIDCConsentPage.php phase=extract_signature failed", output)
        self.assertNotIn("traceback", output)

    async def test_differential_against_v011(self):
        original = subprocess.run(
            ["git", "show", "1c6643d689c6721b4443ce36b9fa2e89d76cda6e:custom_components/delonghi_comfort/api.py"],
            cwd=ROOT, text=True, encoding="utf-8", capture_output=True,
        )
        if original.returncode:
            self.skipTest("v0.1.1 git object required for differential check")
        baseline = types.ModuleType(f"{PACKAGE}.baseline")
        baseline.__package__ = PACKAGE
        exec(compile(original.stdout, "<v0.1.1 api>", "exec"), baseline.__dict__)
        cases = [responses()]
        for index in range(8):
            for replacement in (Response({}), Response([]), Response("invalid json"),
                                Response(status=503), TimeoutError("synthetic failure")):
                replies = responses()
                replies[index] = replacement
                cases.append(replies)
        replies = responses()
        replies[4] = Response("const consentObj2Sig = 'unterminated")
        cases.append(replies)
        # Old logs are intentionally not emitted: their messages are unsafe.
        with patch.object(baseline, "_LOGGER"), patch.object(diagnostics_module, "_LOGGER"):
            for index, replies in enumerate(cases):
                with self.subTest(case=index):
                    expected = await self.run_flow(deepcopy(replies), module=baseline)
                    actual = await self.run_flow(deepcopy(replies))
                    self.assertEqual(actual, expected)
            for first in (Response(status=401), Response({}), TimeoutError("synthetic"),
                          Response({"access_token": "new"}),
                          Response({"access_token": "new", "refresh_token": "rotated"})):
                replies = [first] + responses()
                expected = await self.run_flow(deepcopy(replies), module=baseline, refresh=True, refresh_token="old")
                actual = await self.run_flow(deepcopy(replies), refresh=True, refresh_token="old")
                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
