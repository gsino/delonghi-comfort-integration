"""Allowlisted authentication metadata; never format untrusted response values."""

import logging
from pathlib import PurePath

from aiohttp import ClientResponseError

_LOGGER = logging.getLogger(__name__)
_MEDIA_TYPES = {"application/json", "text/html", "application/xhtml+xml", "text/plain"}
_EXCEPTION_TYPES = {
    "IndexError", "KeyError", "TypeError", "ValueError", "JSONDecodeError",
    "UnicodeDecodeError", "TimeoutError", "ClientResponseError", "ContentTypeError",
    "ClientConnectorError", "ClientConnectorDNSError", "ClientSSLError",
    "ClientConnectorCertificateError", "ServerDisconnectedError", "ClientPayloadError",
    "TooManyRedirects", "RuntimeError", "AttributeError", "OSError",
}


class AuthDiagnostics:
    """One local observer per invocation; no credentials or state are retained."""

    def __init__(self) -> None:
        self.step = "00 authenticate"
        self.phase = "start"

    def start(self, step: str) -> None:
        """Labels passed to this observer must be source-code constants."""
        self.step = step
        self.phase = "request"
        _LOGGER.debug("Auth step=%s start", self.step)

    def phase_at(self, phase: str) -> None:
        self.phase = phase
        _LOGGER.debug("Auth step=%s phase=%s", self.step, self.phase)

    def success(self) -> None:
        _LOGGER.debug("Auth step=%s success (existing processing completed)", self.step)

    def response(self, response) -> None:
        """Omit URL, Location value, cookies, arbitrary headers and MIME parameters."""
        self.phase = "response"
        media = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        media = media if media in _MEDIA_TYPES else ("other" if media else "missing")
        _LOGGER.debug(
            "Auth step=%s HTTP status=%s http_error=%s redirect_response=%s "
            "redirect_followed=%s redirect_count=%s location_present=%s content_type=%s",
            self.step, response.status, response.status >= 400,
            300 <= response.status < 400, bool(response.history), len(response.history),
            "Location" in response.headers, media,
        )
        for index, previous in enumerate(response.history):
            _LOGGER.debug("Auth step=%s redirect_hop=%s HTTP status=%s",
                          self.step, index + 1, previous.status)

    def fields(self, data, paths: tuple[tuple[str, ...], ...]) -> None:
        """Only log presence of statically selected fields, never keys from data."""
        _LOGGER.debug("Auth step=%s body_json_object=%s", self.step, isinstance(data, dict))
        for path in paths:
            value = data
            present = True
            for key in path:
                if not isinstance(value, dict) or key not in value:
                    present = False
                    break
                value = value[key]
            _LOGGER.debug("Auth step=%s field=%s present=%s nonempty=%s",
                          self.step, ".".join(path), present, present and bool(value))
        if isinstance(data, dict):
            # Report comparisons, not server-controlled status/error values or text.
            _LOGGER.debug(
                "Auth step=%s statusCode_present=%s statusCode_is_200=%s "
                "errorCode_present=%s errorCode_is_zero=%s",
                self.step, "statusCode" in data, data.get("statusCode") == 200,
                "errorCode" in data, data.get("errorCode") == 0,
            )

    def query(self, name: str, value) -> None:
        _LOGGER.debug("Auth step=%s query_field=%s present_nonempty=%s",
                      self.step, name, bool(value))

    def consent(self, text: str) -> None:
        """Observe the exact legacy delimiter without replacing the parser."""
        lowered = text.lstrip().lower()
        html = any(tag in lowered for tag in ("<!doctype html", "<html", "<head", "<body"))
        marker = "const consentObj2Sig = '"
        _, found, after = text.partition(marker)
        signature, closed, _ = after.partition("';")
        _LOGGER.debug(
            "Auth step=%s body_looks_html=%s consentObj2Sig_present=%s "
            "legacy_marker_present=%s signature_terminator_present=%s "
            "signature_extractable=%s",
            self.step, html, "consentObj2Sig" in text, bool(found), bool(found and closed),
            bool(found and closed and signature),
        )

    def failure(self, reason: str, error: Exception | None = None) -> None:
        """Log a safe traceback: no exception messages, source text or locals.

        Raw exc_info/traceback.format_exception can contain URLs, JSON documents,
        KeyError values and chained HTTP errors. Traverse chains without formatting
        them. External frame names and all directory paths are deliberately omitted.
        """
        _LOGGER.error("Auth step=%s phase=%s failed reason=%s", self.step, self.phase, reason)
        seen = set()
        while error is not None and id(error) not in seen:
            seen.add(id(error))
            kind = type(error).__name__
            kind = kind if kind in _EXCEPTION_TYPES else "Exception"
            frames = []
            tb = error.__traceback__
            while tb is not None:
                code = tb.tb_frame.f_code
                filename = PurePath(code.co_filename).name
                internal = code.co_filename in {
                    __file__,
                    str(PurePath(__file__).with_name("api.py")),
                    str(PurePath(__file__).with_name("config_flow.py")),
                }
                frames.append("  File %s, line %s, in %s" % (
                    filename if internal else "<external>", tb.tb_lineno,
                    code.co_name if internal else "<external>",
                ))
                tb = tb.tb_next
            _LOGGER.debug("Auth step=%s sanitized traceback exception=%s\n%s",
                          self.step, kind, "\n".join(frames))
            # A library may raise before entering the response context.
            if isinstance(error, ClientResponseError) and type(error.status) is int:
                _LOGGER.debug("Auth step=%s exception_http_status=%s", self.step, error.status)
                _LOGGER.debug("Auth step=%s exception_redirect_count=%s",
                              self.step, len(error.history))
                for index, previous in enumerate(error.history):
                    _LOGGER.debug("Auth step=%s exception_redirect_hop=%s HTTP status=%s",
                                  self.step, index + 1, previous.status)
            error = error.__cause__ or (None if error.__suppress_context__ else error.__context__)
