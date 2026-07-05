import datetime as dt
import json
import logging
import os
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import requests


EXIST_AUTHORIZE_URL = "https://exist.io/oauth2/authorize"
EXIST_ACCESS_TOKEN_URL = "https://exist.io/oauth2/access_token"
EXIST_API = "https://exist.io/api/2"
EXIST_DEFAULT_REDIRECT_URI = "http://localhost:8000/"
EXIST_DEFAULT_SCOPE = "media_write"
EXIST_REFRESH_WINDOW = dt.timedelta(days=7)
EXIST_MAX_UPDATE_OBJECTS = 36


def env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name, default)
    if value is None:
        return None
    value = value.strip()
    return value or default


def required_env(name: str) -> str:
    value = env(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_response_payload(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text


def write_json_file(path: Path, payload: dict[str, Any]) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp_path.replace(path)


def chunked(items: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    return [items[index:index + size] for index in range(0, len(items), size)]


class ExistClient:
    def __init__(
        self,
        token_file: Path,
        client_id: str,
        client_secret: str,
        redirect_uri: str = EXIST_DEFAULT_REDIRECT_URI,
        scope: str = EXIST_DEFAULT_SCOPE,
    ) -> None:
        self.token_file = token_file
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope

    def load_tokens(self) -> dict[str, Any]:
        if not self.token_file.exists():
            raise RuntimeError(
                f"Missing Exist OAuth file at {self.token_file}. Run `python main.py exist-auth` first."
            )

        try:
            payload = json.loads(self.token_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Exist OAuth file at {self.token_file} is not valid JSON. "
                "Run `python main.py exist-auth` again."
            ) from exc

        if not isinstance(payload, dict):
            raise RuntimeError(
                f"Exist OAuth file at {self.token_file} has an unexpected format. "
                "Run `python main.py exist-auth` again."
            )
        return payload

    def save_tokens(self, token_payload: dict[str, Any]) -> None:
        expires_in = token_payload.get("expires_in")
        if not isinstance(expires_in, (int, float)):
            raise RuntimeError(f"Exist token response missing expires_in: {token_payload}")

        existing_attributes: dict[str, str] = {}
        if self.token_file.exists():
            try:
                existing_payload = self.load_tokens()
                existing_attributes = existing_payload.get("attributes", {})
                if not isinstance(existing_attributes, dict):
                    existing_attributes = {}
            except RuntimeError:
                existing_attributes = {}

        issued_at = utc_now()
        stored = {
            "access_token": token_payload.get("access_token"),
            "refresh_token": token_payload.get("refresh_token"),
            "token_type": token_payload.get("token_type", "Bearer"),
            "scope": token_payload.get("scope", self.scope),
            "expires_in": int(expires_in),
            "issued_at": issued_at.isoformat(),
            "expires_at": (issued_at + dt.timedelta(seconds=int(expires_in))).isoformat(),
            "attributes": existing_attributes,
        }

        if not stored["access_token"] or not stored["refresh_token"]:
            raise RuntimeError(f"Exist token response missing tokens: {token_payload}")

        write_json_file(self.token_file, stored)

    def token_refresh_due(self, tokens: dict[str, Any]) -> bool:
        expires_at = tokens.get("expires_at")
        if not isinstance(expires_at, str) or not expires_at:
            return False

        try:
            expires_at_dt = dt.datetime.fromisoformat(expires_at)
        except ValueError:
            return False

        if expires_at_dt.tzinfo is None:
            expires_at_dt = expires_at_dt.replace(tzinfo=dt.timezone.utc)
        return utc_now() >= (expires_at_dt - EXIST_REFRESH_WINDOW)

    def exchange_token(self, grant_payload: dict[str, str]) -> dict[str, Any]:
        response = requests.post(EXIST_ACCESS_TOKEN_URL, data=grant_payload, timeout=30)
        payload = parse_response_payload(response)
        if not response.ok:
            raise RuntimeError(
                f"Exist OAuth token exchange failed with {response.status_code}: {payload}"
            )
        if not isinstance(payload, dict):
            raise RuntimeError(f"Unexpected Exist OAuth token response: {payload}")
        return payload

    def refresh_access_token(self) -> dict[str, Any]:
        tokens = self.load_tokens()
        refresh_token = tokens.get("refresh_token")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise RuntimeError(
                f"Exist OAuth file at {self.token_file} is missing a refresh token. "
                "Run `python main.py exist-auth` again."
            )

        logging.info("Refreshing Exist access token.")
        payload = self.exchange_token(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
        )
        self.save_tokens(payload)
        return self.load_tokens()

    def current_access_token(self, force_refresh: bool = False) -> str:
        tokens = self.load_tokens()
        if force_refresh or self.token_refresh_due(tokens):
            tokens = self.refresh_access_token()

        access_token = tokens.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise RuntimeError(
                f"Exist OAuth file at {self.token_file} is missing an access token. "
                "Run `python main.py exist-auth` again."
            )
        return access_token

    def headers(self, force_refresh: bool = False) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.current_access_token(force_refresh=force_refresh)}",
            "Content-Type": "application/json",
        }

    def request_json(self, method: str, url: str, **kwargs: Any) -> Any:
        base_headers = dict(kwargs.pop("headers", {}))
        request_kwargs = dict(kwargs)

        headers = dict(base_headers)
        headers.update(self.headers())
        response = requests.request(method, url, timeout=30, headers=headers, **request_kwargs)
        payload = parse_response_payload(response)

        if response.status_code == 401:
            headers = dict(base_headers)
            headers.update(self.headers(force_refresh=True))
            response = requests.request(method, url, timeout=30, headers=headers, **request_kwargs)
            payload = parse_response_payload(response)

        if not response.ok:
            raise RuntimeError(f"{method} {url} failed with {response.status_code}: {payload}")
        return payload

    def wait_for_authorization_code(self) -> str:
        parsed = urlparse(self.redirect_uri)
        hostname = parsed.hostname
        port = parsed.port
        path = parsed.path or "/"

        if parsed.scheme != "http" or hostname not in {"localhost", "127.0.0.1"} or port is None:
            raise RuntimeError(
                "EXIST_REDIRECT_URI must be a local HTTP URL with an explicit port, "
                "for example `http://localhost:8000/`."
            )

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                request_url = urlparse(self.path)
                if request_url.path != path:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not found.")
                    return

                query = parse_qs(request_url.query)
                self.server.auth_code = query.get("code", [None])[0]  # type: ignore[attr-defined]
                self.server.auth_error = query.get("error", [None])[0]  # type: ignore[attr-defined]
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                message = (
                    "<html><body><h1>Exist authorization received.</h1>"
                    "<p>You can close this tab and return to the terminal.</p></body></html>"
                )
                self.wfile.write(message.encode("utf-8"))

            def log_message(self, format: str, *args: Any) -> None:
                return

        httpd = HTTPServer((hostname, port), Handler)
        httpd.auth_code = None  # type: ignore[attr-defined]
        httpd.auth_error = None  # type: ignore[attr-defined]
        try:
            httpd.handle_request()
        finally:
            httpd.server_close()

        auth_error = getattr(httpd, "auth_error", None)
        if auth_error:
            raise RuntimeError(f"Exist authorization failed: {auth_error}")

        auth_code = getattr(httpd, "auth_code", None)
        if not auth_code:
            raise RuntimeError("Exist authorization did not return a code.")
        return auth_code

    def build_authorize_url(self) -> str:
        query = urlencode(
            {
                "client_id": self.client_id,
                "response_type": "code",
                "redirect_uri": self.redirect_uri,
                "scope": self.scope,
            }
        )
        return f"{EXIST_AUTHORIZE_URL}?{query}"

    def login(self) -> None:
        authorize_url = self.build_authorize_url()
        logging.info("Starting local callback server for Exist OAuth at %s", self.redirect_uri)
        logging.info("Opening browser for Exist authorization.")
        logging.info("If your browser does not open, use this URL: %s", authorize_url)
        webbrowser.open(authorize_url)
        code = self.wait_for_authorization_code()
        token_payload = self.exchange_token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "redirect_uri": self.redirect_uri,
            }
        )
        self.save_tokens(token_payload)
        logging.info("Saved Exist OAuth tokens to %s", self.token_file)

    def load_attribute_names(self) -> dict[str, str]:
        attributes = self.load_tokens().get("attributes", {})
        if not isinstance(attributes, dict):
            return {}
        return {str(key): str(value) for key, value in attributes.items() if key and value}

    def save_attribute_names(self, attribute_names: dict[str, str]) -> None:
        tokens = self.load_tokens()
        tokens["attributes"] = attribute_names
        write_json_file(self.token_file, tokens)

    def fetch_owned_attribute_names(self, definitions: list[dict[str, Any]]) -> dict[str, str]:
        results: list[dict[str, Any]] = []
        next_url: str | None = f"{EXIST_API}/attributes/owned/"
        params: dict[str, Any] | None = {
            "limit": 100,
            "include_inactive": "true",
        }

        while next_url:
            response = self.request_json("GET", next_url, params=params)
            params = None
            page_results = response.get("results", [])
            if not isinstance(page_results, list):
                raise RuntimeError(f"Unexpected Exist attributes response: {response}")
            results.extend(item for item in page_results if isinstance(item, dict))
            next_value = response.get("next")
            next_url = next_value if isinstance(next_value, str) and next_value else None

        by_label = {
            definition["label"]: definition["key"]
            for definition in definitions
            if "label" in definition
        }
        by_name = {definition["key"]: definition["key"] for definition in definitions}
        by_template = {
            definition["template"]: definition["key"]
            for definition in definitions
            if "template" in definition
        }
        mapping: dict[str, str] = {}
        for item in results:
            key = (
                by_template.get(item.get("template"))
                or by_label.get(item.get("label"))
                or by_name.get(item.get("name"))
            )
            name = item.get("name")
            if key and isinstance(name, str) and name:
                mapping[key] = name
        return mapping

    def acquire_attributes(self, definitions: list[dict[str, Any]]) -> dict[str, str]:
        payload = [
            {
                "template": definition["template"],
                "manual": definition["manual"],
            }
            for definition in definitions
            if "template" in definition
        ]
        if not payload:
            return {}

        response = self.request_json(
            "POST",
            f"{EXIST_API}/attributes/acquire/",
            data=json.dumps(payload),
        )

        failed = response.get("failed", [])
        if failed:
            failed_descriptions = ", ".join(
                f"{item.get('template', '<unknown>')}: {item.get('error', 'unknown error')}"
                for item in failed
            )
            raise RuntimeError(f"Could not acquire Exist attribute templates. {failed_descriptions}")

        return self.fetch_owned_attribute_names(definitions)

    def ensure_attributes(self, definitions: list[dict[str, Any]]) -> dict[str, str]:
        existing = self.load_attribute_names()
        existing.update(self.fetch_owned_attribute_names(definitions))
        templated = [
            definition
            for definition in definitions
            if "template" in definition
        ]
        if templated:
            existing.update(self.acquire_attributes(templated))

        missing = [
            definition
            for definition in definitions
            if definition["key"] not in existing and "template" not in definition
        ]
        if not missing:
            self.save_attribute_names(existing)
            return existing

        payload = [
            {
                "label": definition["label"],
                "group": definition["group"],
                "value_type": definition["value_type"],
                "manual": definition["manual"],
            }
            for definition in missing
        ]

        response = self.request_json(
            "POST",
            f"{EXIST_API}/attributes/create/",
            params={"success_objects": "1"},
            data=json.dumps(payload),
        )

        by_label = {
            definition["label"]: definition["key"]
            for definition in missing
            if "label" in definition
        }
        updated = dict(existing)

        for item in response.get("success", []):
            key = by_label.get(item.get("label"))
            if key:
                updated[key] = item["name"]

        failed = response.get("failed", [])
        refreshed = dict(updated)
        refreshed.update(self.fetch_owned_attribute_names(definitions))
        unresolved = [definition["key"] for definition in missing if definition["key"] not in refreshed]
        if not unresolved:
            self.save_attribute_names(refreshed)
            return refreshed

        failed_descriptions = ", ".join(
            f"{item.get('label', '<unknown>')}: {item.get('error', 'unknown error')}"
            for item in failed
        )
        details = f"Missing attribute names for: {', '.join(unresolved)}"
        if failed_descriptions:
            details = f"{details}. Create errors: {failed_descriptions}"
        raise RuntimeError(f"Could not ensure Exist attributes. {details}")

    def attribute_names_for(self, definitions: list[dict[str, Any]]) -> dict[str, str]:
        stored = self.load_attribute_names()
        missing = [definition["key"] for definition in definitions if definition["key"] not in stored]
        if missing:
            raise RuntimeError(
                "Missing stored Exist attribute names for: "
                f"{', '.join(missing)}. Run `python main.py exist-auth` again."
            )
        self.save_attribute_names(stored)
        return stored

    def build_update_payload(
        self,
        definitions: list[dict[str, Any]],
        attribute_names: dict[str, str],
        day: str,
        values_by_key: dict[str, Any],
    ) -> list[dict[str, Any]]:
        definitions_by_key = {definition["key"]: definition for definition in definitions}
        payload: list[dict[str, Any]] = []
        for key, value in values_by_key.items():
            definition = definitions_by_key.get(key)
            if not definition:
                raise RuntimeError(f"Missing Exist attribute definition for key: {key}")
            attribute_name = attribute_names.get(key)
            if not attribute_name:
                raise RuntimeError(f"Missing Exist attribute mapping for key: {key}")
            payload.append(
                {
                    "name": attribute_name,
                    "date": day,
                    "value": value,
                }
            )
        return payload

    def post_updates(self, payload: list[dict[str, Any]]) -> dict[str, Any]:
        successes: list[Any] = []
        failed_entries: list[Any] = []
        for batch in chunked(payload, EXIST_MAX_UPDATE_OBJECTS):
            result = self.request_json(
                "POST",
                f"{EXIST_API}/attributes/update/",
                data=json.dumps(batch),
            )
            successes.extend(result.get("success", []))
            failed_entries.extend(result.get("failed", []))
        return {"success": successes, "failed": failed_entries}
