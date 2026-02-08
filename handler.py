import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse

import requests


def _get_headers(event):
    if isinstance(event, dict):
        headers = event.get("headers") or {}
        return {str(k).lower(): str(v) for k, v in headers.items()}
    return {}


def _get_body(event):
    if isinstance(event, (bytes, bytearray)):
        return event.decode("utf-8")
    if isinstance(event, str):
        return event
    if isinstance(event, dict):
        body = event.get("body")
        if body is None:
            return ""
        if event.get("isBase64Encoded"):
            return base64.b64decode(body).decode("utf-8")
        if isinstance(body, (bytes, bytearray)):
            return body.decode("utf-8")
        return str(body)
    return ""


def _verify_tailscale_signature(secret, body, headers):
    if not secret:
        return True
    signature = headers.get("x-tailscale-signature", "")
    if not signature.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256)
    return hmac.compare_digest(signature, f"sha256={expected.hexdigest()}")


def _build_dingtalk_url(webhook_url, signing_secret):
    if not signing_secret:
        return webhook_url
    timestamp = str(int(time.time() * 1000))
    string_to_sign = f"{timestamp}\n{signing_secret}"
    hmac_code = hmac.new(
        signing_secret.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    separator = "&" if "?" in webhook_url else "?"
    return f"{webhook_url}{separator}timestamp={timestamp}&sign={sign}"


def _build_message(payload_text):
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError:
        payload = {"raw": payload_text}

    event_type = payload.get("event_type") or payload.get("eventType") or "unknown"
    compact_payload = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return f"[tailscale] event_type={event_type} payload={compact_payload}"


def handler(event, context):
    body = _get_body(event)
    headers = _get_headers(event)

    tailscale_secret = os.environ.get("TAILSCALE_WEBHOOK_SECRET", "")
    if not _verify_tailscale_signature(tailscale_secret, body, headers):
        return {
            "statusCode": 401,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "invalid tailscale signature"}),
        }

    dingtalk_webhook = os.environ.get("DINGTALK_WEBHOOK_URL")
    if not dingtalk_webhook:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "missing DINGTALK_WEBHOOK_URL"}),
        }

    dingtalk_secret = os.environ.get("DINGTALK_SIGNING_SECRET", "")
    signed_url = _build_dingtalk_url(dingtalk_webhook, dingtalk_secret)
    message = _build_message(body)

    response = requests.post(
        signed_url,
        json={"msgtype": "text", "text": {"content": message}},
        timeout=10,
    )

    return {
        "statusCode": response.status_code,
        "headers": {"Content-Type": "application/json"},
        "body": response.text,
    }
