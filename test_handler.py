import hashlib
import hmac
import time
import unittest
from unittest import mock

from handler import _verify_tailscale_signature


def _build_signature(secret, body, timestamp):
    message = f"{timestamp}.{body}".encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), message, hashlib.sha256)
    return mac.hexdigest()


class TestTailscaleSignatureVerification(unittest.TestCase):
    def test_verifies_valid_signature_with_tailscale_header(self):
        secret = "shh"
        body = '{"event_type":"test"}'
        timestamp = 1_700_000_000
        signature = _build_signature(secret, body, timestamp)
        headers = {"tailscale-webhook-signature": f"t={timestamp},v1={signature}"}

        with mock.patch.object(time, "time", return_value=timestamp):
            self.assertTrue(_verify_tailscale_signature(secret, body, headers))

    def test_verifies_valid_signature_with_x_header(self):
        secret = "shh"
        body = '{"event_type":"test"}'
        timestamp = 1_700_000_000
        signature = _build_signature(secret, body, timestamp)
        headers = {"x-tailscale-signature": f"t={timestamp},v1={signature}"}

        with mock.patch.object(time, "time", return_value=timestamp):
            self.assertTrue(_verify_tailscale_signature(secret, body, headers))

    def test_rejects_expired_timestamp(self):
        secret = "shh"
        body = '{"event_type":"test"}'
        timestamp = 1_700_000_000
        signature = _build_signature(secret, body, timestamp)
        headers = {"tailscale-webhook-signature": f"t={timestamp},v1={signature}"}

        with mock.patch.object(time, "time", return_value=timestamp + 301):
            self.assertFalse(_verify_tailscale_signature(secret, body, headers))

    def test_rejects_invalid_signature(self):
        secret = "shh"
        body = '{"event_type":"test"}'
        timestamp = 1_700_000_000
        headers = {"tailscale-webhook-signature": f"t={timestamp},v1=bad"}

        with mock.patch.object(time, "time", return_value=timestamp):
            self.assertFalse(_verify_tailscale_signature(secret, body, headers))


if __name__ == "__main__":
    unittest.main()
