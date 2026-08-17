import os
import tempfile
import unittest
from unittest import mock

import app


class CryptoTests(unittest.TestCase):
    def test_password_hash_round_trip(self):
        stored = app.pw_hash("correct horse battery staple")
        self.assertTrue(app.pw_ok("correct horse battery staple", stored))
        self.assertFalse(app.pw_ok("wrong password", stored))

    def test_secret_encryption_round_trip_and_random_nonce(self):
        with tempfile.NamedTemporaryFile() as key_file:
            key_file.write(os.urandom(32))
            key_file.flush()
            with mock.patch.object(app, "KEY_PATH", key_file.name):
                first = app.enc("vault secret")
                second = app.enc("vault secret")
                self.assertEqual(app.dec(first), "vault secret")
                self.assertNotEqual(first, second)

    def test_totp_known_vector(self):
        # RFC 6238 SHA-1 test secret; 59 seconds corresponds to counter 1.
        with mock.patch.object(app.time, "time", return_value=59):
            code, remaining = app.totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        self.assertEqual(code, "287082")
        self.assertEqual(remaining, 1)


class ConfigurationTests(unittest.TestCase):
    def test_incomplete_tls_configuration_is_rejected(self):
        with mock.patch.object(app, "TLS_CERT", "certificate.pem"), mock.patch.object(app, "TLS_KEY", ""):
            with self.assertRaises(ValueError):
                app.create_server()


if __name__ == "__main__":
    unittest.main()
